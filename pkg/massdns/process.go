package massdns

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/shuffledns/pkg/checkpoint"
	"github.com/projectdiscovery/shuffledns/pkg/iterative"
	"github.com/projectdiscovery/shuffledns/pkg/parser"
	"github.com/projectdiscovery/shuffledns/pkg/resolve"
	"github.com/projectdiscovery/shuffledns/pkg/shard"
	"github.com/projectdiscovery/shuffledns/pkg/store"
	"github.com/projectdiscovery/shuffledns/pkg/wildcards"
	"github.com/projectdiscovery/utils/batcher"
	fileutil "github.com/projectdiscovery/utils/file"
	ioutil "github.com/projectdiscovery/utils/io"
	mapsutil "github.com/projectdiscovery/utils/maps"
	"github.com/remeh/sizedwaitgroup"
	"github.com/weppos/publicsuffix-go/publicsuffix"
)

// parseBatchMode maps a CLI string to the resolver batching mode.
func parseBatchMode(s string) resolve.BatchMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "on", "enabled", "true":
		return resolve.BatchEnabled
	case "adaptive", "auto":
		return resolve.BatchAdaptive
	default:
		return resolve.BatchDisabled
	}
}

// Run processes an existing raw massdns output file for wildcard filtering.
// This is the backward-compatible path for the -ri/--raw-input flag; live
// resolution no longer shells out to massdns and is handled by the streaming
// methods below.
func (instance *Instance) Run(ctx context.Context) error {
	if instance.options.MassdnsRaw == "" {
		return errors.New("streaming processing should be used for new resolution runs")
	}

	// Check for blank or non-existent input file
	blank, err := fileutil.IsEmpty(instance.options.MassdnsRaw)
	if err != nil {
		return err
	}
	if blank {
		return errors.New("blank input file specified")
	}

	shstore, err := store.New(instance.options.TempDir)
	if err != nil {
		return fmt.Errorf("could not create store: %w", err)
	}
	defer shstore.Close()

	gologger.Info().Msgf("Started parsing massdns input\n")
	now := time.Now()
	if err := instance.parseMassDNSOutputFile(instance.options.MassdnsRaw, shstore); err != nil {
		return fmt.Errorf("could not parse massdns input: %w", err)
	}
	gologger.Info().Msgf("Massdns input parsing completed in %s\n", time.Since(now))

	return instance.postProcess(shstore)
}

// resolveNames resolves a stream of hostnames produced by the produce function
// using the native asynchronous resolver, storing successful answers in the
// store. No temporary files are created and no external binary is invoked.
//
// When configured, the input is partitioned by shard (distributed coordination)
// and filtered against a resume checkpoint (crash-safe stop/resume) before being
// dispatched; both filters run in the producer goroutine, off the resolver's hot
// path.
func (instance *Instance) resolveNames(ctx context.Context, shstore *store.Store, produce func(out chan<- string) error) error {
	// Iterative mode recurses from the root servers and needs no resolver list;
	// the stub path requires one.
	var resolvers []string
	var err error
	if !instance.options.Iterative {
		resolvers, err = wildcards.LoadResolversFromFile(instance.options.ResolversFile)
		if err != nil {
			return fmt.Errorf("could not load resolvers: %w", err)
		}
	}

	shardCfg, err := shard.Parse(instance.options.Shard)
	if err != nil {
		return err
	}

	var ckpt *checkpoint.Checkpoint
	if instance.options.ResumeFile != "" {
		ckpt, err = checkpoint.Open(instance.options.ResumeFile)
		if err != nil {
			return fmt.Errorf("could not open resume checkpoint: %w", err)
		}
		defer func() { _ = ckpt.Close() }()
		if n := ckpt.Resumed(); n > 0 {
			gologger.Info().Msgf("Resuming: skipping %d already-completed names\n", n)
		}
	}

	var resolved atomic.Int64

	// The shuffledns runner keys its store by IP address, so only address
	// record types are meaningful here; other types (NS, MX, TXT, ...) would
	// resolve successfully but be silently dropped at store time. Reject them
	// with a clear pointer to cmd/resolve, which renders arbitrary types.
	qtype := dns.TypeA
	if instance.options.QueryType != "" {
		t, ok := dns.StringToType[strings.ToUpper(instance.options.QueryType)]
		if !ok {
			return fmt.Errorf("unknown query type %q", instance.options.QueryType)
		}
		if t != dns.TypeA && t != dns.TypeAAAA {
			return fmt.Errorf("query type %q is not supported by the bruteforce runner (only A/AAAA); use the resolve command for arbitrary record types", instance.options.QueryType)
		}
		qtype = t
	}

	markDone := func(name string) {
		if ckpt != nil {
			_ = ckpt.Done(name)
		}
	}

	// storeResult is the engine-agnostic result handler: it marks the name done
	// (for resume), then stores any address answers keyed by IP. Shared by both
	// the stub resolver and the iterative-from-root resolver.
	storeResult := func(name string, rcode int, a, aaaa []string) {
		markDone(name)
		if rcode != dns.RcodeSuccess {
			return
		}
		ips := a
		if len(aaaa) > 0 {
			ips = append(append([]string{}, a...), aaaa...)
		}
		if len(ips) == 0 {
			return
		}
		for _, ip := range ips {
			if instance.shouldFilterIP(ip) {
				continue
			}
			_ = shstore.Append(ip, name)
		}
		resolved.Add(1)
	}

	// admit applies shard ownership and resume skipping to the name. For
	// extended-input lines ("name resolver ..."), only the leading name is keyed.
	admit := func(line string) bool {
		name := line
		if instance.options.ExtendedInput {
			if i := strings.IndexAny(name, " \t"); i >= 0 {
				name = name[:i]
			}
		}
		if !shardCfg.Owns(name) {
			return false
		}
		if ckpt != nil && ckpt.Has(name) {
			return false
		}
		return true
	}

	// produceErr is written by the producer goroutine before it closes its
	// output channel; the channel-close -> Run-drains -> Run-returns chain
	// establishes happens-before, so the read below (after Run) is safe.
	var produceErr error

	input := make(chan string, 4096)
	if !shardCfg.Enabled() && ckpt == nil {
		// fast path: no filtering, producer writes straight to the resolver.
		go func() {
			defer close(input)
			produceErr = produce(input)
		}()
	} else {
		raw := make(chan string, 4096)
		go func() {
			defer close(raw)
			produceErr = produce(raw)
		}()
		go func() {
			defer close(input)
			for name := range raw {
				if admit(name) {
					input <- name
				}
			}
		}()
	}

	if err := instance.runEngine(ctx, resolvers, qtype, input, storeResult, markDone); err != nil {
		return err
	}
	if produceErr != nil {
		return fmt.Errorf("could not read input: %w", produceErr)
	}

	gologger.Info().Msgf("Resolved %d hosts\n", resolved.Load())
	return nil
}

// runEngine consumes names from input using the configured resolution engine:
// the iterative-from-root resolver (no resolver list required) when
// Options.Iterative is set, otherwise the asynchronous stub resolver against
// the supplied recursive resolvers. Both feed answers to storeResult.
func (instance *Instance) runEngine(ctx context.Context, resolvers []string, qtype uint16, input <-chan string, storeResult func(name string, rcode int, a, aaaa []string), markDone func(string)) error {
	if instance.options.Iterative {
		// Each iterative worker holds one reused UDP socket; clamp the stub
		// thread count (which can be very large) to avoid fd exhaustion.
		workers := instance.options.Threads
		if workers <= 0 {
			workers = 200
		} else if workers > 1024 {
			workers = 1024
		}
		ir, err := iterative.New(iterative.Options{
			QueryType:   qtype,
			Concurrency: workers,
			IPv6:        qtype == dns.TypeAAAA,
		})
		if err != nil {
			return fmt.Errorf("could not create iterative resolver: %w", err)
		}
		gologger.Info().Msgf("Using iterative-from-root resolver (no recursive resolvers needed)\n")
		return ir.ResolveStream(ctx, input, iterative.StreamConfig{
			QueryType: qtype,
			OnResult: func(r *resolve.Result) {
				storeResult(r.Name, r.Rcode, r.A, r.AAAA)
			},
			OnError: func(name string, _ error) {
				markDone(name)
			},
		})
	}

	client, err := resolve.New(resolve.Options{
		Resolvers:             resolvers,
		QueryType:             qtype,
		MaxRetries:            instance.options.Retries,
		Concurrency:           instance.options.Threads,
		QPS:                   instance.options.QPS,
		Batch:                 parseBatchMode(instance.options.BatchMode),
		SocketCount:           instance.options.SocketCount,
		UDPSize:               instance.options.UDPSize,
		NoRecurse:             instance.options.NoRecurse,
		Sticky:                instance.options.Sticky,
		ResolverHealth:        instance.options.ResolverHealth,
		AdaptiveConcurrency:   instance.options.AdaptiveConcurrency,
		CrossCheck:            instance.options.CrossCheck,
		ExtendedInput:         instance.options.ExtendedInput,
		DisableIPVerification: instance.options.NoVerifyIP,
		DisableTCPFallback:    instance.options.NoTCPFallback,
		OnResult: func(r resolve.Result) {
			storeResult(r.Name, r.Rcode, r.A, r.AAAA)
		},
		OnError: func(name string, _ error) {
			markDone(name)
		},
	})
	if err != nil {
		return fmt.Errorf("could not create resolver: %w", err)
	}
	defer client.Close()
	return client.Run(ctx, input)
}

// postProcess performs the common steps after the store has been populated:
// optional root-domain extraction, wildcard removal, and output writing.
func (instance *Instance) postProcess(shstore *store.Store) error {
	if instance.options.AutoExtractRootDomains {
		gologger.Info().Msgf("Started extracting root domains\n")
		now := time.Now()
		if err := instance.autoExtractRootDomains(shstore); err != nil {
			return fmt.Errorf("could not extract root domains: %w", err)
		}
		gologger.Info().Msgf("Root domain extraction completed in %s\n", time.Since(now))
	}

	if len(instance.options.Domains) > 0 {
		gologger.Info().Msgf("Started removing wildcards records\n")
		now := time.Now()
		if err := instance.filterWildcards(shstore); err != nil {
			return fmt.Errorf("could not filter wildcards: %w", err)
		}
		gologger.Info().Msgf("Wildcard removal completed in %s\n", time.Since(now))
	}

	gologger.Info().Msgf("Finished enumeration, started writing output\n")
	now := time.Now()
	if err := instance.writeOutput(shstore); err != nil {
		return fmt.Errorf("could not write output: %w", err)
	}
	gologger.Info().Msgf("Output written in %s\n", time.Since(now))
	return nil
}

type item struct {
	ip     string
	domain string
}

// parseMassDNSOutputFile parses a raw massdns output file (used by the
// -ri/--raw-input compatibility path) into the store.
func (instance *Instance) parseMassDNSOutputFile(tmpFile string, store *store.Store) error {
	flushToDisk := func(ip string, domains []string) error {
		if err := store.Append(ip, domains...); err != nil {
			return fmt.Errorf("could not update record: %w", err)
		}
		return nil
	}

	bulkWriter := batcher.New[item](
		batcher.WithMaxCapacity[item](10000),
		batcher.WithFlushInterval[item](10*time.Second),
		batcher.WithFlushCallback[item](func(items []item) {
			ipMap := make(map[string][]string)
			for _, item := range items {
				ipMap[item.ip] = append(ipMap[item.ip], item.domain)
			}
			for ip, domains := range ipMap {
				if err := flushToDisk(ip, domains); err != nil {
					gologger.Fatal().Msgf("could not update record: %s", err)
				}
			}
		}),
	)

	bulkWriter.Run()

	err := parser.ParseFile(tmpFile, func(domain string, ips []string) error {
		for _, ip := range ips {
			if instance.shouldFilterIP(ip) {
				continue
			}
			bulkWriter.Append(item{ip: ip, domain: domain})
		}
		return nil
	})

	bulkWriter.Stop()
	bulkWriter.WaitDone()

	if err != nil {
		return fmt.Errorf("could not parse massdns output: %w", err)
	}

	return nil
}

func (instance *Instance) autoExtractRootDomains(store *store.Store) error {
	candidateRootDomains := make(map[string]struct{})
	store.Iterate(func(ip string, hostnames []string, counter int) {
		for _, hostname := range hostnames {
			rootDomain, err := publicsuffix.Domain(hostname)
			if err != nil {
				continue
			}
			candidateRootDomains[rootDomain] = struct{}{}
		}
	})

	// add the existing ones
	for _, domain := range instance.options.Domains {
		candidateRootDomains[domain] = struct{}{}
	}

	instance.options.Domains = make([]string, 0)
	for item := range candidateRootDomains {
		instance.options.Domains = append(instance.options.Domains, item)
	}

	return nil
}

func (instance *Instance) filterWildcards(st *store.Store) error {
	// Start to work in parallel on wildcards
	wildcardWg := sizedwaitgroup.New(instance.options.WildcardsThreads)

	var allCancelFunc []context.CancelFunc

	st.Iterate(func(ip string, hostnames []string, counter int) {
		ipCtx, ipCancelFunc := context.WithCancel(context.Background())
		allCancelFunc = append(allCancelFunc, ipCancelFunc)
		// We've stumbled upon a wildcard, just ignore it.
		if instance.wildcardStore.Has(ip) {
			return
		}

		// Perform wildcard detection on the ip, if an IP is found in the wildcard
		// we add it to the wildcard map so that further runs don't require such filtering again.
		if counter >= 5 || instance.options.StrictWildcard {
			for _, hostname := range hostnames {
				wildcardWg.Add()
				go func(ctx context.Context, ipCancelFunc context.CancelFunc, IP string, hostname string) {
					defer wildcardWg.Done()

					gologger.Info().Msgf("Started filtering wildcards for %s\n", hostname)

					select {
					case <-ctx.Done():
						return
					default:
					}

					isWildcard, ips := instance.wildcardResolver.LookupHost(hostname, []string{IP})
					if len(ips) > 0 {
						for ip := range ips {
							// we add the single ip to the wildcard list
							if err := instance.wildcardStore.Set(ip); err != nil {
								gologger.Error().Msgf("could not set wildcard ip: %s", err)
							}
							gologger.Info().Msgf("Removing wildcard %s\n", ip)
						}
					}

					if isWildcard {
						// we also mark the original ip as wildcard, since at least once it resolved to this host
						if err := instance.wildcardStore.Set(IP); err != nil {
							gologger.Error().Msgf("could not set wildcard ip: %s", err)
						}
						ipCancelFunc()
						gologger.Info().Msgf("Removed wildcard %s\n", IP)
					}

				}(ipCtx, ipCancelFunc, ip, hostname)
			}
		}
	})

	wildcardWg.Wait()

	for _, cancelFunc := range allCancelFunc {
		cancelFunc()
	}

	// Do a second pass as well and remove all the wildcards
	// from the store that we have found so that everything is covered
	allWildcardIPs := instance.wildcardResolver.GetAllWildcardIPs()
	for ip := range allWildcardIPs {
		_ = st.Delete(ip)
	}
	// drop all wildcard from the store
	return instance.wildcardStore.Iterate(func(k string) error {
		return st.Delete(k)
	})
}

func (instance *Instance) writeOutput(store *store.Store) error {
	// Write the unique deduplicated output to the file or stdout
	// depending on what the user has asked.
	var err error
	var output *os.File
	var safeWriter *ioutil.SafeWriter
	var w *bufio.Writer

	if instance.options.OutputFile != "" {
		output, err = os.Create(instance.options.OutputFile)
		if err != nil {
			return fmt.Errorf("could not create massdns output file: %v", err)
		}
		w = bufio.NewWriter(output)
		safeWriter, err = ioutil.NewSafeWriter(w)
		if err != nil {
			return fmt.Errorf("could not create safe writer: %v", err)
		}
	}

	uniqueMap := mapsutil.NewSyncLockMap[string, struct{}]()

	// write count of resolved hosts
	var resolvedCount atomic.Int32

	// if trusted resolvers are specified verify the results
	var dnsResolver *dnsx.DNSX
	if len(instance.options.TrustedResolvers) > 0 {
		gologger.Info().Msgf("Trusted resolvers specified, verifying results\n")
		options := dnsx.DefaultOptions
		resolvers, err := wildcards.LoadResolversFromFile(instance.options.TrustedResolvers)
		if err != nil {
			return fmt.Errorf("could not load trusted resolvers: %w", err)
		}
		options.BaseResolvers = resolvers
		dnsResolver, err = dnsx.New(options)
		if err != nil {
			return fmt.Errorf("could not create dns resolver: %w", err)
		}
	}

	swg := sizedwaitgroup.New(instance.options.WildcardsThreads)

	store.Iterate(func(ip string, hostnames []string, counter int) {
		for _, hostname := range hostnames {
			// Skip if we already printed this subdomain once
			if uniqueMap.Has(hostname) {
				continue
			}
			_ = uniqueMap.Set(hostname, struct{}{})

			swg.Add()
			go func(hostname string) {
				defer swg.Done()

				if dnsResolver != nil {
					if resp, err := dnsResolver.QueryOne(hostname); err != nil || (len(resp.A) == 0 && len(resp.AAAA) == 0) {
						gologger.Info().Msgf("not resolved with trusted resolver - skipping: %s", hostname)
						return
					} else {
						// perform a last check on wildcards ip in case some hosts sneaked due to bad resolvers
						addrs := append(append([]string{}, resp.A...), resp.AAAA...)
						for _, ip := range addrs {
							if instance.wildcardStore.Has(ip) {
								gologger.Info().Msgf("resolved with trusted resolver but is a wildcard - skipping: %s", hostname)
								return
							}
						}

						gologger.Info().Msgf("resolved with trusted resolver: %s", hostname)

						if instance.options.OnResult != nil {
							instance.options.OnResult(resp)
						}
					}
				}

				var buffer strings.Builder

				if instance.options.Json {
					hostnameJson, err := json.Marshal(map[string]interface{}{"hostname": hostname})
					if err != nil {
						gologger.Error().Msgf("could not marshal output as json: %v", err)
					}

					buffer.WriteString(string(hostnameJson))
					buffer.WriteString("\n")
				} else {
					buffer.WriteString(hostname)
					buffer.WriteString("\n")
				}

				data := buffer.String()

				if output != nil {
					_, _ = safeWriter.Write([]byte(data))
				}
				gologger.Silent().Msgf("%s", data)
				resolvedCount.Add(1)
			}(hostname)
		}
	})

	swg.Wait()

	gologger.Info().Msgf("Total resolved: %d\n", resolvedCount.Load())

	// Close the files and return
	if output != nil {
		_ = w.Flush()
		_ = output.Close()
	}
	return nil
}

// ProcessDomainStreaming resolves a domain bruteforce by streaming generated
// permutations directly into the native resolver (no chunk files).
func (instance *Instance) ProcessDomainStreaming(ctx context.Context, wordlistFile *os.File) error {
	shstore, err := store.New(instance.options.TempDir)
	if err != nil {
		return fmt.Errorf("could not create store: %w", err)
	}
	defer shstore.Close()

	gologger.Info().Msgf("Started bruteforce resolution with native resolver\n")
	now := time.Now()

	var permutationCount atomic.Int64
	err = instance.resolveNames(ctx, shstore, func(out chan<- string) error {
		scanner := bufio.NewScanner(wordlistFile)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			// RFC4343 - case insensitive domain
			text := strings.ToLower(strings.TrimSpace(scanner.Text()))
			if text == "" {
				continue
			}
			for _, domain := range instance.options.Domains {
				out <- text + "." + domain
				permutationCount.Add(1)
			}
		}
		return scanner.Err()
	})
	if err != nil {
		return fmt.Errorf("could not resolve permutations: %w", err)
	}

	gologger.Info().Msgf("Resolved %d permutations in %s\n", permutationCount.Load(), time.Since(now))

	return instance.postProcess(shstore)
}

// ProcessSubdomainsStreaming resolves a list of subdomains by streaming them
// directly into the native resolver (no chunk files).
func (instance *Instance) ProcessSubdomainsStreaming(ctx context.Context, subdomainReader io.Reader) error {
	shstore, err := store.New(instance.options.TempDir)
	if err != nil {
		return fmt.Errorf("could not create store: %w", err)
	}
	defer shstore.Close()

	gologger.Info().Msgf("Started resolving subdomains with native resolver\n")
	now := time.Now()

	var subdomainCount atomic.Int64
	err = instance.resolveNames(ctx, shstore, func(out chan<- string) error {
		scanner := bufio.NewScanner(subdomainReader)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			// RFC4343 - case insensitive domain
			subdomain := strings.ToLower(strings.TrimSpace(scanner.Text()))
			if subdomain == "" {
				continue
			}
			out <- subdomain
			subdomainCount.Add(1)
		}
		return scanner.Err()
	})
	if err != nil {
		return fmt.Errorf("could not resolve subdomains: %w", err)
	}

	gologger.Info().Msgf("Resolved input of %d subdomains in %s\n", subdomainCount.Load(), time.Since(now))

	return instance.postProcess(shstore)
}
