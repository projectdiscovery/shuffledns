<h1 align="center">
  <img src="static/shuffledns-logo.png" alt="shuffledns" width="200px">
  <br>
</h1>

<h4 align="center">massDNS wrapper to bruteforce and resolve the subdomains with wildcard handling support</h4>


<p align="center">
<a href="https://goreportcard.com/report/github.com/projectdiscovery/shuffledns"><img src="https://goreportcard.com/badge/github.com/projectdiscovery/shuffledns"></a>
<a href="https://github.com/projectdiscovery/shuffledns/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>
<a href="https://github.com/projectdiscovery/shuffledns/releases"><img src="https://img.shields.io/github/release/projectdiscovery/shuffledns"></a>
<a href="https://twitter.com/pdiscoveryio"><img src="https://img.shields.io/twitter/follow/pdiscoveryio.svg?logo=twitter"></a>
<a href="https://discord.gg/projectdiscovery"><img src="https://img.shields.io/discord/695645237418131507.svg?logo=discord"></a>
</p>
      
<p align="center">
  <a href="#features">Feature</a> •
  <a href="#installation-instructions">Install</a> •
  <a href="#running-shuffledns">Run</a> •
  <a href="#handling-wildcards">Wildcard</a> •
  <a href="#license">License</a> •
  <a href="https://discord.gg/projectdiscovery">Discord</a>
</p>

---


`shuffleDNS` is a wrapper around `massdns`, written in go, that allows you to enumerate valid subdomains using active bruteforce, as well as resolve subdomains with wildcard handling and easy input-output support.

Based on the work on `massdns` project by [@blechschmidt](https://github.com/blechschmidt).

 # Features

<h1 align="left">
  <img src="static/shuffledns-run.png" alt="shuffledns" width="700px">
  <br>
</h1>

 - Simple and modular code base making it easy to contribute.
 - Fast And Simple active subdomain scanning.
 - Handles wildcard subdomains in a smart manner.
 - Optimized for **ease of use**
 - **Stdin** and **stdout** support for integrating in workflows

# Usage

```bash
shuffledns -h
```
This will display help for the tool. Here are all the switches it supports.

```yaml
shuffleDNS is a wrapper around massdns written in go that allows you to enumerate valid subdomains using active bruteforce as well as resolve subdomains with wildcard handling and easy input-output support.

Usage:
  ./shuffledns [flags]

Flags:
Flags:
INPUT:
   -d, -domain string[]           Domain to find or resolve subdomains for
   -ad, -auto-domain              Automatically extract root domains
   -l, -list string               File containing list of subdomains to resolve
   -w, -wordlist string           File containing words to bruteforce for domain
   -r, -resolver string           File containing list of resolvers for enumeration
   -tr, -trusted-resolver string  File containing list of trusted resolvers
   -ri, -raw-input string         Validate raw full massdns output
   -mode string                   Execution mode (bruteforce, resolve, filter)

RATE-LIMIT:
   -t int  Number of concurrent massdns resolves (default 10000)

UPDATE:
   -up, -update                 update shuffledns to latest version
   -duc, -disable-update-check  disable automatic shuffledns update check

OUTPUT:
   -o, -output string            File to write output to (optional)
   -j, -json                     Make output format as ndjson
   -wo, -wildcard-output string  Dump wildcard ips to output file

CONFIGURATIONS:
   -m, -massdns string         Path to the massdns binary
   -mcmd, -massdns-cmd string  Optional massdns commands to run (example '-i 10')
   -directory string           Temporary directory for enumeration

OPTIMIZATIONS:
   -retries int           Number of retries for dns enumeration (default 5)
   -sw, -strict-wildcard  Perform wildcard check on all found subdomains
   -wt int                Number of concurrent wildcard checks (default 250)

DEBUG:
   -silent         Show only subdomains in output
   -version        Show version of shuffledns
   -v              Show Verbose output
   -nc, -no-color  Don't Use colors in output
```

<table>
<tr>
<td>  

## Prerequisite

`shuffledns` requires `massdns` to be installed in order to perform its operations. You can see the installation instructions at [massdns project](https://github.com/blechschmidt/massdns#compilation). If you place the binary in `/usr/bin/massdns` or `/usr/local/bin/massdns`, the tool will auto-detect the presence of the binary and use it. On Windows, you need to supply the path to the binary for the tool to work.

The tool also needs a list of valid resolvers. The [dnsvalidator](https://github.com/vortexau/dnsvalidator) project can be used to generate these lists. You also need to provide wordlist, you can use a custom wordlist or use the [commonspeak2-wordlist](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt).

</td>
</tr>
</table>

## Installation Instructions

`shuffledns` requires `go1.21+` to install successfully. Run the following command to install the latest version: 

```bash
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
```

## Running shuffledns

`shuffledns` supports two types of operations:

<ins>**Subdomain resolving**</ins>

To resolve a list of subdomains, you can pass the list of subdomains via the `-list` option.

```bash
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt -mode resolve
```

This will run the tool against subdomains in `example-subdomains.txt` and returns the results. The tool uses the resolvers specified with `-r` flag to do the resolving.

You can also pass the list of subdomains at standard input (STDIN). This allows for easy integration in automation pipelines.

```bash
subfinder -d example.com | shuffledns -d example.com -r resolvers.txt -mode resolve
```

This uses the subdomains found passively by `subfinder` and resolves them with `shuffledns` returning only the unique and valid subdomains.

<ins>**Subdomain Bruteforcing**</ins>

`shuffledns` also supports bruteforce of a target with a given wordlist. You can use the `w` flag to pass a wordlist which will be used to generate permutations that will be resolved using massdns.

```bash
shuffledns -d hackerone.com -w wordlist.txt -r resolvers.txt -mode bruteforce
```

This will run the tool against `hackerone.com` with the wordlist `wordlist.txt`. The domain bruteforce can also be done with standard input as in previous example for resolving the subdomains.

```bash
echo hackerone.com | shuffledns -w wordlist.txt -r resolvers.txt -mode bruteforce
```

---

<table>
<tr>
<td>

## Handling Wildcards

A special feature of `shuffleDNS` is its ability to handle multi-level DNS based wildcards, and do it so with a very reduced number of DNS requests. Sometimes all the subdomains would resolve, leading to lots of garbage in the results. The way `shuffleDNS` handles this is by keeping track of how many subdomains point to an IP, and if the number of subdomains increase beyond a certain small threshold, it checks for wildcard on all the levels of the hosts for that IP iteratively.

</td>
</tr>
</table>

### Notes

- Wildcard filter feature works with domain (`-d`) input only.
- Resolving or Brute-forcing only one operation can be done at a time. 

### License

`shuffledns` is distributed under [GPL v3 License](https://github.com/projectdiscovery/shuffledns/blob/main/LICENSE.md)
