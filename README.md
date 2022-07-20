<h1 align="center">
  <img src="static/shuffledns-logo.png" alt="shuffledns" width="200px"></a>
  <br>
</h1>

<h4 align="center">massDNS wrapper to bruteforce and resolve the subdomains with wildcard handling support</h4>

<p align="center">
<a href="https://goreportcard.com/report/github.com/mohammadanaraki/shuffledns"><img src="https://goreportcard.com/badge/github.com/mohammadanaraki/shuffledns"></a>
<a href="https://github.com/mohammadanaraki/shuffledns/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>
<a href="https://github.com/mohammadanaraki/shuffledns/releases"><img src="https://img.shields.io/github/release/projectdiscovery/shuffledns"></a>
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

shuffleDNS is a wrapper around massdns written in go that allows you to enumerate valid subdomains using active bruteforce as well as resolve subdomains with wildcard handling and easy input-output support.

Based on the work on `massdns` project by [@blechschmidt](https://github.com/blechschmidt).

# Features

<h1 align="left">
  <img src="static/shuffledns-run.png" alt="shuffledns" width="700px"></a>
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

| Flag      | Description                                           | Example                              |
| --------- | ----------------------------------------------------- | ------------------------------------ |
| d         | Domain to find or resolve subdomains for              | shuffledns -d hackerone.com          |
| directory | Temporary directory for enumeration                   | shuffledns -directory /hdd           |
| r         | File containing resolvers for enumeration             | shuffledns -r resolvers.txt          |
| nC        | Don't Use colors in output                            | shuffledns -nC                       |
| o         | File to save output result (optional)                 | shuffledns -o hackerone.txt          |
| list      | List of subdomains to process for                     | shuffledns -list bugcrowd.txt        |
| massdns   | Massdns binary path                                   | shuffledns -massdns /usr/bin/massdns |
| retries   | Number of retries for dns enumeration (default 5)     | shuffledns -retries 1                |
| silent    | Show only subdomains in output                        | shuffledns -silent                   |
| t         | Number of concurrent massdns resolves (default 10000) | shuffledns -t 100                    |
| v         | Show Verbose output                                   | shuffledns -v                        |
| version   | Show version of shuffledns                            | shuffledns -version                  |
| w         | File containing words to bruteforce for domain        | shuffledns -w words.txt              |
| wt        | Number of concurrent wildcard checks (default 25)     | shuffledns -wt 100                   |
| raw-input | File containing existing massdns output               | shuffledns -massdns-file output.txt  |

<table>
<tr>
<td>

## Prerequisite

shuffledns requires massdns to be installed in order to perform its operations. You can see the install instructions at [massdns project](https://github.com/blechschmidt/massdns#compilation). If you place the binary in `/usr/bin/massdns` or `/usr/local/bin/massdns`, the tool will auto-detect the presence of the binary and use it. On windows, you need to supply the path to the binary for the tool to work.

The tool also needs a list of valid resolvers. The [dnsvalidator](https://github.com/vortexau/dnsvalidator) project can be used to generate these lists. You also need to provide wordlist, you can use a custom wordlist or use the [commonspeak2-wordlist](https://s3.amazonaws.com/assetnote-wordlists/data/manual/best-dns-wordlist.txt).

</td>
</tr>
</table>

## Installation Instructions

shuffledns requires `go1.17+` to install successfully. Run the following command to get the repo -

```bash
go install -v github.com/mohammadanaraki/shuffledns/cmd/shuffledns@latest
```

## Running shuffledns

**shuffledns** supports two types of operations.

<ins>**Subdomain resolving** </ins>

To resolve a list of subdomains, you can pass the list of subdomains via the `list` option.

```bash
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

This will run the tool against subdomains in `example-subdomains.txt` and returns the results. The tool uses the resolvers specified with `-r` flag to do the resolving.

You can also pass the list of subdomains at standard input (STDIN). This allows for easy integration in automation pipelines.

```bash
subfinder -d example.com | shuffledns -d example.com -r resolvers.txt
```

This uses the subdomains found passively by `subfinder` and resolves them with shuffledns returning only the unique and valid subdomains.

<ins>**Subdomain Bruteforcing** </ins>

shuffledns also supports bruteforce of a target with a given wordlist. You can use the `w` flag to pass a wordlist which will be used to generate permutations that will be resolved using massdns.

```bash
shuffledns -d hackerone.com -w wordlist.txt -r resolvers.txt
```

This will run the tool against `hackerone.com` with the wordlist `wordlist.txt`. The domain bruteforce can also be done with standard input as in previous example for resolving the subdomains.

```bash
echo hackerone.com | shuffledns -w wordlist.txt -r resolvers.txt
```

---

<table>
<tr>
<td>

## Handling Wildcards

A special feature of shuffleDNS is its ability to handle multi-level DNS based wildcards and do it so with very less number of DNS requests. Sometimes all the subdomains will resolve which will lead to lots of garbage in the results. The way shuffleDNS handles this is it will keep track of how many subdomains point to an IP and if the count of the Subdomains increase beyond a certain small threshold, it will check for wildcard on all the levels of the hosts for that IP iteratively.

</td>
</tr>
</table>

### Notes

- Wildcard filter feature works with domain (-d) input only.
- Resolving or Brute-forcing only one operation can be done at a time.

### License

shuffledns is distributed under [MIT License](https://github.com/mohammadanaraki/shuffledns/blob/master/LICENSE.md)
