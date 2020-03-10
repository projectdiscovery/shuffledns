<h1 align="left">
  <img src="static/shuffledns-logo.png" alt="shuffledns" width="200px"></a>
  <br>
</h1>

[![License](https://img.shields.io/badge/license-MIT-_red.svg)](https://opensource.org/licenses/MIT)
[![Go Report Card](https://goreportcard.com/badge/github.com/projectdiscovery/shuffledns)](https://goreportcard.com/report/github.com/projectdiscovery/shuffledns)
[![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/projectdiscovery/shuffledns/issues)

shuffleDNS is a wrapper around massdns written in go that allows you to enumerate valid subdomains using active bruteforce as well as resolve subdomains with wildcard handling and easy input-output support.

Based on the work on `massdns` project by [@blechschmidt](https://github.com/blechschmidt).

# Resources
- [Resources](#resources)
- [Features](#features)
- [Usage](#usage)
- [Installation Instructions](#installation-instructions)
  - [Prerequisite](#prerequisite)
  - [Direct Installation](#direct-installation)
    - [From Binary](#from-binary)
    - [From Source](#from-source)
- [Running shuffledns](#running-shuffledns)
    - [1. Resolving Subdomains](#1-resolving-subdomains)
    - [2. Bruteforcing Subdomains](#2-bruteforcing-subdomains)
    - [A note on wildcards](#a-note-on-wildcards)
- [License](#license)

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

| Flag           | Description                                             | Example                              |
|----------------|---------------------------------------------------------|--------------------------------------|
| -d             | Domain to find or resolve subdomains for                | shuffledns -d hackerone.com          |
| -directory     | Temporary directory for enumeration                     | shuffledns -directory /hdd           |
| -r             | File containing resolvers for enumeration               | shuffledns -r resolvers.txt          |
| -nC            | Don't Use colors in output                              | shuffledns -nC                       |
| -o             | File to save output result (optional)                   | shuffledns -o hackerone.txt          |
| -list          | List of subdomains to process for                       | shuffledns -list bugcrowd.txt        |
| -massdns       | Massdns binary path                                     | shuffledns -massdns /usr/bin/massdns |
| -retries       | Number of retries for dns enumeration (default 5)       | shuffledns -retries 1                |
| -silent        | Show only subdomains in output                          | shuffledns -silent                   |
| -t             | Number of concurrent massdns resolves (default 10000)   | shuffledns -t 100                    |
| -v             | Show Verbose output                                     | shuffledns -v                        |
| -version       | Show version of shuffledns                              | shuffledns -version                  |
| -w             | File containing words to bruteforce for domain          | shuffledns -w words.txt              |
| -wt            | Number of concurrent wildcard checks (default 25)       | shuffledns -wg 100                   |
| -raw-input     | File containing existing massdns output                 | shuffledns -massdns-file output.txt  |

# Installation Instructions

## Prerequisite

shuffledns requires massdns to be installed in order to perform its operations. You can see the install instructions at [https://github.com/blechschmidt/massdns#compilation](https://github.com/blechschmidt/massdns#compilation). 

If you place the binary in `/usr/bin/massdns` or `/usr/local/bin/massdns`, the tool will auto-detect the presence of the binary and use it. On windows, you need to supply the path to the binary for the tool to work.

The tool also needs a list of valid resolvers. The [dnsvalidator](https://github.com/vortexau/dnsvalidator) project can be used to generate these lists. Either you can use a custom wordlist or use the commonspeak2 wordlists at [commonspeak2-wordlist](https://github.com/assetnote/commonspeak2-wordlists/tree/master/subdomains).

## Direct Installation

### From Binary

The installation is easy. You can download the pre-built binaries for your platform from the [Releases](https://github.com/projectdiscovery/shuffledns/releases/) page. Extract them using tar, move it to your $PATH and you're ready to go.

```bash
> tar -xzvf shuffledns-linux-amd64.tar
> mv shuffledns-linux-amd64 /usr/bin/shuffledns
> shuffledns -h
```

### From Source

shuffledns requires go1.13+ to install successfully. Run the following command to get the repo - 

```bash
> GO111MODULE=on go get -u -v github.com/projectdiscovery/shuffledns/cmd/shuffledns
```

In order to update the tool, you can use -u flag with `go get` command.

# Running shuffledns

shuffledns supports two types of operations.

### 1. Resolving Subdomains

To resolve a list of subdomains, you can pass the list of subdomains via the `list` option.

```bash
> shuffledns -d example.com -list example.com-subdomains.txt -r resolvers.txt
```

This will run the tool against subdomains in `example.com-subdomains.txt` and returns the results. The tool uses the resolvers specified with -r option to do the resolving.

You can also pass the list of subdomains at standard input (STDIN). This allows for easy integration in automation pipelines.

```bash
> subfinder -d example.com | shuffledns -d example.com -r resolvers.txt
```

This uses the subdomains found passively by `subfinder` and resolves them with shuffledns returning only the unique and valid subdomains.

### 2. Bruteforcing Subdomains 

shuffledns also supports bruteforce of a target with a given wordlist. You can use the `w` flag to pass a wordlist which will be used to generate permutations that will be resolved using massdns.

```bash
> shuffledns -d hackerone.com -w wordlist.txt -r resolvers.txt
```

This will run the tool against `hackerone.com` with the wordlist `wordlist.txt`. The domain bruteforce can also be done with standard input as in previous example for resolving the subdomains.

```bash
> echo hackerone.com | shuffledns -w wordlist.txt -r resolvers.txt
```

---

The -o command can be used to specify an output file.

```bash
> shuffledns -d hackerone.com -w wordlist.txt -o output.txt
```

The subdomains discovered can be piped to other tools too. For example, you can pipe the host discovered by shuffledns to the [httprobe](https://github.com/tomnomnom/httprobe) tool by @tomnomnom which will then find running http servers on the host.

```bash
> echo hackerone.com | shuffledns -w wordlist.txt -r resolvers.txt -silent | httprobe

http://docs.hackerone.com
http://www.hackerone.com
http://info.hackerone.com
```

or

```bash
> echo hackerone.com | subfinder | shuffledns -d hackerone.com -r resolvers.txt -silent | httprobe

http://docs.hackerone.com
http://www.hackerone.com
http://info.hackerone.com
```

### A note on wildcards

A special feature of shuffleDNS is its ability to handle multi-level DNS based wildcards and do it so with very less number of DNS requests. Sometimes all the subdomains will resolve which will lead to lots of garbage in the results. The way shuffleDNS handles this is it will keep track of how many subdomains point to an IP and if the count of the Subdomains increase beyond a certain small threshold, it will check for wildcard on all the levels of the hosts for that IP iteratively. 

# License

shuffleDNS is made with 🖤 by the [projectdiscovery](https://projectdiscovery.io) team. Community contributions have made the project what it is. See the **[Thanks.md](https://github.com/projectdiscovery/shuffledns/blob/master/THANKS.md)** file for more details.
