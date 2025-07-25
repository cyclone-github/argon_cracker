[![Readme Card](https://github-readme-stats.vercel.app/api/pin/?username=cyclone-github&repo=argon_cracker&theme=gruvbox)](https://github.com/cyclone-github/argon_cracker/)

[![Go Report Card](https://goreportcard.com/badge/github.com/cyclone-github/argon_cracker)](https://goreportcard.com/report/github.com/cyclone-github/argon_cracker)
[![GitHub issues](https://img.shields.io/github/issues/cyclone-github/argon_cracker.svg)](https://github.com/cyclone-github/argon_cracker/issues)
[![License](https://img.shields.io/github/license/cyclone-github/argon_cracker.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/release/cyclone-github/argon_cracker.svg)](https://github.com/cyclone-github/argon_cracker/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/cyclone-github/argon_cracker.svg)](https://pkg.go.dev/github.com/cyclone-github/argon_cracker)

# Argon2id Hash Cracker
```
 ---------------------------------
| Cyclone's Argon2id Hash Cracker |
 ---------------------------------

Hash file:      hash.txt
Valid Hashes:   4
Invalid Hashes: 1
CPU Threads:    56
Wordlist:       cyclone.txt
Working...

$argon2id$v=19$m=65536,t=4,p=1$d2tycHJEYlBuenNEOUpqNg$pEXhocM661JmS3oRCR6MPQ:password
$argon2id$v=19$m=100000,t=4,p=1$cXVrNUdUVHI1SmN3RjcwNw$hMBzEYMGeblwwhj56bW6ig:password
$argon2id$v=19$m=65536,t=4,p=1$VWF5MkY2S3pYdm1nZm1HdQ$V3CVYSZuo4hAIgAPicV0NA:password1
$argon2id$v=19$m=65536,t=4,p=1$VWF5MkY2S3pYdm1nZm1HdQ$3zL8i47o4/l9rhLuDZE1oQ:passwords

Cracked:        4/4
Hashrate:       81.09/s
Runtime:        00h:00m:58s
```
### Info:
I wrote this tool due to the limited selection of programs that can crack/verify argon2id hashes. Hashcat currently lacks support for any argon algo, and even though John the Ripper does support it in its bleeding-edge version, the high memory requirements of argon2id make it impractical for handling higher-cost memory argon2id hashes that demand more memory than most GPUs have. If your GPU allows it, I suggest running argon2id hashes with JTR first. If not, `Argon2id Hash Cracker` may be your only choice as it is only limited by your system RAM and CPU.

Example hash: `$argon2id$v=19$m=65536,t=4,p=1$d2tycHJEYlBuenNEOUpqNg$pEXhocM661JmS3oRCR6MPQ`

Plaintext: `password`
### Usage:

`./argon_cracker -w wordlist.txt -h hashes.txt`
### Changelog:
- https://github.com/cyclone-github/argon_cracker/blob/main/CHANGELOG.md

### Compile from source:
- If you want the latest features, compiling from source is the best option since the release version may run several revisions behind the source code.
- This assumes you have Go and Git installed
  - `git clone https://github.com/cyclone-github/argon_cracker.git`  # clone repo
  - `cd argon_cracker`                                               # enter project directory
  - `go mod init argon_cracker`                                      # initialize Go module (skips if go.mod exists)
  - `go mod tidy`                                              # download dependencies
  - `go build -ldflags="-s -w" .`                              # compile binary in current directory
  - `go install -ldflags="-s -w" .`                            # compile binary and install to $GOPATH
  - `./argon_cracker -h {hash file} -w {wordlist file} -t {CPU threads to use (optional)}`
- Compile from source code how-to:
  - https://github.com/cyclone-github/scripts/blob/main/intro_to_go.txt
