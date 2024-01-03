# Argon2id Hash Cracker
```
 ---------------------------------
| Cyclone's Argon2id Hash Cracker |
 ---------------------------------

Hash file: hash.txt
Total Hashes: 1
CPU Threads: 16
Wordlist: wordlist.txt
Working...

$argon2id$v=19$m=65536,t=4,p=1$d2tycHJEYlBuenNEOUpqNg$pEXhocM661JmS3oRCR6MPQ:password

Cracked:        1/1
Hashrate:       1.45/s
Runtime:        00h:00m:00s
```
### Info:
I wrote this tool due to the limited selection of programs that can crack/verify argon2id hashes. Hashcat currently lacks support for any argon algo, and even though John the Ripper does support it in its bleeding-edge version, the high memory requirements of argon2id make it impractical for handling higher-cost memory argon2id hashes that demand more memory than most GPUs have. If your GPU allows it, I suggest running argon2id hashes with JTR first. If not, `Argon2id Hash Cracker` may be your only choice as it is only limited by your system RAM and CPU.

Example hash: `$argon2id$v=19$m=65536,t=4,p=1$d2tycHJEYlBuenNEOUpqNg$pEXhocM661JmS3oRCR6MPQ`

Plaintext: `password`
### Usage:

`./argon_cracker -w wordlist.txt -h hashes.txt`
### Changelog:
- v0.1.0; 2024-01-03.1600; initial github release

### Compile from source code info:
- https://github.com/cyclone-github/scripts/blob/main/intro_to_go.txt
