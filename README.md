# ish2
Fast, lightweight CLI tool to check if a host supports HTTP/2 via ALPN.

## Dependencies ##
Compiled with OpenSSL 1.1.1d.\
On Debian-based:\
`sudo apt install libssl-dev`

## Compiling ##
Use the make script:\
`$ ./make.sh`

## Usage ##
`./ish2 <IP> [<port=443>]`

For example:
```
$ ./ish2 www.google.com
www.google.com h2
$ ./ish2 www.github.com
www.github.com http/1.1
```
