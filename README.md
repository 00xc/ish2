# ish2
Fast, lightweight CLI tool to check if a host supports HTTP/2 via ALPN.

## Dependencies ##
Compiled with OpenSSL 1.0.2n.\
On Debian-based:\
`sudo apt install libssl1.0-dev`

## Compiling ##
`gcc ish2.c -o ish2 -lssl -lcrypto`

## Usage ##
`./ish2 <IP> [<port=443>]`

For example:
```
$ ./ish2 www.google.com
www.google.com h2
$ ./ish2 www.github.com
www.github.com http/1.1
```
