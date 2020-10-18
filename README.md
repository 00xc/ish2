# ish2
Fast, lightweight CLI tool to check if a host supports HTTP/2 via ALPN.

## Dependencies ##
Tested with OpenSSL 1.1.1d.\
On Debian-based:\
`sudo apt install libssl-dev`

## Compiling ##
Use `make`. Alternatively, if you do not want to verify the target's certificate (for example if it uses self-signed certificates), compile with `make noverify`.

## Usage ##
`./ish2 host [port]`.\
By default, port 443 is used.

For example:
```
$ ./ish2 www.google.com
www.google.com h2
$ ./ish2 www.github.com 443
www.github.com http/1.1
```

NOTE: this tool hangs when the server does not support HTTPS. The quickest workaround is to use [timeout(1)](https://man7.org/linux/man-pages/man1/timeout.1.html):
```
$ timeout 3 ./ish2 deaddomain.com
```
