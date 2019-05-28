# ish2
Lightweight CLI tool to check if a host supports HTTP/2 via ALPN.

# Installing #
`gcc ish2.c -o ish2 -lssl -lcrypto`

# Usage #
`./ish2 <IP> [<port=443>]`

# Dependencies #
Compiled with OpenSSL 1.0.2n.
On Debian-based:
`sudo apt install libssl1.0-dev`
