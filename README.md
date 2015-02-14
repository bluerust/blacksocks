### Blacksocks

This is a fast SOCKS5 server with built-in Asynchronous dns resolver.


## Usage

make
sudo make install

modify /etc/blacksocks.conf if needed.

run `/etc/init.d/blacksocks start`

## Features

* I/O multiplexing by epoll()
* built-in cached async DNS A resolver


## Intended use

* Embedded devices.
* Combine with iptables, redirect internet traffic through tunnel.



[Contact me](mailto: weichen302@gmail.com)
