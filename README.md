### Blacksocks

This is a fast SOCKS5 server with built-in Asynchronous DNS resolver.


## Usage

$ make

$ sudo make install

Modify /etc/blacksocks.conf if necessary.

$ sudo debian/postinst configure

$ sudo /etc/init.d/blacksocks start


## Features

* I/O multiplexing by epoll()
* built-in cached async DNS A resolver


## Limitations

* Only support IPV4.
* Use epoll(), therefor only work on Linux.
* Can not fully utilize mutlicore or hyperthreaded CPU.


## Intended use

* Embedded devices.
* Combine with iptables, redirect Internet traffic through VPN tunnel.
* ...



[Contact me](mailto: weichen302@gmail.com)
