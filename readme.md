# TCPMPing

TCP SYN ping multiple hosts

Quick start: `tcpmping google.com facebook.com`

Requires `CAP_NET_RAW` to work.

```bash
setcap cap_net_raw+ep tcpmping
```

Try these great tools if you need only one single host:
* [tcpping](https://github.com/deajan/tcpping)
* [hping](http://www.hping.org)
* [nping](https://nmap.org/nping/)

Forked from http://www.programming-pcap.aldabaknocking.com/code/tcpsyndos.c

## Compile

Should compile directly with `gcc main.c`. Tested on CentOS7.

## Release

Please find the Github [release](https://github.com/liqi0816/tcpmping/releases) page.

## Documentation

Usage: `tcpmping [OPTION...] <remote_host>[:<remote_port>]...`

Options:

```
-c, --count=<count>        (default=3) Stop after sending <count> packets
-l, --loose                (default=false) Accept non-TCP response packets
-p, --port=<remote_port>   (default=80) Default remote port to use
-r, --throttle             (default=0.3) Wait <throttle> seconds between sending each packet
-s, --source=<source_ip>   (default=0.0.0.0) Source IP address to use
-t, --timeout=<timeout>    (default=1.5) Time to wait for a response, in seconds
-v, --verbose              (default=false) verbose mode
-?, --help                 Give this help list
    --usage                Give a short usage message
-V, --version              Print program version
```

Mandatory or optional arguments to long options are also mandatory or optional
for any corresponding short options.

## Smokeping

Put `TCPMPing.pm` inside `/usr/share/smokeping/Smokeping/probes`.

## License

This code is distributed under the GPL License.
