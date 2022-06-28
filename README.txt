djbdns / tinydns record builder
===============================

This is a small shell tool and library for building records for the djbdns /
tinydns DNS server. It is more or less a port of the great buildRecord.cgi by
Anders Brownworth, available here:
https://andersbrownworth.com/projects/sysadmin/djbdnsRecordBuilder/

The program requires Python >=3.5 as it makes use of
ipaddress.IPv4Address.reverse_pointer (new in Python 3.5) in the aaaa function.


== Usage ==

$ ./recordbuilder.py
You may create the following records:

AAAA domain address ttl
CAA domain flag tag value ttl
DOMAINKEYS domain keytype key ttl
NAPTR domain order preference flag services regexp replacement ttl
SPF domain text ttl
SRV service priority weight port target ttl
TXT domain text ttl

Run recordbuilder.py with only the record type as argument to see more info,
e.g. ./recordbuilder.py aaaa

$ ./recordbuilder.py aaaa
Usage: AAAA domain address ttl
Construct a generic AAAA record.

Arguments:
    domain -- the hostname to map an IPv6 address to
    address -- the IPv6 address, zero compression is supported
    ttl -- time to live (int)

Returns a generic AAAA record and a PTR record.

$ ./recordbuilder.py aaaa example.com 2606:2800:220:1:248:1893:25c8:1946 3600
:example.com:28:\046\006\050\000\002\040\000\001\002\110\030\223\045\310\031\106:3600
^6.4.9.1.8.c.5.2.3.9.8.1.8.4.2.0.1.0.0.0.0.2.2.0.0.0.8.2.6.0.6.2.ip6.arpa:example.com:3600
