================
recordbuilder.py
================

``recordbuilder.py`` is a small shell tool and library for building records
for the djbdns / tinydns DNS server. It is more or less a port of the great
buildRecord.cgi_ by Anders Brownworth that you may try out `at his website`_.

You can find some more information about each record type over there as well.

The program requires Python >=3.5 as it makes use of
``ipaddress.IPv4Address.reverse_pointer`` (new in Python 3.5) in the ``aaaa``
function. If you do not use that function you should get away with Python >=3.3,
and if you remove ``import ipaddress``, any Py3k should be fine.

.. _buildRecord.cgi:
        https://andersbrownworth.com/projects/sysadmin/djbdnsRecordBuilder/buildRecord.txt
.. _at his website:
        https://andersbrownworth.com/projects/sysadmin/djbdnsRecordBuilder/

Usage
=====

::

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

    $ ./recordbuilder.py aaaa example.net 2001:db8::ff00:42:8329 3600
    :example.net:28:\040\001\015\270\000\000\000\000\000\000\377\000\000\102\203\051:3600
    ^9.2.3.8.2.4.0.0.0.0.f.f.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa:example.net:3600
