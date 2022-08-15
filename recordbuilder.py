#!/usr/bin/env python3
import functools
import inspect
import ipaddress
import sys

_cli_commands = {}


def cli(*cli_args):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)

        tupled_args = []
        str_args = []
        for arg in cli_args:
            tupled_args.append(arg if isinstance(arg, tuple) else (arg, None))
            str_args.append(arg[0] if isinstance(arg, tuple) else arg)

        _cli_commands[func.__name__] = {
            'func': func,
            'args': tupled_args,
            'help': '{} {}'.format(func.__name__.upper(), ' '.join(str_args)),
            'doc': inspect.getdoc(func)
        }

        return wrapper
    return decorator


def run_cli():
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
    else:
        command = None

    if command in ('help', '--help', '-h') or command is None:
        print("You may create the following records:\n")

        for arg_data in _cli_commands.values():
            print(arg_data['help'])

        print(
            "\nRun recordbuilder.py with only the record type as argument"
            " to see more info,\ne.g. ./recordbuilder.py aaaa"
        )
        return

    cmd = _cli_commands.get(command)
    if not cmd:
        print("Did not understand argument '{}'?".format(command), file=sys.stderr)
        return 1

    if len(sys.argv[2:]) < len(cmd['args']):
        exit_code = 0
        if sys.argv[2:]:
            print("Too few arguments.\n", file=sys.stderr)
            exit_code = 1
        print("Usage:", cmd['help'])
        print(cmd['doc'])
        return exit_code

    parsed_args = []
    for arg_val, arg_desc in zip(sys.argv[2:], cmd['args']):
        if arg_desc[1]:
            try:
                arg_parsed = arg_desc[1](arg_val)
            except ValueError:
                print(
                    "{arg} must be of type {type} and '{val}' can't be parsed as such"
                    .format(arg=arg_desc[0], type=arg_desc[1].__name__, val=arg_val),
                    file=sys.stderr
                )
                return 1
            parsed_args.append(arg_parsed)
        else:
            parsed_args.append(arg_val)

    res = _cli_commands[command]['func'](*parsed_args)
    print(res)


def to_oct(n):
    return '\\{:03o}'.format(n)


def oct_len(s):
    return to_oct(len(s))


def escape_text(s):
    escapees = '\r\n\t: \\/'
    escaped = []
    for c in s:
        if c in escapees:
            escaped.append(to_oct(ord(c)))
        else:
            escaped.append(c)
    escaped = ''.join(escaped)
    return escaped


def escape_number(n):
    # n == high * 256 + low
    high = n // 256
    low = n % 256
    return to_oct(high) + to_oct(low)


@cli('domain', 'address', ('ttl', int))
def aaaa(domain, address, ttl):
    """Construct a generic AAAA record.

    Arguments:
        domain -- the hostname to map an IPv6 address to
        address -- the IPv6 address, zero compression is supported
        ttl -- time to live (int)

    Returns a generic AAAA record and a PTR record.
    """
    try:
        ip = ipaddress.IPv6Address(address)
    except ipaddress.AddressValueError:
        print(
            "Could not parse '{}' as an IPv6 address, see traceback:\n".format(address),
            file=sys.stderr
        )
        raise
    ip_oct = ''.join([to_oct(n) for n in ip.packed])
    aaaa = ':{domain}:28:{address}:{ttl}'.format(
        domain=escape_text(domain),
        address=ip_oct,
        ttl=ttl
    )
    reverse_ptr = '^{reverse}:{domain}:{ttl}'.format(
        reverse=ip.reverse_pointer,
        domain=escape_text(domain),
        ttl=ttl
    )
    return '{aaaa}\n{reverse_ptr}'.format(aaaa=aaaa, reverse_ptr=reverse_ptr)


@cli('domain', 'flag', 'tag', 'value', ('ttl', int))
def caa(domain, flag, tag, value, ttl):
    """Construct a generic CAA record.

    Arguments:
        domain -- the hostname for this record
        flag -- one of 0, 1
        tag -- one of 'issue', 'issuewild', 'iodef'
        value -- the value of the record
        ttl -- time to live (int)
    """
    if flag in (1, '1'):
        flag_oct = '\\200'
    elif flag in (0, '0'):
        flag_oct = '\\000'
    else:
        raise ValueError("flag must be one of 0, 1")

    if tag not in ('issue', 'issuewild', 'iodef'):
        raise ValueError("tag must be one of 'issue', 'issuewild', 'iodef'")

    result = ':{domain}:257:{flag}{tag}{value}:{ttl}'.format(
        domain=escape_text(domain),
        flag=flag_oct,
        tag=oct_len(tag) + tag,
        value=value,
        ttl=ttl
    )
    return result


@cli('domain', 'keytype', 'key', ('ttl', int))
def domainkeys(domain, keytype, key, ttl):
    """Construct a generic DKIM record.

    Arguments:
        domain -- the hostname for this record
        keytype -- should be 'rsa'
        key -- the public key
        ttl -- time to live (int)

    Newlines (\\n) and carriage returns (\\r) are removed automatically from
    the key.
    """
    key = key.replace('\n', '')
    key = key.replace('\r', '')
    if len(key) > 255:
        print(
            "Warning: key is > 255 octets and won't fit inside a single TXT record (splitting to multiple values)\n",
            file=sys.stderr
        )

    prefix = 'v=DKIM1; k={keytype}; p='.format(keytype=keytype)
    chunk_length = 250 - len(prefix)
    chunks = [key[i:i + chunk_length] for i in range(0, len(key), chunk_length)]

    lines = list()
    lines.append(prefix + chunks.pop(0))
    for chunk in chunks:
        lines.append(chunk)

    results = list()
    for line in lines:
        results.append(':{domain}:16:{line}:{ttl}'.format(
            domain=escape_text(domain),
            line=oct_len(line) + escape_text(line),
            ttl=ttl
        ))

    return '\n'.join(results)


@cli('domain', ('order', int), ('preference', int), 'flag', 'services', 'regexp', 'replacement', ('ttl', int))
def naptr(domain, order, preference, flag, services, regexp, replacement, ttl):
    """Construct a generic NAPTR record.

    Arguments:
        domain -- the hostname for this record
        order -- lower has precedence (int in range [0, 65535])
        preference -- lower has precedence (int in range [0, 65535])
        flag -- one of 'S', 'A', 'U', 'P'
        services -- the services offered
        regexp -- a regular expression rule, can be empty
        replacement -- a replacement pattern
        ttl -- time to live (int)
    """
    if not 0 <= order <= 65535:
        raise ValueError("order must be 0 <= order <= 65535")
    if not 0 <= preference <= 65535:
        raise ValueError("preference must be 0 <= preference <= 65535")

    if replacement:
        chunks = replacement.split('.')
        chunks_oct = []
        for chunk in chunks:
            chunks_oct.append(oct_len(chunk) + chunk)
        replacement_oct = ''.join(chunks_oct)
    else:
        replacement_oct = ''

    result = (
        ':{domain}:35:{order}{preference}{flag}{services}{regexp}{replacement}\\000:{ttl}'
        .format(
            domain=escape_text(domain),
            order=escape_number(order),
            preference=escape_number(preference),
            flag=oct_len(flag) + flag,
            services=oct_len(services) + escape_text(services),
            regexp=oct_len(regexp) + escape_text(regexp),
            replacement=replacement_oct,
            ttl=ttl
        )
    )
    return result


@cli('domain', 'text', ('ttl', int))
def spf(domain, text, ttl):
    """Construct a generic SPF record.

    Arguments:
        domain -- the hostname for this record
        text -- the SPF data
        ttl -- time to live (int)
    """
    result = ':{domain}:16:{text_len}{text}:{ttl}'.format(
        domain=escape_text(domain),
        text_len=oct_len(text),
        text=escape_text(text),
        ttl=ttl
    )
    return result


@cli('service', ('priority', int), ('weight', int), ('port', int), 'target', ('ttl', int))
def srv(service, priority, weight, port, target, ttl):
    """Construct a generic SRV record.

    Arguments:
        service -- on the form _service._proto.name.
        priority -- lower has precedence (int in range [0, 65535])
        weight -- higher has higher chance of getting picked (int in range [0, 65535])
        port -- the service's port (int in range [0, 65535])
        target -- hostname of the machine providing the service
        ttl -- time to live (int)
    """
    if not 0 <= priority <= 65535:
        raise ValueError("priority must be 0 <= priority <= 65535")
    if not 0 <= weight <= 65535:
        raise ValueError("weight must be 0 <= weight <= 65535")
    if not 0 <= port <= 65535:
        raise ValueError("port must be 0 <= port <= 65535")

    chunks = target.split('.')
    chunks_oct = []
    for chunk in chunks:
        chunks_oct.append(oct_len(chunk) + chunk)
    target_oct = ''.join(chunks_oct)
    result = (
        ':{service}:33:{priority}{weight}{port}{target}\\000:{ttl}'
        .format(
            service=escape_text(service),
            priority=escape_number(priority),
            weight=escape_number(weight),
            port=escape_number(port),
            target=target_oct,
            ttl=ttl
        )
    )
    return result


@cli('domain', 'text', ('ttl', int))
def txt(domain, text, ttl):
    """Construct a TXT record.

    Arguments:
        domain -- the hostname for the record
        text -- the value of the record
        ttl -- time to live (int)
    """
    result = "'{domain}:{text}:{ttl}".format(
        domain=escape_text(domain),
        text=escape_text(text),
        ttl=ttl
    )
    return result


if __name__ == '__main__':
    sys.exit(run_cli())
