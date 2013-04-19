

# follows are the convert method
# welcome to complement if needed
#
#mac(bin) <-> string
#ipv4_src(long) <-> string
#ipv6_src <-> string
#
#
import struct
from types import *

_HADDR_LEN = 6
_IPV4_LEN = 4
_IPV6_LEN = 16


def haddr_to_str(addr):
    """Format mac address in internal representation into human readable
    form"""
    if addr is None:
        return 'None'
    assert len(addr) == _HADDR_LEN
    return ':'.join('%02x' % ord(char) for char in addr)


def haddr_to_bin(string):
    """Parse mac address string in human readable format into
    internal representation"""
    hexes = string.split(':')
    if len(hexes) != _HADDR_LEN:
        raise ValueError('Invalid format for mac address: %s' % string)
    return ''.join(chr(int(h, 16)) for h in hexes)

def ipNum(  w, x, y, z ):
    """Generate unsigned int from components of IP address
       returns: w << 24 | x << 16 | y << 8 | z"""
    return ( w << 24 ) | ( x << 16 ) | ( y << 8 ) | z

# ip eg '192.168.1.1'
def ipv4_to_int(ip):
    "Parse an IP address and return an unsigned int."
    args = [ int( arg ) for arg in ip.split( '.' ) ]
    return ipNum( *args )

# ip eg 62258 (int or long)
def ipv4_to_str( ip ):
    """Generate IP address string from an unsigned int.
       ip: unsigned int of form w << 24 | x << 16 | y << 8 | z
       returns: ip address string w.x.y.z"""
    w = ( ip >> 24 ) & 0xff
    x = ( ip >> 16 ) & 0xff
    y = ( ip >> 8 ) & 0xff
    z = ip & 0xff
    return "%i.%i.%i.%i" % ( w, x, y, z )


def ipv4_in_network(ip, network, prefix):
    '''
        return True if the ip address is in network/prefix,
        ip and network should be in binary representation
    '''
    mask = ipv4_prefix_to_bin(prefix)
    if (mask & ip) == (mask & network):
        return True
    else:
        return False

def ipv4_prefix_to_bin(prefix):
    mask = 0
    for i in xrange(prefix):
        mask = (mask << 1) | 1
    mask = mask << (32 - prefix)
    return mask


# ipv6

IPV6_PACK_STR = '!8H'


def ipv6_to_arg_list(ipv6):
    '''
        convert ipv6 string to a list of 8 different parts
    '''
    args = []
    if '::' in ipv6:
        h, t = ipv6.split('::')
        h_list = [int(x, 16) for x in h.split(':')]
        t_list = [int(x, 16) for x in t.split(':')]
        args += h_list
        zero = [0]
        args += ((8 - len(h_list) - len(t_list)) * zero)
        args += t_list
    else:
        args = [int(x, 16) for x in ipv6.split(':')]

    return args


def ipv6_to_bin(ipv6):
    '''
        convert ipv6 string to binary representation
    '''
    args = ipv6_to_arg_list(ipv6)
    return struct.pack(IPV6_PACK_STR, *args)

def arg_list_to_ipv6_bin(args):
    return struct.pack(IPV6_PACK_STR, *args)

def bin_to_ipv6(bin_addr):
    '''
        convert binary representation to human readable string
    '''
    args = struct.unpack_from(IPV6_PACK_STR, bin_addr)
    return ':'.join('%x' % x for x in args)
    

def ipv6_prefix_to_arg_list(prefix):
    ffffs = prefix / 16
    residue = prefix % 16
    zeros = (128 - prefix) / 16
    args = []
    args += ffffs * [0xffff]
    mask = 0
    for i in xrange(residue):
        mask = (mask << 1) | 1
    mask = mask << (16 - residue)
    args.append(mask)
    args += [0] * zeros
    return args

def ipv6_in_network(ipv6, network, ipv6_prefix):
    '''
        return True if ipv6 is in network/prefix,
        ipv6 and network should be in binary representation
    '''
    mask_arg = ipv6_prefix_to_arg_list(ipv6_prefix)
    ipv6_arg = struct.unpack_from(IPV6_PACK_STR, ipv6)
    network_arg = struct.unpack_from(IPV6_PACK_STR, network)

    for mask, ipv6, network in zip(mask_arg, ipv6_arg, network_arg):
        if mask & ipv6 != mask & network:
            return False
    return True
            
    
if __name__ == '__main__':
    a = 3232236035
    print ipv4_to_str(a)
    print bin_to_ipv6(ipv6_to_bin('3f:10::1:2'))
    print bin_to_ipv6(ipv6_to_bin('2013:da8:215:8f2:aa20:66ff:fe4c:9c3c'))
    ipv4 = ipv4_to_int('192.168.1.1')
    ipv4_network = ipv4_to_int('192.168.2.254')
    print ipv4_in_network(ipv4, ipv4_network, 24)
    ipv6 = ipv6_to_bin('2013:da8:215:8f2:aa20:66ff:fe4c:9c3c')
    ipv6_network = ipv6_to_bin('2013:da18:215:8f2:aa20:66ff:ffff:ff3d')
    print ipv6_in_network(ipv6, ipv6_network, 65)

