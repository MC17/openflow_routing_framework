

# follows are the convert method
# welcome to complement if needed
#
#mac(bin) <-> string
#ipv4_src(long) <-> string
#ipv6_src <-> string
#
#

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

# ipv6
    
if __name__ == '__main__':
    a = 3232236035
    print ipv4_to_str(a)








