import convert


class Gateway(object):
    def __init__(
            self, name='', ip='', ipv6='', num='',
            prefixlen='', ipv6prefixlen='', border=False):
        self.port_name = name
        self.gw_ip = convert.ipv4_to_int(ip)
        self.gw_ipv6 = convert.ipv6_to_bin(ipv6)
        self.port_num = num
        self.prefixlen = int(prefixlen)
        self.ipv6prefixlen = int(ipv6prefixlen)
        self.border = border

    def __str__(self):
        return 'Gateway<name=%s,gw_ip=%s,gw_ipv6=%s,port_num=%s,\
prefixLen=%s,ipv6prefixlen=%s,border=%s>' % (
            self.port_name, convert.ipv4_to_str(self.gw_ip),
            convert.bin_to_ipv6(self.gw_ipv6),
            self.port_num, self.prefixlen, self.ipv6prefixlen, self.border)
