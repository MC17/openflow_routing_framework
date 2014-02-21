import netaddr


class Gateway(object):
    def __init__(
            self, name='', ip='', ipv6='', port_no='',
            prefixlen='', ipv6prefixlen='', border=False):
        self.port_name = name
        self.gw_ip = netaddr.IPNetwork(ip)
        self.gw_ip.prefixlen = int(prefixlen)
        self.gw_ipv6 = netaddr.IPNetwork(ipv6)
        self.gw_ipv6.prefixlen = int(ipv6prefixlen)
        self.port_no = port_no
        self.isBorder = border

    def __str__(self):
        return 'Gateway<name=%s, gw_ip=%s, gw_ipv6=%s, port_num=%s, border=%s>'\
            % (
                self.port_name, str(self.gw_ip), str(self.gw_ipv6),
                self.port_no, self.isBorder
              )
