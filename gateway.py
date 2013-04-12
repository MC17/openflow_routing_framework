

class Gateway(object):
    def __init__(self, name='', ip='', ipv6='', num = '', prefixlen='', mac=''):
        self.port_name = name
        self.gw_ip = ip
        self.gw_ipv6 = ipv6
        self.port_num = num
        self.prefixlen = prefixlen  
        self.mac = mac

    def __str__(self):
        return 'Gateway<name=%s,gw_ip=%s,gw_ipv6=%s,port_num=%s,prefixLen=%s,mac=%s>' % \
        (self.port_name, self.gw_ip, self.gw_ipv6, self.port_num, self.prefixlen, self.mac)
