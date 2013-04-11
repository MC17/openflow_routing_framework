

class Gateway(object):
    # if add member ,should use lowercase
    def __init__(self, ip='', prefixlen=0, mac=''):
	self.gateway_ip = ip     # str
	self.prefixlen = prefixlen  # int
	self.mac = mac		    # str

    def __str__(self):
	return 'Gateway<gw_ip=%s,prefixLen=%s,mac=%s>' % \
	    (self.gateway_ip, self.prefixlen, self.mac)
