class RouteEntry(object):
    def __init__(self, ip, prefix_len, _4or6 = 4):
        super(RouteEntry, self).__init__()
        self._4or6 = _4or6
        self.ip = ip
        self.prefix_len = prefix_len
        self.nexthop_ip = None

    def __eq__(self, other):
        if not isinstance(other, RouteEntry):
            return False
        
        if self.prefix_len == other.prefix_len and \
           self.ip == other.ip and \
           self._4or6 == other._4or6:
            return True
        else:
            return False


class BGPEntry(RouteEntry):
    def __init__(self, ip, prefix_len, _4or6 = 4):
        super(BGPEntry, self).__init__(ip, prefix_len, _4or6)
        self.attributes = None 


class Attributes(object):
    def __init__(self):
        self.origin = None
        self.multi_exit_disc = None
        self.as_path_type = None
        self.as_path = None
        self.next_hop = None
