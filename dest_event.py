from ryu.controller import event


class EventDestinationRequest(event.EventRequestBase):
    '''
        request for the border switch by destination address
    '''
    def __init__(self, dest_addr = None, _4or6 = 4):
        super(EventDestinationRequest, self).__init__()
        self.dst = 'bgper'
        # dest_addr should be in binary form
        self.dest_addr = dest_addr
        self._4or6 = _4or6


class EventDestinationReply(event.EventReplyBase):
    def __init__(self, dpid = None, switch_name = None, dest = None):
        # 'dest' here is the event consumer, required by Ryu,
        # no need to set this parameter when init
        super(EventDestinationReply, self).__init__(dest)
        self.dpid = dpid
        self.switch_name = switch_name
