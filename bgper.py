from ryu.base import app_manager
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import (HANDSHAKE_DISPATCHER, MAIN_DISPATCHER,
                                    CONFIG_DISPATCHER, DEAD_DISPATCHER)

import dest_event
import convert


class BGPer(app_manager.RyuApp):
    '''
        the BGP part of this project(aka. "B")
    '''
    def __init__(self, *args, **kwargs):
        super(BGPer, self).__init__(*args, **kwargs)
        self.name = 'bgper'


    @set_ev_cls(dest_event.EventDestinationRequest)
    def destination_request_handler(self, event):
        # for test only by now
        if event._4or6 == 4:
            print 'dst address:', convert.ipv4_to_str(event.dest_addr)
        else:
            print 'dst address:', convert.bin_to_ipv6(event.dest_addr)
        reply = dest_event.EventDestinationReply(dpid = 0x0)
        self.reply_to_request(event, reply)
