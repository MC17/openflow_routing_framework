import contextlib

from ryu.base import app_manager
from ryu.lib import hub
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import (HANDSHAKE_DISPATCHER, MAIN_DISPATCHER,
                                    CONFIG_DISPATCHER, DEAD_DISPATCHER)

import dest_event
import convert
from bgp_server import Server, Connection
import BGP4


class BGPer(app_manager.RyuApp):
    """
        the BGP part of this project(aka. "B")
    """
    peers = {}

    def __init__(self, *args, **kwargs):
        super(BGPer, self).__init__(*args, **kwargs)
        self.name = 'bgper'

        # XXX should read from config file
        Server.local_ip = '10.109.242.118'
        Server.local_as = 64496
        Server.capabilities = []
        Server.capabilities.append(BGP4.multi_protocol_extension(code = 1,
                            length = 4, addr_family = 1,res = 0x00,
                            sub_addr_family = 1))
        Server.capabilities.append(BGP4.multi_protocol_extension(code = 1,
                            length = 4, addr_family = 2,res = 0x00,
                            sub_addr_family = 1))
        Server.capabilities.append(BGP4.route_refresh(2,0))
        Server.capabilities.append(BGP4.support_4_octets_as_num(65,4,
                                                        Server.local_as))

        server = Server(handler)
        g = hub.spawn(server)
        hub.spawn(self._test)
        g.wait()

    def _test(self):
        while True:
            print 'looping...'
            for k,v in BGPer.peers.iteritems():
                print k, v

            hub.sleep(3)

    @set_ev_cls(dest_event.EventDestinationRequest)
    def destination_request_handler(self, event):
        # for test only by now
        if event._4or6 == 4:
            print 'dst address:', convert.ipv4_to_str(event.dest_addr)
        else:
            print 'dst address:', convert.bin_to_ipv6(event.dest_addr)
        reply = dest_event.EventDestinationReply(dpid = 0x0)
        self.reply_to_request(event, reply)


def handler(socket, address):
    print 'connect from ', address
    with contextlib.closing(Connection(socket, address)) as connection:
        try:
            BGPer.peers[address] = connection
            connection.serve()
        except:
            print "Error in the connection from ", address
            raise
        finally:
            del BGPer.peers[address]
