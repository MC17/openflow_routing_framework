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
from util import read_bgp_config


class BGPer(app_manager.RyuApp):
    """
        the BGP part of this project(aka. "B")
    """
    peers = {}

    def __init__(self, *args, **kwargs):
        super(BGPer, self).__init__(*args, **kwargs)
        self.name = 'bgper'

        self.filepath = 'bgper.config'
        self.bgp_cfg = None
        try:
            self.bgp_cfg = read_bgp_config(self.filepath)
            #print self.bgp_cfg
        except:
            print "File %s Parse Error" % self.filepath

        Server.local_ip4 = self.bgp_cfg.get('local_ip4')
        Server.local_ip6 = self.bgp_cfg.get('local_ip6')
        Server.local_as = int(self.bgp_cfg.get('local_as'))
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

        Server.route_table = set()

        server = Server(handler)
        g = hub.spawn(server)
        hub.spawn(self._test)
        g.wait()

    def _test(self):
        while True:
            print 'looping...'
            #for k,v in BGPer.peers.iteritems():
            #    print k, v
            for i in Server.route_table:
                print i._4or6
                print convert.bin_to_ipv4(i.ip) if i._4or6 == 4 else \
                        convert.bin_to_ipv6(i.ip)
                print i.attributes.as_path

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
