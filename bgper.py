import contextlib
import netaddr
import logging

from ryu.base import app_manager
from ryu.lib import hub
from ryu.controller.handler import set_ev_cls

import dest_event
from bgp_server import Server, Connection
import BGP4
import util
import tap


LOG = logging.getLogger(__name__)

def address_match_entry(dest_addr, route_entry):
    dest_addr = netaddr.IPAddress(dest_addr)
    network = netaddr.IPNetwork(route_entry.ip)
    return dest_addr in network


class BGPer(app_manager.RyuApp):
    """
        the BGP part of this project(aka. "B")
    """
    peers = {}

    def __init__(self, *args, **kwargs):
        super(BGPer, self).__init__(*args, **kwargs)
        self.name = 'bgper'

        if util.bgper_config is None:
            try:
                util.bgper_config = util.read_bgp_config(util.BGPER_CONFIG_PATH)
                LOG.info('bgper_config: %s', util.bgper_config)
            except:
                LOG.error('File %s parse error', util.bgper_config)

        local_ipv4 = util.bgper_config.get('local_ipv4')
        ipv4_prefix_len = util.bgper_config.get('ipv4_prefix_len')
        local_ipv6 = util.bgper_config.get('local_ipv6')
        ipv6_prefix_len = util.bgper_config.get('ipv6_prefix_len')

        if tap.device is None:
            tap.device = tap.TapDevice()
        tap.device.setIPv4Address(local_ipv4, ipv4_prefix_len)
        tap.device.setIPv6Address(local_ipv6, ipv6_prefix_len)

        Server.local_ipv4 = local_ipv4
        Server.local_ipv6 = local_ipv6
        Server.local_as = int(util.bgper_config.get('local_as'))
        Server.capabilities = []
        Server.capabilities.append(BGP4.multi_protocol_extension(code = 1,
                                length = 4, addr_family = 1, res = 0x00,
                                sub_addr_family = 1))
        Server.capabilities.append(BGP4.multi_protocol_extension(code = 1,
                                length = 4, addr_family = 2, res = 0x00,
                                sub_addr_family = 1))
        Server.capabilities.append(BGP4.route_refresh(2, 0))
        Server.capabilities.append(BGP4.support_4_octets_as_num(65, 4,
                                                        Server.local_as))

        Server.route_table = []

        server = Server(handler)
        g = hub.spawn(server)
        #hub.spawn(self._test)

    def _test(self):
        while True:
            print 'looping...'
            #for k,v in BGPer.peers.iteritems():
            #    print k, v
            for i in Server.route_table:
                print i._4or6
                print i.ip
                print i.attributes.as_path

            hub.sleep(3)

    @set_ev_cls(dest_event.EventDestinationRequest)
    def destination_request_handler(self, event):
        LOG.debug('Get EventDestinationRequest for dest addr %s',
                  event.dest_addr)

        longest_match = None
        for entry in Server.route_table:
            if event._4or6 == entry._4or6:
                if address_match_entry(event.dest_addr, entry):
                    if longest_match is None or \
                            entry.prefix_len > longest_match.prefix_len:
                        longest_match = entry

        if longest_match:
            address = longest_match.announcer
            neighbors = util.bgper_config.get('neighbor')
            for neighbor in neighbors:
                if netaddr.IPAddress(neighbor['neighbor_ipv4']) == address or \
                   netaddr.IPAddress(neighbor['neighbor_ipv6']) == address:
                    name = neighbor['border_switch']
                    outport = int(neighbor['outport_no'])
                    reply = dest_event.EventDestinationReply(switch_name=name,
                                                             outport_no=outport,
                                                             neighbor_ip=address)
                    break
        else:
            reply = dest_event.EventDestinationReply()

        self.reply_to_request(event, reply)


def handler(socket, address):
    LOG.info('BGP server got connection from %s', address)
    with contextlib.closing(Connection(socket, address)) as connection:
        try:
            BGPer.peers[address] = connection
            connection.serve()
        except:
            LOG.error('Error in connection with %s', address)
            raise
        finally:
            del BGPer.peers[address]
