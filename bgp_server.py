#!/usr/bin/env python

import struct
import netaddr
from ryu.lib import hub
from ryu.lib.hub import StreamServer
from eventlet.queue import Queue
import eventlet
import greenlet
import traceback
import logging

from ryu.lib.packet import packet
import time

import BGP4
import route_entry

LOG = logging.getLogger(__name__)

BGP_TCP_PORT = 179

BGP4_PACK_STR = BGP4.bgp4._PACK_STR
BGP4_HEADER_SIZE = BGP4.bgp4.BGP4_HEADER_SIZE


class Server(object):
    def __init__(self, handler, conn_num=128, *args, **kwargs):
        super(Server, self).__init__()
        self.conn_num = conn_num
        self.handler = handler

    def __call__(self):
        self.server_loop()

    def server_loop(self):
        server = StreamServer(('::', BGP_TCP_PORT), self.handler)

        LOG.info('BGP server starting...')
        server.serve_forever()


def _deactivate(method):
    def deactivate(self):
        try:
            method(self)
        except greenlet.GreenletExit:
            pass
        except:
            traceback.print_exc()
            raise
        finally:
            self.is_active = False

    return deactivate


class Connection(object):
    def __init__(self, socket, address):
        super(Connection, self).__init__()

        self.socket = socket
        self.address = address
        self.is_active = True

        # The limit is arbitrary. We need to limit queue size to
        # prevent it from eating memory up
        self.send_q = Queue(128)

        # data structures for BGP
        self.peer_ip = None
        self.peer_as = None
        self.peer_id = None
        self.peer_capabilities = []
        self.peer_last_keepalive_timestamp = None
        self._4or6 = 0
        self.hold_time = 240

    def close(self):
        LOG.info('Connection %s closing...', self.address)
        self.socket.close()

    @_deactivate
    def _recv_loop(self):
        header_size = BGP4_HEADER_SIZE

        while self.is_active:
            buf = bytearray()
            receive = self._exact_receive(header_size)
            if receive != '':
                buf.extend(receive)
            else:
                break

            (marker, packet_len, msg_type) = struct.unpack(BGP4_PACK_STR,
                                                           buffer(buf))
            required_len = packet_len - header_size
            if required_len:
                # notification message has only a header
                receive = self._exact_receive(required_len)
                if receive != '':
                    buf.extend(receive)
                else:
                    break

            msg = BGP4.bgp4.parser(buffer(buf[0:packet_len]))
            self._handle(msg)
            eventlet.sleep(0)

    def _exact_receive(self, required_len):
        """
            receive exact size of data from socket
            returns empty string if socket closed/error
        """
        buf = bytearray()
        while len(buf) < required_len:
            more_data = self.socket.recv(required_len - len(buf))
            if len(more_data) != 0:
                buf.extend(more_data)
            else:
                self.is_active = False
                return ''
        return buf

    def _handle(self, msg):
        msg_type = msg.type_
        if msg_type == BGP4.BGP4_OPEN:
            self._handle_open(msg.data)
            LOG.debug('Receive OPEN msg')
        elif msg_type == BGP4.BGP4_UPDATE:
            LOG.debug('Receive UPDATE msg')
            self._handle_update(msg.data)
        elif msg_type == BGP4.BGP4_NOTIFICATION:
            LOG.debug('Receive NOTIFICATION msg')
            self._handle_notification(msg.data)
        elif msg_type == BGP4.BGP4_KEEPALIVE:
            self._handle_keepalive(msg)
            LOG.debug('Receive KEEPALIVE msg')
        else:
            LOG.debug('Receive unknown msg_type %s', msg_type)

    def __check_capabilities(self, peer_capabilities):
        """
            ideally,
            1) checks if some important capabilities are supported by peer
               return True if OK
            2) assigns self.capabilities, which is the actual capabilities
               used in this connection
        """
        for self_capabilities in Server.capabilities:
            if self_capabilities not in peer_capabilities:
                return False
        return True

    def _handle_open(self, msg):

        self.peer_as = msg.my_as
        peer_holdtime = msg.hold_time
        self.hold_time = min(peer_holdtime, self.hold_time)
        self.peer_id = msg.bgp_identifier
        self.peer_capabilities = msg.data
        for capability in self.peer_capabilities:
            if isinstance(capability, BGP4.multi_protocol_extension):
                if capability.addr_family == 1:
                    self._4or6 = 4
                elif capability.addr_family == 2:
                    self._4or6 = 6
                else:
                    self._4or6 = 0
            if isinstance(capability, BGP4.support_4_octets_as_num):
                self.peer_as = capability.as_num

        LOG.info('BGP peer info. 4/6: %s, AS %s, hold time %s, ID %s, capability %s',
                 self._4or6, self.peer_as, self.hold_time, self.peer_id,
                 self.peer_capabilities)

        self.send_open_msg()

        if self.__check_capabilities(self.peer_capabilities):
            self.peer_last_keepalive_timestamp = time.time()
            hub.spawn(self.keepalive)
            self.send_current_route_table()
        else:
            self.send_notification_msg()

    def keepalive(self):
        while True:
            self.send_keepalive_msg()
            current_time = time.time()
            if current_time - self.peer_last_keepalive_timestamp > \
               self.hold_time:
                self.send_notification_msg(err_code=4, err_subcode=0, data="Hold timer expired")
                self.is_active = False
            hub.sleep(self.hold_time / 3)

    def __check_AFI(self, afi):
        if afi == BGP4.AFI_IPV4:
            return 4
        elif afi == BGP4.AFI_IPV6:
            return 6
        else:
            return None

    def _handle_update(self, msg):
        LOG.debug('Handling UPDATE msg')

        advert_entries = []
        withdraw_entries = []

        if msg.wd_routes:
            for i in msg.wd_routes:
                entry = route_entry.BGPEntry(i.network, i.length, 4)
                entry.announcer = netaddr.IPAddress(self.address)
                withdraw_entries.append(entry)

        if msg.nlri:
            for i in msg.nlri:
                entry = route_entry.BGPEntry(i.network, i.length, 4)
                entry.announcer = netaddr.IPAddress(self.address)
                advert_entries.append(entry)

        attributes = route_entry.Attributes()
        for i in msg.path_attr:
            if i.code == BGP4.bgp4_update._ORIGIN:
                attributes.origin = i.value
            elif i.code == BGP4.bgp4_update._AS_PATH:
                if Server.local_as in i.as_values:
                    return
                attributes.as_path_type = i.as_type
                attributes.as_path = i.as_values
            elif i.code == BGP4.bgp4_update._NEXT_HOP:
                attributes.next_hop = i._next_hop
            elif i.code == BGP4.bgp4_update._MULTI_EXIT_DISC:
                attributes.multi_exit_disc = i.value
            elif i.code == BGP4.bgp4_update._MP_REACH_NLRI:
                _4or6 = self.__check_AFI(i.addr_family)
                attributes.next_hop = i.next_hop
                if i.nlri:
                    for j in i.nlri:
                        entry = route_entry.BGPEntry(j.network, j.length, _4or6)
                        entry.announcer = netaddr.IPAddress(self.address)
                        advert_entries.append(entry)
            elif i.code == BGP4.bgp4_update._MP_UNREACH_NLRI:
                _4or6 = self.__check_AFI(i.addr_family)
                if i.wd_routes:
                    for j in i.wd_routes:
                        entry = route_entry.BGPEntry(j.network, j.length, _4or6)
                        entry.announcer = netaddr.IPAddress(self.address)
                        withdraw_entries.append(entry)
        self.__add_route(advert_entries, attributes)
        self.__remove_route(withdraw_entries)

    def __add_route(self, advert_entries, attributes):
        # XXX acquire route table lock?
        # XXX remove duplicate
        for entry in advert_entries:
            entry.attributes = attributes
            Server.route_table.append(entry)

    def __remove_route(self, withdraw_entries):
        # XXX acquire route table lock?
        for i in withdraw_entries:
            for j in Server.route_table:
                if i == j:
                    Server.route_table.remove(j)

    def _handle_notification(self, msg):
        LOG.error('BGP error code %s, error sub code %s',
                  msg.err_code, msg.err_subcode)

    def _handle_keepalive(self, msg):
        self.peer_last_keepalive_timestamp = time.time()

    @_deactivate
    def _send_loop(self):
        try:
            while self.is_active:
                buf = self.send_q.get()
                self.socket.sendall(buf)
        finally:
            self.send_q = None

    def send(self, buf):
        if self.send_q:
            self.send_q.put(buf)

    def serve(self):
        send_thr = hub.spawn(self._send_loop)

        try:
            self._recv_loop()
        finally:
            hub.kill(send_thr)
            hub.joinall([send_thr])

    #
    #  Utility methods for convenience
    #  

    def send_open_msg(self):
        open_reply = BGP4.bgp4_open(version=4, my_as=Server.local_as,
                                    hold_time=self.hold_time,
                                    bgp_identifier=Server.local_ipv4,
                                    data=Server.capabilities)
        bgp4_reply = BGP4.bgp4(type_=BGP4.BGP4_OPEN, data=open_reply)
        self.serialize_and_send(bgp4_reply)

    def send_keepalive_msg(self):
        keepalive = BGP4.bgp4(type_=BGP4.BGP4_KEEPALIVE, data=None)
        self.serialize_and_send(keepalive)

    def send_notification_msg(self, err_code, err_subcode, data):
        """
            input: err_code, err_subcode, and data 
            output: send msg
        """
        notification_msg = BGP4.bgp4_notification(err_code, err_subcode, data)
        bgp_msg = BGP4.bgp4(type_=BGP4.BGP4_NOTIFICATION, data=notification_msg)
        self.serialize_and_send(bgp_msg)

    def serialize_and_send(self, protocol_data):
        p = packet.Packet()
        p.add_protocol(protocol_data)
        p.serialize()
        self.send(p.data)

    def send_current_route_table(self):
        """
            used after OPEN to send current route_table to peer
        """
        LOG.info('Sending local route table...')
        for i in Server.route_table:
            self.send_update_msg(i)

    def send_update_msg(self, entry):
        """
            convenient method to send update message
            input is a BGPEntry object
        """
        path_attr = []
        # 0 is a valid origin number, compare with None
        if entry.attributes.origin is not None:
            origin_msg = BGP4.origin(value=entry.attributes.origin)
            path_attr.append(origin_msg)
        if entry.attributes.multi_exit_disc:
            multi_exit_disc_msg = BGP4.multi_exit_disc(value= \
                                            entry.attributes.multi_exit_disc)
            path_attr.append(multi_exit_disc_msg)
        if entry.attributes.as_path:
            # information stored in as_path is the original got from
            # peer's update messages, so when sending to others, we should
            # insert server's AS number
            as_path_msg = BGP4.as_path(as_type=entry.attributes.as_path_type,
                                       as_len=len(entry.attributes.as_path)+1,
                                       as_values=[Server.local_as] + \
                                                 entry.attributes.as_path)
            path_attr.append(as_path_msg)
        # nlri
        if entry._4or6 == 4:
            nlri = [BGP4.NLRI(entry.prefix_len, entry.ip, entry._4or6)]
            if entry.attributes.next_hop:
                next_hop_msg = BGP4.next_hop(_next_hop= \
                                                 entry.attributes.next_hop)
                path_attr.append(next_hop_msg)
        elif entry._4or6 == 6:
            nlri = []
            nlri_in_mp_reach = [BGP4.NLRI(entry.prefix_len, entry.ip, entry._4or6)]
            mp_reach_nlri_msg = BGP4.mp_reach_nlri(next_hop_len= \
                                                   16 * len(entry.attributes.next_hop),
                                                   next_hop=entry.attributes.next_hop,
                                                   nlri=nlri_in_mp_reach)
            path_attr.append(mp_reach_nlri_msg)

        update_msg = BGP4.bgp4_update(path_attr=path_attr,
                                      nlri=nlri)
        bgp4_msg = BGP4.bgp4(type_=BGP4.BGP4_UPDATE, data=update_msg)
        self.serialize_and_send(bgp4_msg)
