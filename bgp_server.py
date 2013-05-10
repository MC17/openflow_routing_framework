#!/usr/bin/env python

import socket
import struct
from ryu.lib import hub
from ryu.lib.hub import StreamServer
from eventlet.queue import Queue
import eventlet
import contextlib
import greenlet
import traceback

from ryu.lib.packet import packet, ethernet

import BGP4
import convert
import route_entry


BGP_TCP_PORT = 179

BGP4_PACK_STR = BGP4.bgp4._PACK_STR
BGP4_HEADER_SIZE = BGP4.bgp4.BGP4_HEADER_SIZE


class Server(object):

    def __init__(self, handler, conn_num = 128, *args, **kwargs):
        super(Server, self).__init__()
        self.conn_num = conn_num
        self.handler = handler

    def __call__(self):
        self.server_loop()

    def server_loop(self):
        
        # line 70 in ryu.lib.hub.py is changed to self.server = eventlet.listen(*listen_info)
        #listen_info = (('', BGP_TCP_PORT), socket.AF_INET6, self.conn_num)
        server = StreamServer(('::', BGP_TCP_PORT), self.handler)

        print "Starting server..."
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
        self.send_q = Queue(1)

        # data structures for BGP
        self.peer_ip = None
        self.peer_as = None
        self.peer_id = None
        self.peer_capabilities = []
        self._4or6 = 0
        self.hold_time = 240
        self.route_table = []
    
    def close(self):
        print "close the connect from", self.address
        self.socket.close() 

    @_deactivate
    def _recv_loop(self):
        header_size = BGP4_HEADER_SIZE
        
        while self.is_active:
            buf = bytearray()     
            recv = self.socket.recv(header_size)
            if len(recv) == 0:
                self.is_active = False
                break
            
            buf += recv
            (marker, packet_len, msg_type) = struct.unpack(BGP4_PACK_STR,
                                                           buffer(buf))
            required_len = packet_len - header_size
            
            if required_len != 0:
                more_data = self.socket.recv(required_len)
                buf += more_data

            assert len(buf) == packet_len
            msg = BGP4.bgp4.parser(buffer(buf[0:packet_len]))
            self._handle(msg)
            eventlet.sleep(0)
                    
                

    def _handle(self, msg):
        msg_type = msg.type_
        if msg_type == BGP4.BGP4_OPEN:
            self._handle_open(msg.data)
            print 'receive OPEN msg'
        elif msg_type == BGP4.BGP4_UPDATE:
            print 'receive UPDATE msg'
            self._handle_update(msg.data) 
        elif msg_type == BGP4.BGP4_NOTIFICATION:            
            print 'receive NOTIFICATION msg'
            self._handle_notification(msg.data)            
        elif msg_type == BGP4.BGP4_KEEPALIVE:
            self._handle_keepalive(msg)
            print 'receive KEEPALIVE msg'
        else:
            print 'receive unknown msg_type', msg_type

    def __check_capabilities(self, peer_capabilities):
        """
            1) checks if some important capabilities are supported by peer
               return True if OK
            2) assigns self.capabilities, which is the actual capabilities
               used in this connection
        """
        # XXX
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

        print '4/6:', self._4or6
        print 'peer_as:', self.peer_as
        print 'hold_time:', self.hold_time
        print 'peer_id:', convert.ipv4_to_str(self.peer_id)
        print 'capability:', self.peer_capabilities

        # send OPEN to peer
        open_reply = BGP4.bgp4_open(version = 4,my_as = Server.local_as,
                            hold_time = self.hold_time,
                            bgp_identifier = Server.local_ip4,
                            data = Server.capabilities)
        bgp4_reply = BGP4.bgp4(type_ = BGP4.BGP4_OPEN, data = open_reply)
        p = packet.Packet()
        p.add_protocol(bgp4_reply)
        p.serialize()
        self.send(p.data)
        
        if self.__check_capabilities(self.peer_capabilities):
            self.send_keepalive_msg()
        else:
            self.send_notification_msg()
    

    def _handle_update(self, msg):
        
        print '----UPDATE----'
        no_nlri = True
        entries = []
        if msg.nlri:
            no_nlri = False
            for i in msg.nlri:
                entry = route_entry.BGPEntry(i.prefix, i.length, 4)
                entries.append(entry)
        
        attributes = route_entry.Attributes()
        for i in msg.path_attr:
            if i.code == BGP4.bgp4_update._ORIGIN:
                attributes.origin = i.value
            elif i.code == BGP4.bgp4_update._AS_PATH:
                for path in i.as_values:
                    if path == Server.local_as:
                        return
                attributes.as_path_type = i.as_type
                attributes.as_path = i.as_values
            elif i.code == BGP4.bgp4_update._NEXT_HOP:
                attributes.next_hop = i._next_hop
            elif i.code == BGP4.bgp4_update._MULTI_EXIT_DISC:
                attributes.multi_exit_disc = i.value
            elif i.code == BGP4.bgp4_update._MP_REACH_NLRI:
                _4or6 = 0
                if i.addr_family == BGP4.AFI_IPV4:
                    _4or6 = 4
                elif i.addr_family == BGP4.AFI_IPV6:
                    _4or6 = 6
                attributes.next_hop = i.next_hop
                

    def _handle_notification(self, msg):
        """
        send norification test

        no = BGP4.bgp4_notification(1,2,None)
        bgp = BGP4.bgp4(1, 46, BGP4.BGP4_NOTIFICATION, no)
        p = packet.Packet()
        p.add_protocol(bgp)
        p.serialize()
        self.send(p.data)
        """
        print 'error code,sub error code',msg.err_code,msg.err_subcode         

    def _handle_keepalive(self,msg):
        self.send_keepalive_msg()
        
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
        pass

    def send_keepalive_msg(self):
        keepalive = BGP4.bgp4(type_ = BGP4.BGP4_KEEPALIVE, data = None)
        p = packet.Packet()
        p.add_protocol(keepalive)
        p.serialize()
        self.send(p.data)

    def send_notification_msg(self):
        """
            input: err_code, err_subcode, and data 
            output: send msg
        """
        pass

    def send_current_route_table(self):
        """
            used after OPEN to send current route_table to peer
        """
        #send update for test

        print '---------start send update test'
        #path_attr
        origin_msg = BGP4.origin(0x40, BGP4.bgp4_update._ORIGIN, 1, 1)
        as_value = [100]
        as_path_msg = BGP4.as_path(0x40, BGP4.bgp4_update._AS_PATH,0,2,1,as_value)
        # as_path length will calculate auto in serialize  4B/per as
        next_hop_ip = '10.109.242.57'
        next_hop_msg = BGP4.next_hop(0x40, BGP4.bgp4_update._NEXT_HOP, 4, next_hop_ip)
        path_attr = [origin_msg, as_path_msg, next_hop_msg]

        # nlri 
        nlri = set()
        local_ip = (24,convert.ipv4_to_int('192.168.56.101')) # (prefix,ip)
        nlri.add(local_ip)

        update_reply = BGP4.bgp4_update(0, [], 0, path_attr, nlri) 
        # path_attr_len will calculate automatic in serialize 
        bgp4_reply = BGP4.bgp4(type_ = BGP4.BGP4_UPDATE, data = update_reply)
        p = packet.Packet()
        p.add_protocol(bgp4_reply)
        p.serialize()
        #self.send(p.data)

        print '---------send update test success'
        pass

    def send_update_msg(self):
        """
            convenient method to send update message
        """
        pass
