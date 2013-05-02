#!/usr/bin/env python

import gevent
import struct
from gevent.server import StreamServer
from gevent.pool import Pool
from gevent.queue import Queue
from gevent import Greenlet
import contextlib
import greenlet
import traceback

from ryu.lib.packet import packet, ethernet

import BGP4
import convert


BGP_TCP_PORT = 179  # 179

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

        pool = Pool(self.conn_num)
        server = StreamServer(('0.0.0.0', BGP_TCP_PORT), self.handler, spawn=pool)

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
        #self.send_thr = None

        # The limit is arbitrary. We need to limit queue size to
        # prevent it from eating memory up
        self.send_q = Queue(1)
    
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
            gevent.sleep(0)
                    
                

    def _handle(self, msg):
        msg_type = msg.type_
        if msg_type == BGP4.BGP4_OPEN:
            self._handle_open(msg)
            print 'receive OPEN msg'
        elif msg_type == BGP4.BGP4_UPDATE:
            print 'receive UPDATE msg'
            self._handle_update(msg) 
        elif msg_type == BGP4.BGP4_NOTIFICATION:            
            print 'receive NOTIFICATION msg'
            self._handle_notification(msg)            
        elif msg_type == BGP4.BGP4_KEEPALIVE:
            self._handle_keepalive(msg)
            print 'receive KEEPALIVE msg'
        else:
            print 'receive else msg_type',msg_type

    def _handle_open(self,msg):

        #print type(msg),msg.__dict__,msg.data.__dict__

        
        #if self.send_thr != None:
        hdr = bytearray()
        cp_ad = []
        cp_ad.append(BGP4.multi_protocol_extension(1,4,1,0x00,1))
        cp_ad.append(BGP4.route_refresh(2,0))
        cp_ad.append(BGP4.support_4_octets_as_num(65,4,64496))#as_num =100
        open_reply = BGP4.bgp4_open(4,64496,240,'10.109.242.118',0,2,0,cp_ad)
        bgp4_reply = BGP4.bgp4(1,0,1,open_reply)       
        p = packet.Packet()
        p.add_protocol(bgp4_reply)        
        p.serialize()

        #print bgp4_reply.marker
        #print BGP4.bgp4.parser(buffer(p.data)).__dict__
        #print type(p.data)
        self.send(p.data)
        #print 'send open reply success!'
        keepalive = BGP4.bgp4(1,0,4,None)
        p = packet.Packet()
        p.add_protocol(keepalive)
        p.serialize()
        self.send(p.data)
    

    def _handle_update(self, msg):

        
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
        bgp4_reply = BGP4.bgp4(1, 46,BGP4.BGP4_UPDATE, update_reply)
        p = packet.Packet()
        p.add_protocol(bgp4_reply)
        p.serialize()
        self.send(p.data)

        print '---------send update test success'
        
        

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
        no = msg.data
        print 'error code,sub error code',no.err_code,no.err_subcode         

    def _handle_keepalive(self,msg):
        bgp4_reply = BGP4.bgp4(1,0,4,None)
        p = packet.Packet()
        p.add_protocol(bgp4_reply)        
        p.serialize()
        self.send(p.data)

        
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
        send_thr = gevent.spawn(self._send_loop)
       
        try:
            self._recv_loop()
        finally:
            gevent.kill(send_thr)
            gevent.joinall([send_thr])

    #
    #  Utility methods for convenience
    #  
    
    def send_open_msg(self):
        pass
        

if __name__ == '__main__':
    s = Server(10)
    g = Greenlet(s)
    g.start()
    g.join()
