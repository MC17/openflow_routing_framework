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


BGP_TCP_PORT = 179  # 179

bgp4_PACK_STR = '!16sHB'
BGP4_HEADER_SIZE = struct.calcsize(bgp4_PACK_STR)


class Server(object):
    
    def __init__(self, conn_num, *args, **kwargs):
        super(Server, self).__init__()
        self.conn_num = conn_num

    def __call__(self):
        self.server_loop()

    def server_loop(self):

        pool = Pool(self.conn_num)
        server = StreamServer(('0.0.0.0', BGP_TCP_PORT), handler, spawn=pool)

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
        self.send_q = Queue()
    
    def close(self):
        print "close the connect from", self.address
        self.socket.close() 

    @_deactivate
    def _recv_loop(self):
        buf = bytearray()
        required_len = BGP4_HEADER_SIZE
        packet_len = 0 
        msg_type = 0
        
        #count = 0
        while self.is_active:
            ret = self.socket.recv(required_len)
            print 'receive socket data length',len(ret)
            if len(ret) == 0:
                self.is_active = False
                break
            buf += ret           
            
            while len(buf) >= required_len:
                if packet_len == 0:
                    (marker,length,type_) = struct.unpack('!16sHB',buffer(buf))
                    #print 'length is ',length
                    packet_len = length
                    msg_type = type_
                    required_len = length - required_len
                    break
                else:
                    msg = BGP4.bgp4.parser(buffer(buf[0:packet_len])) 
                    self._handle(msg)
                    buf = buf[packet_len:]
                    required_len = BGP4_HEADER_SIZE 
                    packet_len = 0
                    msg_type = 0
                    #count += 1
                    #if count > 20:
                    gevent.sleep(0)
                
                

    def _handle(self, msg):
        print 'call handle'
        msg_type = msg.type_
        if msg_type == BGP4.BGP4_OPEN:
            self._handle_open(msg)
        elif msg_type == BGP4.BGP4_UPDATE:
            print 'UPDATE msg' 
        elif msg_type == BGP4.BGP4_NOTIFICATION:
            print 'NOTIFICATION msg'            
        elif msg_type == BGP4.BGP4_KEEPALIVE:
            print 'KEEPALIVE msg'
        else:
            print 'else msg_type',msg_type

    def _handle_open(self,msg):

        #print type(msg),msg.__dict__,msg.data.__dict__
        
        #if self.send_thr != None:
        hdr = bytearray()
        cp_ad = []
        cp_ad.append(BGP4.multi_protocol_extension(1,4,1,0x00,1))
        cp_ad.append(BGP4.route_refresh(2,0))
        cp_ad.append(BGP4.support_4_octets_as_num(65,4,100))#as_num =100
        open_replay = BGP4.bgp4_open(4,100,240,'10.109.242.53',0,2,0,cp_ad)
        bgp4_replay = BGP4.bgp4(1,0,1,open_replay)       
        p = packet.Packet()
        p.add_protocol(bgp4_replay)        
        p.serialize()

        print bgp4_replay.marker
        print BGP4.bgp4.parser(buffer(p.data)).__dict__
        #print type(p.data)
        #self.send(p.data)
           
       
            
        
    @_deactivate
    def _send_loop(self):
        try:
            while self.is_active:
                buf = self.send_q.get()
                self.socket.sendall(buf)
        finally:
            self.send_q = None

    def send(self, buf):
        while self.send_q:
            self.send_q.put(buf)  

    def serve(self):
        send_thr = gevent.spawn(self._send_loop)
       
        try:
            self._recv_loop()
        finally:
            gevent.kill(send_thr)
            gevent.joinall([send_thr])
    
   

def handler(socket, address):
    print 'connect from ',address
    with contextlib.closing(Connection(socket, address)) as connection:
        try:
            connection.serve()
        except:
            print "Error in the connection from " ,address
            raise
        

if __name__ == '__main__':
    s = Server(10)
    g = Greenlet(s)
    g.start()
    g.join()


