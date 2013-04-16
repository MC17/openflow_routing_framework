import struct
from ryu.lib.packet import packet_base

BGP4_OPEN = 1
BGP4_UPDATE = 2
BGP4_NOTIFICATION = 3
BGP4_KEEPALIVE = 4
#BGP4_ROUTE_REFRESH = 5

class bgp4(packet_base.PacketBase):
  _PACK_STR = '!16sHB'
	_MIN_LEN = struct.calcsize(_PACK_STR)
	_BGP4_TYPES = {}

    #?????
	@staticmethod
    def register_bgp4_type(*args):
        def _register_bgp4_type(cls):
            for type_ in args:
                bgp4._BGP4_TYPES[type_] = cls
            return cls
        return _register_bgp4_type


    def __init__(self, marker,length, type_, data=None):
        super(bgp4, self).__init__()
        self.marker = marker
        self.length = length
        self.type_ = type_        
        self.data = data

    @classmethod
    def parser(cls, buf):
        (marker_, length, type_) = struct.unpack_from(cls._PACK_STR, buf)
        marker = (struct.unpack_from('!4I',marker_)[0])&0x1
        msg = cls(marker, length, type_)
        offset = cls._MIN_LEN
        if len(buf) > offset:
            cls_ = cls._BGP4_TYPES.get(type_, None)
            if cls_:
                msg.data = cls_.parser(buf, offset)
            else:
                msg.data = buf[offset:]

        return msg, None

    def serialize(self, payload, prev):
        marker_ = None
        if self.marker == 1:
            marker_ = struct.pack('!4I',*[(self.marker)<<32-1]*4)
        elif self.marker == 0:
            marker_ = struct.pack('!4I',*[self.marker]*4) 

        if marker_:   
            hdr = bytearray(struct.pack(BGP4._PACK_STR,marker_,self.length, self.type_))            
            if self.data is not None:
                if self.type_ in bgp4._BGP4_TYPES:
                    hdr += self.data.serialize()
                else:
                    hdr += bytearray(self.data)

            if self.length == 0:
                self.length = len(hdr)
                struct.pack_into('!H', hdr, 16, self.length)
            return hdr

@bgp4.register_bgp4_type(BGP4_OPEN)
class bgp4_open(object):
    _PACK_STR = '!BHHIB'
    _MIN_LEN = struct.calcsize(_PACK_STR)  
   
    _CAPABILITY_ADVERTISEMENT = {}


    #_CAPABILITY_ADVERTISEMENT = 2
    _CAPABILITY_ADVERTISEMENT_MPE = 1

    @staticmethod
    def register_capability_advertisement_type(*args):
        def _register_capability_advertisement_type(cls):
            for type_ in args:
                bgp4_open._CAPABILITY_ADVERTISEMENT[type_] = cls
            return cls
        return _register_capability_advertisement_type
	
    #using capabilities adverstisement in it's optional parameters' field,so type_ is 2
    def __init__(self, version, my_as, hold_time, bgp_identifier,opt_para_len = 0,type_ = 2, para_len = 0, data = []):
        self.version = version
        self.my_as = my_as
        self.hold_time = hold_time
        self.bgp_identifier = bgp_identifier
        self.opt_para_len = opt_para_len        
        self.type_ = type_
        self.para_len = para_len
        self.data = data

    @classmethod
    def parser(cls, buf, offset):
        (version, my_as, hold_time, bgp_identifier, opt_para_len) = struct.unpack_from(cls._PACK_STR, buf, offset)
        offset += cls._MIN_LEN        

        if opt_para_len >= 2:
            (type_,para_len) = struct.unpack_from('!BB',buf,offset)
            offset += 2
            msg = cls(version, my_as, hold_time, bgp_identifier, opt_para_len, type_,para_len)
        else:
            msg = cls(version, my_as, hold_time, bgp_identifier, opt_para_len)
       
        msg.data = []
        if len(buf) > offset:
            #capability advertisement  
            length = msg.opt_para_len - 2      
            while length >= 2:
                    code,len_ = struct.unpack_from('!BB')
                    offset += 2
                    length -= 2
                    cls_ = cls._CAPABILITY_ADVERTISEMENT.get(code, None)            
                    if cls_ and len_ != 0:
                        msg.data.append(cls_.parser(buf, offset))
                        offset += len_
                        length -= len_                 

        return msg
    
    def serialize(self):
        self.opt_para_len = 0 
        hdr = bytearray(struct.pack(bgp4_open._PACK_STR, self.version, self.my_as, self.hold_time, 
            self.bgp_identifier, self.opt_para_len)) 

        if self.data != []:            
            hdr +=  bytearray(struct.pack('!BB', self.type_, self.para_len)) 
            for para in self.data:
                
                #hdr += bytearray(struct.pack('!BB', para.code, para.length))
                cls_ = cls._CAPABILITY_ADVERTISEMENT.get(para.code, None)
                if cls_:
                    hdr += cls_.serialize()              
                    self.para_len += para.length + 2

        self.opt_para_len = self.para_len + 2 
        struct.pack_into('!B', hdr, 9, self.opt_para_len)
        struct.pack_into('!B', hdr, 11, self.para_len)
        return hdr

@register_capability_advertisement_type(bgp4_open._CAPABILITY_ADVERTISEMENT_MPE) 
capability_advertisement_multi_protocol_extentions(object)
    _PACK_STR = '!HBB'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self,addr_family, res = 0x00,sub_addr_family):
        self.code = bgp4_open._CAPABILITY_ADVERTISEMENT_MPE
        self.length = self._MIN_LEN
        self.addr_family = addr_family
        self.res = res
        self.sub_addr_family = sub_addr_family 

    @classmethod
    def parser(cls, buf, offset):
        (addr_family,res,sub_addr_family) = struct.unpack_from(cls._PACK_STR, buf, offset)
        msg = cls(,addr_family,res,addr_family)
        offset += cls._MIN_LEN 
        return msg

    def serialize(self):
        hdr = bytearray(struct.pack('!BB', self.code, self.length))
        hdr += bytearray(struct.pack(self._PACK_STR, self.hw_src, self.res, self.sub_addr_family))
        return hdr
    
@bgp4.register_bgp4_type(BGP4_UPDATE)
class bgp4_update(object):

    #_PACK_STR = '!HH'
    #_MIN_LEN = struct.calcsize(_PACK_STR)  

    # we only consider BGP+ 
    #path_attr is a list of dicts {}
    def __init__(self, wd_rout_len = 0, wd_rout = [], path_attr_len = 0, path_attr = [], nlri = []):
        self.wd_rout_len = wd_rout_len
        self.wd_rout = wd_rout
        self.path_attr_len = path_attr_len
        self.path_attr = path_attr
        self.nlri = nlri  

    def serialize(self):
        if path_attr != []:
            for attr in path_attr:
       
   

@bgp4.register_bgp4_type(BGP4_NOTIFICATION)
class bgp4_notification(object):
	pass

@bgp4.register_bgp4_type(BGP4_KEEPALIVE)
class bgp4_keepalive(object):
	pass
