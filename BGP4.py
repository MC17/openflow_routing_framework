import struct
from ryu.lib.packet import packet_base

BGP4_OPEN = 1
BGP4_UPDATE = 2
BGP4_NOTIFICATION = 3
#BGP4_KEEPALIVE = 4 keepalive message only contain a header  
#BGP4_ROUTE_REFRESH = 5

class bgp4(packet_base.PacketBase):

    _PACK_STR = '!16sHB'
    _MIN_LEN = struct.calcsize(_PACK_STR)
    _BGP4_TYPES = {}
    
    @staticmethod
    def register_bgp4_type(*args):        
        def _register_bgp4_type(cls):
            for type_ in args:
                bgp4._BGP4_TYPES[type_] = cls
            return cls
        return _register_bgp4_type        

    def __init__(self, marker, length, type_, data=None):
        #length default value is 0
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
    _CAPABILITY_ADVERTISEMENT_ROUTE_REFRESH = 2


    @staticmethod
    def register_capability_advertisement_type(*args):
        def _register_capability_advertisement_type(cls):
            for type_ in args:
                bgp4_open._CAPABILITY_ADVERTISEMENT[type_] = cls
            return cls
        return _register_capability_advertisement_type
    
     #using capabilities adverstisement in it's optional parameters' field
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
            #capability advertisement  2
            length = msg.opt_para_len - 2      
            while length >= 2:
                    code,len_ = struct.unpack_from('!BB')
                    cls_ = cls._CAPABILITY_ADVERTISEMENT.get(code, None)            
                    if cls_:
                        msg.data.append(cls_.parser(buf, offset))
                    length -= (len_ + 2)              

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
                    self.para_len += cls_._MIN_LEN

        self.opt_para_len = self.para_len + 2
        struct.pack_into('!B', hdr, 9, self.opt_para_len)
        struct.pack_into('!B', hdr, 11, self.para_len)
        return hdr

@bgp4_open.register_capability_advertisement_type(bgp4_open._CAPABILITY_ADVERTISEMENT_MPE)
class capability_advertisement_multi_protocal_extentions(object):

    _PACK_STR = '!BBHBB'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, addr_family, res, sub_addr_family):
        #res = 0x00
        self.code = bgp4_open._CAPABILITY_ADVERTISEMENT_MPE
        self.length = self._MIN_LEN
        self.addr_family = addr_family
        self.res = res
        self.sub_addr_family = sub_addr_family 

    @classmethod
    def parser(cls, buf, offset):
        (code, length, addr_family, res, sub_addr_family) = struct.unpack_from(cls._PACK_STR, buf, offset)
        msg = cls(code, length, addr_family, res, addr_family)
        #offset has no meaning here ?
        offset += cls._MIN_LEN 
        return msg

    def serialize(self):
        hdr = bytearray(struct.pack(self._PACK_STR, self.code, self.length, self.hw_src, self.res, self.sub_addr_family))
        return hdr

@bgp4_open.register_capability_advertisement_type(bgp4_open._CAPABILITY_ADVERTISEMENT_ROUTE_REFRESH) 
class capability_advertisement_route_refresh(object):

    _PACK_STR = '!BB'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self):
        self.code = bgp4_open._CAPABILITY_ADVERTISEMENT_ROUTE_REFRESH
        self.length = 0
        
    @classmethod
    def parser(cls, buf, offset):
        (code, length) = struct.unpack_from(cls._PACK_STR, buf, offset)
        msg = cls(code, length)
        offset += cls._MIN_LEN 
        return msg

    def serialize(self):
        hdr = bytearray(struct.pack(self._PACK_STR, self.code, self.length))
        return hdr

@bgp4.register_bgp4_type(BGP4_UPDATE)
class bgp4_update(object):

    _PACK_STR = '!HH'
    _MIN_LEN = struct.calcsize(_PACK_STR) 
    _PATH_ATTRIBUTES = {}

    _ORIGIN = 1
    _AS_PATH = 2
    _MULTI_EXIT_DISK = 4
    _MP_REACH_NLRI = 14
    _MP_UNREACH_NLRI = 15

    @staticmethod
    def register_path_attributes_type(*args):
        def _register_path_attributes_type(cls):
            for type_ in args:
                bgp4_update._PATH_ATTRIBUTES[type_] = cls
            return cls
        return _register_path_attributes_type

    # we only consider BGP+,wd_rout may be replaced by MP_UNREACH_NLRI in path_attr,and the same to nlri
    
    def __init__(self, wd_rout_len = 0, wd_rout = [], path_attr_len = 0, path_attr = [], nlri = []):
        self.wd_rout_len = wd_rout_len
        self.wd_rout = wd_rout
        self.path_attr_len = path_attr_len
        self.path_attr = path_attr
        self.nlri = nlri  
        
    def parser(cls, buf, offset):
        (wd_rout_len,path_attr_len) = struct.unpack_from(cls._PACK_STR, buf, offset)
        offset += 4
        msg = cls(wd_rout_len, [], path_attr_len,[], [])
        len_ = path_attr_len
        #msg = cls(,addr_family,res,addr_family)
        while len_ > 0:
            (flag,code) = struct.unpack_from('!BB',buf,offset)
            cls_ = cls._PATH_ATTRIBUTES.get(code,None)
            if cls_:
                msg.path_attr.append(cls_.parser(buf, offset))
                len_ -= cls_._MIN_LEN
                offset += cls_._MIN_LEN
                if cls_.__dict__.has_key('length'):
                    len_ -= cls_.length
                    offset += cls_.length
            else:
                pass
        return msg
    

    def serialize(self):
        #serialise wd_route_len and path_attr_len first
        hdr = bytearray(struct.pack( self._PACK_STR, self.wd_rout_len, self.path_attr_len))
        if path_attr != []:
            for attr in path_attr:
                cls = self._PATH_ATTRIBUTES.get(attr.type_,None)
                if cls: 
                    hdr += cls.serialize()
                    self.path_attr_len += cls._MIN_LEN
                    if cls.__dict__.has_key('length'):
                        self.path_attr_len += cls.length

            struct.pack_into('!H', hdr, 2, self.path_attr_len)

        return hdr
       
@bgp4_update.register_path_attributes_type(bgp4_update._ORIGIN)
class origin(object):

    _PACK_STR = 'BBB'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self,flag = 0x80, code = bgp4_update._ORIGIN, length = 1, value = 1):
        #value: 0--IGP 1--EGP 2--INCOMPLETE
        self.flag = flag
        self.code = code
        self.length = length
        self.value = value

    def parser(cls, buf, offset):
        (flag, code, length, value) = struct.unpack_from( self._PACK_STR+'B', buf, offset)
        offset += cls._MIN_LEN + 1
        msg = cls( flag, code, length, value)
        return msg

    def serialize(self):
        hdr = bytearray(struct.pack( self._PACK_STR+'B', self.flag, self.code, self.length, self.value))
        return hdr

@bgp4_update.register_path_attributes_type(bgp4_update._AS_PATH)
class as_path(object):
    def __init__( self,flag, code, length, as_type, as_len, as_values =[]):
        #flag = 0x80, length = 0,code = bgp4_update._AS_PATH
        self.flag = flag
        self.code = code
        self.length = length
        self.as_type =  as_type
        self.as_len = as_len
        self.as_values = as_values
      
        if ((flag & 0x10) == 0x10):
            _PACK_STR = '!BBH'
            _MIN_LEN = struct.calcsize(_PACK_STR) 
        else:
            _PACK_STR = '!BBB'
            _MIN_LEN = _MIN_LEN = struct.calcsize(_PACK_STR)


    def parser(cls, buffer, offset):
        (flag,code) = struct.unpack_from('!BB', buf, offset)

        if ((flag & 0x10) == 0x10):
            cls._PACK_STR = '!BBH'
            cls._MIN_LEN = struct.calcsize(_PACK_STR) 
        else:
            cls._PACK_STR = '!BBB'
            cls._MIN_LEN = _MIN_LEN = struct.calcsize(_PACK_STR) 

        (flag, code, length, as_type, as_len) = struct.unpack_from(cls._PACK_STR+'BB', buf, offset)
        offset += cls._MIN_LEN + 2
        as_values = []
        for i in range(as_len):
            as_value = struct.unpack_from('!H', buf, offset)
            offset += 2
            as_values.append[as_value]
        msg = cls(flag, code, length, as_type, as_len, as_values)
        return msg


    def serialize(self):
        hdr = bytearray(struct.pack( self._PACK_STR+'BB', self.flag, self.code, self.length, self.as_type, self.as_len))
        self.length = 2
        for i in range(self.as_len):
            hdr += bytearray(struct.pack('!H',self.as_values[i]))
            self.length += 2
        struct.pack_into('!'+self._PACK_STR[3], self.length)
        return hdr

@bgp4_update.register_path_attributes_type(bgp4_update._MULTI_EXIT_DISK)
class multi_exit_disk(object):

    _PACK_STR = 'BBB'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self,flag = 0x80, code = bgp4_update._MULTI_EXIT_DISK, length = 1, value = 0):
       
        self.flag = flag
        self.code = code
        self.length = length
        self.value = value

    def parser(cls, buf, offset):
        (flag, code, length, value) = struct.unpack_from( self._PACK_STR+'I', buf, offset)
        offset += cls._MIN_LEN + 4
        msg = cls( flag, code, length, value)
        return msg

    def serialize(self):
        hdr = bytearray(struct.pack( self._PACK_STR+'I', self.flag, self.code, self.length, self.value))
        return hdr


@bgp4_update.register_path_attributes_type(bgp4_update._MP_REACH_NLRI)
class mp_reach_nlri(object):

    def __init__( self, flag, code, length, addr_family, sub_addr_family, next_hop_len = 0, next_hop = None, num_of_snpas = 0, snpas = [], nlri = []):
        #flag = 0x90, code = bgp4_update._MP_REACH_NLRI
        self.flag = flag
        self.code = code
        self.length = length
        self.addr_family = addr_family
        self.sub_addr_family = sub_addr_family
        self.next_hop_len = next_hop_len
        self.next_hop = next_hop
        self.num_of_snpas = num_of_snpas
        #snpas may in the form of [len1,value1,len2,value2]
        self.snpas =snpas
        self.nlri = nlri

        if ((flag & 0x10) == 0x10):
            _PACK_STR = '!BBH'
            _MIN_LEN = struct.calcsize(_PACK_STR) 
        else:
            _PACK_STR = '!BBB'
            _MIN_LEN = _MIN_LEN = struct.calcsize(_PACK_STR)

    def parser(cls, buf, offset):
        (flag,code) = struct.unpack_from('!BB', buf, offset)

        if ((flag & 0x10) == 0x10):
            cls._PACK_STR = '!BBH'
            cls._MIN_LEN = struct.calcsize(_PACK_STR) 
        else:
            cls._PACK_STR = '!BBB'
            cls._MIN_LEN = _MIN_LEN = struct.calcsize(_PACK_STR) 

        (flag,code,length) = struct.unpack_from(cls._PACK_STR, buf, offset)
        offset += cls._MIN_LEN

        if length >= 4:
            (addr_family,sub_addr_family, next_hop_len) = struct.unpack_from('!HBB', buf, offset)
            offset += 4

        next_hop = None
        if next_hop_len !=0:
            #next_hop_len == 4(ipv4) or 16(ipv6) 
            (next_hop,) = struct.unpack_from('!%is'%next_hop_len, buf, offset)
            offset += next_hop_len

        if offset < len(buf):
            (num_of_snpas,) = struct.unpack_from('!B', buf, offset)
            offset += 1
            snaps = []
            if num_of_snpas != 0:                
                for i in range(num_of_snpas):
                    (len_of_snap,) = struct.unpack_from('!B', buf, offset)
                    offset += 1
                    snaps.append(len_of_snap)
                    (snap,) = struct.unpack_from('!%is'%len_of_snap, buf , offset)
                    offset += len_of_snap
                    snaps.append(snap)

        if offset < len(buf):
            nlri = []
            #for i in range(len(self.nlri)):
            len_nlri = struct.unpack_from('!B', buf, offset)
            offset += 1
            nlri.append(len_nlri)
            a = len_nlri/8
            b = len_nlri%8

            if b != 0:
                a += 1
                b = 8-b
            para_nlri = struct.unpack_from('!%is'%a, buf, offset)
            para_nlri >>= b 
            offset += a
            nlri.append(para_nlri)

        msg = cls(flag, code, length, addr_family, sub_addr_family, next_hop_len, next_hop, 
            num_of_snpas, snpas, nlri)
        return msg

    def serialize(self):
        #serialise wd_route_len and path_attr_len first
        hdr = bytearray(struct.pack( self._PACK_STR+'HB', self.flag, self.code, self.length, self.addr_family, self.sub_addr_family))
        self.length = 3
        if self.next_hop_len == 4:
            hdr += bytearray(struct.pack('!BI',self.next_hop_len,self.next_hop))
            self.length += 4 + 1
        elif self.next_hop_len == 16:
            hdr += bytearray(struct.pack('!B16s',self.next_hop_len,self.next_hop))
            self.length += 16 + 1
        elif self.next_hop_len == 0:
             hdr += bytearray(struct.pack('!B',self.next_hop_len))
             self.length += 1

        hdr += bytearray(struct.pack('!B',self.num_of_snpas))
        if self.num_of_snpas != 0:
            for i in range(self.num_of_snpas):
                len_of_snap = self.snaps[2*i]
                if len_of_snap != 0:
                    hdr += bytearray(struct.pack('!B%is'%len_of_snap, self.snaps[2*i], self.snaps[2*i+1]))
                else:
                    hdr += bytearray(struct.pack('!B',self.snaps[2*i]))
                self.length += len_of_snap + 1

        for i in range(len(self.nlri)/2):
            len_nlri = nlri[2*i]
            a = len_nlri/8
            b = len_nlri%8
            if b != 0:
                a += 1
                self.snaps[2*i+1] <<= (8-b) 
                hdr += bytearray(struct.pack('!B%is'%a, self.snaps[2*i], self.snaps[2*i+1]))
            elif a == 0 and b == 0:
                hdr += bytearray(struct.pack('!B',self.snaps[2*i]))
            self.length += a + 1

        if self._PACK_STR == '!BBH':
            struct.pack_into('!H', hdr, 2, self.length)
        else:
            struct.pack_into('!B', hdr, 2, self.length)

        return hdr

@bgp4_update.register_path_attributes_type(bgp4_update._MP_UNREACH_NLRI)
class mp_unreach_nlri(object):

    def __init__( self, flag, code, length, addr_family, sub_addr_family, wd_routes = []):
        #flag = 0x90,code = bgp4_update._MP_UNREACH_NLRI
        self.flag = flag
        self.code = code
        self.length = length
        self.addr_family = addr_family
        self.sub_addr_family = sub_addr_family
        self.wd_routes = wd_routes        

        if ((flag & 0x10) == 0x10):
            _PACK_STR = '!BBH'
            _MIN_LEN = struct.calcsize(_PACK_STR) 
        else:
            _PACK_STR = '!BBB'
            _MIN_LEN = _MIN_LEN = struct.calcsize(_PACK_STR)

    def parser(cls, buf, offset):
        
        (flag,code) = struct.unpack_from('!BB', buf, offset)
        if ((flag & 0x10) == 0x10):
            cls._PACK_STR = '!BBH'
            cls._MIN_LEN = struct.calcsize(_PACK_STR) 
        else:
            cls._PACK_STR = '!BBB'
            cls._MIN_LEN = _MIN_LEN = struct.calcsize(_PACK_STR) 

        (flag, code, length, addr_family, sub_addr_family) = struct.unpack_from(cls._PACK_STR+'BB', buf, offset)
        offset += cls._MIN_LEN
        msg = cls(flag, code, length, addr_family, sub_addr_family)
        len_ = length
        len_ -= 2
        if len_ > 0:
            len_wd_route = struct.unpack_from('!B', buf, offset)
            offset += 1
            msg.wd_routes.append(len_wd_route)
            a = len_wd_route/8
            b = len_wd_route%8
            if b != 0:
                a += 1              
            wd_route = struct.unpack_from('!%is'%a, buf, offset)
            wd_route >>= (8-b)
            offset += a
            msg.wd_routes.append(wd_route)
        return msg  

    def serialize(self):
        #serialise wd_route_len and path_attr_len first
        hdr = bytearray(struct.pack( self._PACK_STR+'HB', self.flag, self.code, self.length, self.addr_family, self.sub_addr_family))
        self.length = 3   

        for i in range(len(self.wd_routes)/2):
            len_wd_route = self.wd_routes[2*i]
            a = len_wd_route/8
            b = len_wd_route%8
            if b != 0:
                a += 1
                self.wd_routes[2*i+1] <<= (8-b) 
                hdr += bytearray(struct.pack('!B%is'%a, self.wd_routes[2*i], self.wd_routes[2*i+1]))
            elif a == 0 and b == 0:
                hdr += bytearray(struct.pack('!B', self.wd_routes[2*i])) 
            self.length += a + 1

        if self._PACK_STR == '!BBH':
            struct.pack_into('!H', hdr, 2, self.length)
        else:
            struct.pack_into('!B', hdr, 2, self.length)
        return hdr
   

@bgp4.register_bgp4_type(BGP4_NOTIFICATION)
class bgp4_notification(object):

    _PACK_STR = '!BB'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, err_code, err_subcode, data=None):
        self.err_code = err_code
        self.err_subcode = err_subcode
        self.data = data

    def parser(cls, buf, offset):
        (err_code,err_subcode) = struct.unpack_from(cls._PACK_STR, buf, offset)
        offset += self._MIN_LEN
        msg = cls( err_code, err_subcode)
        if len(buf) > offset:
            msg.data = buf[offset:]
        return msg


    def serialize(self):
        hdr = bytearray(struct.pack(self._PACK_STR, self.err_code, self.err_subcode))
        if data != None:
            hdr += bytearray(self.data)
        return hdr