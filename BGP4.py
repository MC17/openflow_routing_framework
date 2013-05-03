import struct
import convert
from ryu.lib.packet import packet_base

BGP_TCP_PORT = 179

BGP4_OPEN = 1
BGP4_UPDATE = 2
BGP4_NOTIFICATION = 3
BGP4_KEEPALIVE = 4 #keepalive message only contain a header  
#BGP4_ROUTE_REFRESH = 5

class bgp4(packet_base.PacketBase):
    """

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                                                               +
    |                                                               |
    +                                                               +
    |                        Marker                                 |
    +                                                               +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |              Length           |       Type    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    
    """

    _PACK_STR = '!16sHB'
    _MIN_LEN = struct.calcsize(_PACK_STR)
    BGP4_HEADER_SIZE = _MIN_LEN
    _BGP4_TYPES = {}

    @staticmethod
    def register_bgp4_type(*args):
        def _register_bgp4_type(cls):
            for type_ in args:
                bgp4._BGP4_TYPES[type_] = cls
            return cls

        return _register_bgp4_type

    def __init__(self, type_, marker = 1, length = 0, data = None):
        #length default value is 0
        super(bgp4, self).__init__()
        self.marker = marker
        self.length = length
        self.type_ = type_
        self.data = data

    @classmethod
    def parser(cls, buf):
        (marker_, length, type_) = struct.unpack_from(cls._PACK_STR, buf)
        marker = (struct.unpack_from('!4I', marker_)[0]) & 0x1
        msg = cls(marker = marker, length = length, type_ = type_)
        offset = cls._MIN_LEN
        if len(buf) > offset:
            cls_ = cls._BGP4_TYPES.get(type_, None)
            if cls_:
                msg.data = cls_.parser( buf, offset)
            else:
                msg.data = buf[offset:]

        return msg

    def serialize(self, payload, prev):
        marker_ = None
        if self.marker == 1:
            marker_ = struct.pack('!4I', *[((self.marker) << 32) - 1] * 4)

        if marker_:
            hdr = bytearray(struct.pack(self._PACK_STR, marker_, self.length, self.type_))
            if self.data is not None:
                if self.type_ in bgp4._BGP4_TYPES:
                    hdr += self.data.serialize()
                else:
                    hdr += bytearray(self.data)

            if self.length != len(hdr):
                self.length = len(hdr)
                struct.pack_into('!H', hdr, 16, self.length)
        
            return hdr
        else:
            return None


@bgp4.register_bgp4_type(BGP4_OPEN)
class bgp4_open(object):
    """
    
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+
    |   Version     |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   My Autonomous System        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Hold Time           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                           BGP Identifier                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Opt Parm Len |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    |               Optional Parameters (variable)                  |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


    Optional Parameters:

    a list of <Parameter Type, Parameter Length, Parameter Value> triplet

    0                   1
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...
    |  Parm. Type   | Parm. Length  |  Parameter Value (variable)
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...

    Type = 2 for Capabilities

    BGP capability advertisement(RFC 5492)

          +------------------------------+
          | Capability Code (1 octet)    |
          +------------------------------+
          | Capability Length (1 octet)  |
          +------------------------------+
          | Capability Value (variable)  |
          ~                              ~
          +------------------------------+

          Capability Length is the length of "Capability Value"
    """

    _PACK_STR = '!BHHIB'
    _MIN_LEN = struct.calcsize(_PACK_STR)
    _CAPABILITY_ADVERTISEMENT = {}


    #_CAPABILITY_ADVERTISEMENT = 2
    _MULTI_PROTOCOL_EXTENSION = 1
    _ROUTE_REFRESH = 2
    _SUPPORT_FOR_4_OCTETS_AS_NUM = 65


    @staticmethod
    def register_capability_advertisement_type(*args):
        def _register_capability_advertisement_type(cls):
            for type_ in args:
                bgp4_open._CAPABILITY_ADVERTISEMENT[type_] = cls
            return cls

        return _register_capability_advertisement_type

    # using capabilities adverstisement in it's optional parameters' field
    def __init__(self, version, my_as, hold_time, bgp_identifier,
                 opt_para_len=0, type_=2, para_len=0, data=[]):
        self.version = version
        self.my_as = my_as
        self.hold_time = hold_time
        self.bgp_identifier = convert.ipv4_to_int(bgp_identifier)
        self.opt_para_len = opt_para_len
        self.type_ = type_
        self.para_len = para_len
        self.data = data

    @classmethod
    def parser(cls, buf, offset):
        (version, my_as, hold_time, bgp_identifier, opt_para_len) = \
                        struct.unpack_from(cls._PACK_STR, buf, offset)
        offset += cls._MIN_LEN

        bgp_identifier = convert.ipv4_to_str(bgp_identifier)
        if opt_para_len >= 2:
            (type_, para_len) = struct.unpack_from('!BB', buf, offset)
            offset += 2
            msg = cls(version, my_as, hold_time, bgp_identifier,
                      opt_para_len, type_, para_len)
        else:
            msg = cls(version, my_as, hold_time, bgp_identifier,
                      opt_para_len)
            return msg

        msg.data = []
        buf = buffer(buf[offset:])
        while len(buf) > 0:
            code, len_ = struct.unpack_from('!BB', buf)
            cls_ = cls._CAPABILITY_ADVERTISEMENT.get(code, None)
            if cls_:
                msg.data.append(cls_.parser(buf, 0))
            offset += len_ + 2
            buf = buffer(buf[len_+2:])

        return msg

    def serialize(self):
        self.opt_para_len = 0
        hdr = bytearray(struct.pack(bgp4_open._PACK_STR, self.version, self.my_as, self.hold_time,
                                    self.bgp_identifier, self.opt_para_len))

        if self.data != []:
            hdr += bytearray(struct.pack('!BB', self.type_, self.para_len))
            for para in self.data:

                #hdr += bytearray(struct.pack('!BB', para.code, para.length))
                cls_ = self._CAPABILITY_ADVERTISEMENT.get(para.code, None)
                if cls_:
                    hdr += para.serialize()
                    self.para_len += para._MIN_LEN

        self.opt_para_len = self.para_len + 2
        struct.pack_into('!B', hdr, 9, self.opt_para_len)
        struct.pack_into('!B', hdr, 11, self.para_len)
        return hdr


@bgp4_open.register_capability_advertisement_type(bgp4_open._MULTI_PROTOCOL_EXTENSION)
class multi_protocol_extension(object):
    """
        Multi-protocol capability advertisement(RFC 4760)

        Capability Code = 1
        Capability Length = 4
        Capability Value field:

                     0       7      15      23      31
                     +-------+-------+-------+-------+
                     |      AFI      | Res.  | SAFI  |
                     +-------+-------+-------+-------+
        AFI: Address Family Identifier(16 bit)
        Res.: reserved(8 bit)   should set default 0
        SAFI: Subsequent Address Family Identifier(8 bit)

        for AFI and SAFI values, search http://www.iana.org/protocols,
        with keyword "Address Family Numbers" and "SAFI"

        e.g.
        AFI
        other -- 0
        ipv4 --  1
        ipv6 --  2

        SAFI
        0 --  reserved
        1 --  unicast
        2 --  multicast

    """
    _PACK_STR = '!BBHBB'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, code, length, addr_family, res, sub_addr_family):
        #res = 0x00 code = bgp4_open._CAPABILITY_ADVERTISEMENT_MPE length = self._MIN_LEN
        self.code = code
        self.length = length
        self.addr_family = addr_family
        self.res = res
        self.sub_addr_family = sub_addr_family

    @classmethod
    def parser(cls, buf, offset):
        (code, length, addr_family, res, sub_addr_family) = struct.unpack_from(cls._PACK_STR, buf, offset)
        msg = cls(code, length, addr_family, res, addr_family)
        return msg

    def serialize(self):
        hdr = bytearray(
            struct.pack(self._PACK_STR, self.code, self.length, self.addr_family, self.res, self.sub_addr_family))
        return hdr


@bgp4_open.register_capability_advertisement_type(bgp4_open._ROUTE_REFRESH)
class route_refresh(object):
    """
        RFC 2918:
        This capability is advertised using the Capability code 2 
        and Capability length 0.
    """
    _PACK_STR = '!BB'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, code, length):
        #code = bgp4_open._CAPABILITY_ADVERTISEMENT_ROUTE_REFRESH length = 0
        self.code = code
        self.length = length

    @classmethod
    def parser(cls, buf, offset):
        (code, length) = struct.unpack_from(cls._PACK_STR, buf, offset)
        msg = cls(code, length)
        return msg

    def serialize(self):
        hdr = bytearray(struct.pack(self._PACK_STR, self.code, self.length))
        return hdr


@bgp4_open.register_capability_advertisement_type(bgp4_open._SUPPORT_FOR_4_OCTETS_AS_NUM)
class support_4_octets_as_num(object):
    """
        RFC 4893:
        Capability Code = 65
        Capability Length = 4
        Capability Value: the 4-octet AS number
    """
    _PACK_STR = '!BBI'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, code, length, as_num):
        #code = bgp4_open._SUPPORT_FOR_4_OCTETS_AS_NUM length = 4
        self.code = code
        self.length = length
        self.as_num = as_num
        if self.length == 2:
            self._PACK_STR = '!BBH'
        else:
            self._PACK_STR = '!BBI'
        self._MIN_LEN = struct.calcsize(self._PACK_STR)

    @classmethod
    def parser(cls, buf, offset):
        code, length = struct.unpack_from('!BB', buf, offset)
        if length == 2:
            cls._PACK_STR = '!BBH'
        else:
            cls._PACK_STR = '!BBI'
        (code, length, as_num) = struct.unpack_from(cls._PACK_STR, buf, offset)
        msg = cls(code, length, as_num)
        return msg

    def serialize(self):
        hdr = bytearray(struct.pack(self._PACK_STR, self.code, self.length, self.as_num))
        return hdr


@bgp4.register_bgp4_type(BGP4_UPDATE)
class bgp4_update(object):
    """

    +-----------------------------------------------------+
    |       Withdrawn Routes Length (2 octets)            |
    +-----------------------------------------------------+
    |       Withdrawn Routes (variable)                   |
    +-----------------------------------------------------+
    |       Total Path Attribute Length (2 octets)        |
    +-----------------------------------------------------+
    |       Path Attributes (variable)                    |
    +-----------------------------------------------------+
    |   Network Layer Reachability Information (variable) |
    +-----------------------------------------------------+  
    
    """

    _PACK_STR = '!HH'
    _MIN_LEN = struct.calcsize(_PACK_STR)
    _PATH_ATTRIBUTES = {}

    _ORIGIN = 1
    _AS_PATH = 2
    _NEXT_HOP = 3
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
    
    def __init__(self, wd_rout_len = 0, wd_rout = [], path_attr_len = 0,
                 path_attr = [], nlri = set(), total_len = 0):
        self.wd_rout_len = wd_rout_len
        self.wd_rout = wd_rout
        self.path_attr_len = path_attr_len
        self.path_attr = path_attr
        self.nlri = nlri
        self.total_len = total_len  # convenient to add nlri
        # nlri_len = total_len - 23 - path_attr_len - wd_rout_len

    @classmethod
    def parser(cls, buf, offset):

        (wd_rout_len,) = struct.unpack_from('!H', buf, offset)
        offset += 2
        # we don't handle wd_rote here,just skip it
        if wd_rout_len != 0:
            offset += wd_rout_len
        (path_attr_len,) = struct.unpack_from('!H', buf, offset)
        offset += 2
        msg = cls(wd_rout_len, [], path_attr_len, [], [])
        len_ = path_attr_len

        while len_ > 0:
            (flag, code) = struct.unpack_from('!BB', buf, offset)
            cls_ = cls._PATH_ATTRIBUTES.get(code, None)
            if cls_:
                path_attr_msg = cls_.parser(buf, offset)
                msg.path_attr.append(path_attr_msg)
                len_ -= cls_._MIN_LEN
                offset += cls_._MIN_LEN

                if path_attr_msg.__dict__.has_key('length'):
                    len_ -= path_attr_msg.length
                    offset += path_attr_msg.length
            else:
                # skip the atttribute we don't defined 
                offset += 2
                if (flag & 0x10) == 0x10:
                    (length,) = struct.unpack_from('!H', buf, offset)
                    offset += 2 + length
                    len_ -= 2 + length
                elif (flag & 0x10) == 0:
                    (length,) = struct.unpack_from('!B', buf, offset)
                    offset += 1 + length
                    len_ -= 1 + length
                else:
                    print '** here'
           
        nlri = set()    # e.g. set((prefix,ip),(prefix,ip),) eg (24,3232237568)
        nlri_len = 0
        while len(buf) > offset:
            (len_nlri,) = struct.unpack_from('!B', buf, offset)
            offset += 1

            a = len_nlri / 8
            if len_nlri % 8 != 0:
                a += 1   # aB
            b = a*'B'
            ip_tuple = struct.unpack_from('!%s'%b, buf, offset)  # e.g (192,168,8,)
            temp_list = list(ip_tuple)  # need to append 0
            while len(temp_list) < 4:
                temp_list.append(0)
            ip_nlri = convert.ipNum(*temp_list)  # ip int
            print '** nlri ip,prefix', convert.ipv4_to_str(ip_nlri), len_nlri
            _tuple = (len_nlri, ip_nlri)
            nlri.add(_tuple)
            offset += a
            nlri_len += 1 + a
        update_total_len = 23 + path_attr_len + wd_rout_len + nlri_len
        msg.nlri = nlri
        msg.total_len = update_total_len
        return msg


    def serialize(self):
        #serialise wd_route_len and path_attr_len first
        hdr = bytearray(struct.pack(self._PACK_STR, self.wd_rout_len, self.path_attr_len))
        if self.path_attr != []:
            for attr in self.path_attr:
                cls = self._PATH_ATTRIBUTES.get(attr.code, None)
                if cls:
                    hdr += attr.serialize()
                    self.path_attr_len += attr._MIN_LEN
                    if attr.__dict__.has_key('length'):
                        self.path_attr_len += attr.length
            struct.pack_into('!H', hdr, 2, self.path_attr_len)
        print '## serialize path_attr success'

        #nlri
        nlri_len = 0
        if len(self.nlri) != 0:
            for prefix, ip in self.nlri:
                ip_list = convert.ipv4_to_list(ip, prefix)
                b = len(ip_list) * 'B'
                hdr += bytearray(struct.pack('!B%s' % b, prefix, *ip_list))
                nlri_len += 1 + len(ip_list)
        print '## serialize nlri success'
        return hdr


@bgp4_update.register_path_attributes_type(bgp4_update._ORIGIN)
class origin(object):
    
    """

    0                   1
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Attr. Flags   |Attr. Type Code|
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Value:
    0   --  IGP 
    1   --  EGP 
    2   --  INCOMPLETE

    """

    _PACK_STR = 'BBB'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self,flag = 0x40, code = bgp4_update._ORIGIN,
                 length = 1, value = 1):
        
        self.flag = flag
        self.code = code
        self.length = length
        self.value = value

    @classmethod
    def parser(cls, buf, offset):
        (flag, code, length, value) = struct.unpack_from(cls._PACK_STR + 'B', buf, offset)
        offset += cls._MIN_LEN + 1
        msg = cls(flag, code, length, value)
        return msg

    def serialize(self):
        hdr = bytearray(struct.pack(self._PACK_STR + 'B', self.flag, self.code, self.length, self.value))
        return hdr


@bgp4_update.register_path_attributes_type(bgp4_update._AS_PATH)
class as_path(object):

    """

    0                   1
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Attr. Flags   |Attr. Type Code|
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    
    
    Value:  some As path segments like follows

    trible<path segment type, path segment length, path segment value>
    
    path segment type:
    1   --    AS_SET
    2   --    AS_SEQUENCE

    """

    # TODO need to modify by referring to rfc4271,4.3
    def __init__(self,flag, code, length, as_type, as_len, as_values =[]):
        #flag = 0x80, length = 0,code = bgp4_update._AS_PATH
        self.flag = flag
        self.code = code
        self.length = length
        self.as_type = as_type
        self.as_len = as_len
        self.as_values = as_values

        if ((flag & 0x10) == 0x10):
            self._PACK_STR = '!BBH'
            self._MIN_LEN = struct.calcsize(self._PACK_STR)
        else:
            self._PACK_STR = '!BBB'
            self._MIN_LEN = _MIN_LEN = struct.calcsize(self._PACK_STR)

    @classmethod
    def parser(cls, buf, offset):
        (flag, code) = struct.unpack_from('!BB', buf, offset)

        if ((flag & 0x10) == 0x10):
            cls._PACK_STR = '!BBH'
            cls._MIN_LEN = struct.calcsize(cls._PACK_STR)
        else:
            cls._PACK_STR = '!BBB'
            cls._MIN_LEN = struct.calcsize(cls._PACK_STR)

        (flag, code, length, as_type, as_len) = struct.unpack_from(cls._PACK_STR + 'BB', buf, offset)
        offset += cls._MIN_LEN + 2
        as_values = []
        for i in range(as_len):
            (as_value,) = struct.unpack_from('!I', buf, offset)
            offset += 2
            as_values.append(as_value)
        print '** as', as_values
        msg = cls(flag, code, length, as_type, as_len, as_values)
        return msg


    def serialize(self):
        hdr = bytearray(
            struct.pack(self._PACK_STR + 'BB', self.flag, self.code, self.length, self.as_type, self.as_len))
        self.length = 2
        for i in range(self.as_len):
            hdr += bytearray(struct.pack('!I', self.as_values[i]))
            self.length += 4
        struct.pack_into('!' + self._PACK_STR[3], hdr, 2, self.length)
        return hdr


@bgp4_update.register_path_attributes_type(bgp4_update._NEXT_HOP)
class next_hop(object):

    """

    0                   1
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Attr. Flags   |Attr. Type Code|
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    
    
    Value:
    IP address in Integer form

    """

    _PACK_STR = '!BBB'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, flag=0x40, code=bgp4_update._NEXT_HOP, length=4, _next_hop=None):
        self.flag = flag
        self.code = code
        self.length = length
        self._next_hop = convert.ipv4_to_int(_next_hop)

    @classmethod
    def parser(cls, buf, offset):
        (flag, code, length, _int_next_hop) = struct.unpack_from(cls._PACK_STR + 'I', buf, offset)
        _next_hop = convert.ipv4_to_str(_int_next_hop)
        print '** next_hop', _next_hop
        msg = cls(flag, code, length, _next_hop)
        return msg

    def serialize(self):
        hdr = bytearray(struct.pack(self._PACK_STR + 'I', self.flag, self.code, self.length, self._next_hop))
        return hdr

@bgp4_update.register_path_attributes_type(bgp4_update._MULTI_EXIT_DISK)
class multi_exit_disk(object):
    
    """

    0                   1
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Attr. Flags   |Attr. Type Code|
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Value:
    four-octet unsigned integer
    Usage in rfc4271,5.1.4

    """

    _PACK_STR = 'BBB'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, flag=0x80, code=bgp4_update._MULTI_EXIT_DISK, length=1, value=0):
        self.flag = flag
        self.code = code
        self.length = length
        self.value = value

    @classmethod
    def parser(cls, buf, offset):
        (flag, code, length, value) = struct.unpack_from(cls._PACK_STR + 'I', buf, offset)
        offset += cls._MIN_LEN + 4
        msg = cls(flag, code, length, value)
        return msg

    def serialize(self):
        hdr = bytearray(struct.pack(self._PACK_STR + 'I', self.flag, self.code, self.length, self.value))
        return hdr


@bgp4_update.register_path_attributes_type(bgp4_update._MP_REACH_NLRI)
class mp_reach_nlri(object):
    """
        ref: rfc4760,3
        Type Code: 14
        +---------------------------------------------------------+
        | Address Family Identifier (2 octets)                    |
        +---------------------------------------------------------+
        | Subsequent Address Family Identifier (1 octet)          |
        +---------------------------------------------------------+
        | Length of Next Hop Network Address (1 octet)            |
        +---------------------------------------------------------+
        | Network Address of Next Hop (variable)                  |
        +---------------------------------------------------------+
        | Reserved (1 octet)                                      |
        +---------------------------------------------------------+
        | Network Layer Reachability Information (variable)       |
        +---------------------------------------------------------+

        AFI: same to multi_protocol_extension
        SAFI: same to multi_protocol_extension
        Length: express the length of the "Network Address of Next Hop" field,measured in octets
        
        
    """

    def __init__(self, flag, code, length, addr_family, sub_addr_family, next_hop_len=0, next_hop=None, num_of_snpas=0,
                 snpas=[], nlri=[]):
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
        self.snpas = snpas
        self.nlri = nlri

        if ((flag & 0x10) == 0x10):
            _PACK_STR = '!BBH'
            _MIN_LEN = struct.calcsize(_PACK_STR)
        else:
            _PACK_STR = '!BBB'
            _MIN_LEN = _MIN_LEN = struct.calcsize(_PACK_STR)

    @classmethod
    def parser(cls, buf, offset):
        (flag, code) = struct.unpack_from('!BB', buf, offset)

        if ((flag & 0x10) == 0x10):
            cls._PACK_STR = '!BBH'
            cls._MIN_LEN = struct.calcsize(cls._PACK_STR)
        else:
            cls._PACK_STR = '!BBB'
            cls._MIN_LEN = struct.calcsize(cls._PACK_STR)

        (flag, code, length) = struct.unpack_from(cls._PACK_STR, buf, offset)
        offset += cls._MIN_LEN

        if length >= 4:
            (addr_family, sub_addr_family, next_hop_len) = struct.unpack_from('!HBB', buf, offset)
            offset += 4

        next_hop = None
        if next_hop_len != 0:
            #next_hop_len == 4(ipv4) or 16(ipv6) 
            (next_hop,) = struct.unpack_from('!%is' % next_hop_len, buf, offset)
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
                    (snap,) = struct.unpack_from('!%is' % len_of_snap, buf, offset)
                    offset += len_of_snap
                    snaps.append(snap)

        nlri = []
        while offset < len(buf):
            (len_nlri,) = struct.unpack_from('!B', buf, offset)
            offset += 1
            nlri.append(len_nlri)
            a = len_nlri / 8
            b = len_nlri % 8

            if b != 0:
                a += 1
                b = 8 - b
            para_nlri = struct.unpack_from('!%is' % a, buf, offset)
            para_nlri >>= b
            offset += a
            nlri.append(para_nlri)

        msg = cls(flag, code, length, addr_family, sub_addr_family, next_hop_len, next_hop,
                  num_of_snpas, snaps, nlri)
        return msg

    def serialize(self):
        #serialise wd_route_len and path_attr_len first
        hdr = bytearray(struct.pack(self._PACK_STR + 'HB', self.flag, self.code, self.length, self.addr_family,
                                    self.sub_addr_family))
        self.length = 3
        if self.next_hop_len == 4:
            hdr += bytearray(struct.pack('!BI', self.next_hop_len, self.next_hop))
            self.length += 4 + 1
        elif self.next_hop_len == 16:
            hdr += bytearray(struct.pack('!B16s', self.next_hop_len, self.next_hop))
            self.length += 16 + 1
        elif self.next_hop_len == 0:
            hdr += bytearray(struct.pack('!B', self.next_hop_len))
            self.length += 1

        hdr += bytearray(struct.pack('!B', self.num_of_snpas))
        if self.num_of_snpas != 0:
            for i in range(self.num_of_snpas):
                len_of_snap = self.snaps[2 * i]
                if len_of_snap != 0:
                    hdr += bytearray(struct.pack('!B%is' % len_of_snap, self.snaps[2 * i], self.snaps[2 * i + 1]))
                else:
                    hdr += bytearray(struct.pack('!B', self.snaps[2 * i]))
                self.length += len_of_snap + 1

        for i in range(len(self.nlri) / 2):
            len_nlri = self.nlri[2 * i]
            a = len_nlri / 8
            b = len_nlri % 8
            if b != 0:
                a += 1
                self.nlri[2 * i + 1] <<= (8 - b)
                hdr += bytearray(struct.pack('!B%is' % a, self.nlri[2 * i], self.nlri[2 * i + 1]))
            elif a == 0 and b == 0:
                hdr += bytearray(struct.pack('!B', self.nlri[2 * i]))
            self.length += a + 1

        if self._PACK_STR == '!BBH':
            struct.pack_into('!H', hdr, 2, self.length)
        else:
            struct.pack_into('!B', hdr, 2, self.length)

        return hdr


class NLRI(object):
    def __init__(self, length, prefix):
        self.length = length
        self.prefix = prefix


@bgp4_update.register_path_attributes_type(bgp4_update._MP_UNREACH_NLRI)
class mp_unreach_nlri(object):
    """
    ref:rfc4760,4

    +---------------------------------------------------------+
    | Address Family Identifier (2 octets)                    |
    +---------------------------------------------------------+
    | Subsequent Address Family Identifier (1 octet)          |
    +---------------------------------------------------------+
    | Withdrawn Routes (variable)                             |
    +---------------------------------------------------------+

    """

    def __init__(self, flag, code, length, addr_family,
                 sub_addr_family, wd_routes = []):
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

    @classmethod
    def parser(cls, buf, offset):

        (flag, code) = struct.unpack_from('!BB', buf, offset)
        if ((flag & 0x10) == 0x10):
            cls._PACK_STR = '!BBH'
            cls._MIN_LEN = struct.calcsize(cls._PACK_STR)
        else:
            cls._PACK_STR = '!BBB'
            cls._MIN_LEN = _MIN_LEN = struct.calcsize(cls._PACK_STR)

        (flag, code, length, addr_family, sub_addr_family) = struct.unpack_from(cls._PACK_STR + 'BB', buf, offset)
        offset += cls._MIN_LEN
        msg = cls(flag, code, length, addr_family, sub_addr_family)
        len_ = length
        len_ -= 2
        if len_ > 0:
            (len_wd_route,) = struct.unpack_from('!B', buf, offset)
            offset += 1
            msg.wd_routes.append(len_wd_route)
            a = len_wd_route / 8
            b = len_wd_route % 8
            if b != 0:
                a += 1
            wd_route = struct.unpack_from('!%is' % a, buf, offset)
            offset += a
            withdraw_nlri = NLRI(len_wd_route, wd_route)
            msg.wd_routes.append(withdraw_nlri)
        return msg

    def serialize(self):
        #serialise wd_route_len and path_attr_len first
        hdr = bytearray(struct.pack(self._PACK_STR + 'HB', self.flag, self.code, self.length, self.addr_family,
                                    self.sub_addr_family))
        self.length = 3

        for i in range(len(self.wd_routes) / 2):
            len_wd_route = self.wd_routes[2 * i]
            a = len_wd_route / 8
            b = len_wd_route % 8
            if b != 0:
                a += 1
                self.wd_routes[2 * i + 1] <<= (8 - b)
                hdr += bytearray(struct.pack('!B%is' % a, self.wd_routes[2 * i], self.wd_routes[2 * i + 1]))
            elif a == 0 and b == 0:
                hdr += bytearray(struct.pack('!B', self.wd_routes[2 * i]))
            self.length += a + 1

        if self._PACK_STR == '!BBH':
            struct.pack_into('!H', hdr, 2, self.length)
        else:
            struct.pack_into('!B', hdr, 2, self.length)
        return hdr


@bgp4.register_bgp4_type(BGP4_NOTIFICATION)
class bgp4_notification(object):

    """

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Error code    | Error subcode |       Data (variable)         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Error Code      Symbolic Name               Reference
    1               Message Header Error        Section 6.1
    2               OPEN Message Error          Section 6.2
    3               UPDATE Message Error        Section 6.3
    4               Hold Timer Expired          Section 6.5
    5               Finite State Machine Error  Section 6.6
    6               Cease Section 6.7 

    """

    _PACK_STR = '!BB'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, err_code, err_subcode, data=None):
        self.err_code = err_code
        self.err_subcode = err_subcode
        self.data = data

    @classmethod
    def parser(cls, buf, offset):
        (err_code, err_subcode) = struct.unpack_from(cls._PACK_STR, buf, offset)
        offset += cls._MIN_LEN
        msg = cls(err_code, err_subcode)
        if len(buf) > offset:
            msg.data = buf[offset:]
        return msg


    def serialize(self):
        hdr = bytearray(struct.pack(self._PACK_STR, self.err_code, self.err_subcode))
        if self.data != None:
            hdr += bytearray(self.data)
        return hdr
