import netaddr

from ryu.topology import switches
from ryu.topology.switches import Port as Port_type
from ryu.lib.dpid import dpid_to_str
from ryu.lib.port_no import port_no_to_str
from ryu.ofproto.ofproto_v1_0_parser import OFPPhyPort

class Port(switches.Port):
    def __init__(self, port, peer = None, dp = None):
        # if the conbination is port + peer, then
        # port and peer are two switches.Port objects;
        # if port + dp, then
        # port is ofp_phy_port and dp is the datapath of this port

        self.peer_switch_dpid = None
        self.peer_port_no = None

        if isinstance(port, Port_type):
            # init switches.Port variables
            self.dpid = port.dpid
            self._ofproto = port._ofproto
            self._config = port._config
            self._state = port._state

            self.port_no = port.port_no
            self.hw_addr = netaddr.EUI(port.hw_addr)
            self.name = port.name

            # below are our new variables
            if peer:
                self.peer_switch_dpid = peer.dpid
                self.peer_port_no = peer.port_no
        elif isinstance(port, OFPPhyPort):
            self.dpid = dp.id 
            self._ofproto = dp.ofproto
            self._config = port.config
            self._state = port.state

            self.port_no = port.port_no
            self.hw_addr = netaddr.EUI(port.hw_addr)
            self.name = port.name
        else:
            print type(port)
            print switches.Port
            print Port_type
            raise AttributeError

        self.gateway = None
        self.cost = float('inf') # infinite

    def to_dict(self):
        d = super(Port, self).to_dict()
        d['peer_switch_dpid'] = dpid_to_str(self.peer_switch_dpid)
        d['peer_port_no'] = port_no_to_str(self.peer_port_no)
        d['is_border'] = 'True' if self.is_border else 'False'
        return d

    def update_from_config(self, config):
        try:
            self.gateway = config[self.port_no]
        except KeyError:
            pass
        print self.port_no, 'gateway:', self.gateway


class Switch(switches.Switch):
    def __init__(self, dp):
        # dp here is not dpid, but a Datapath class object,
        # defined in ryu.controller.Datapath
        super(Switch, self).__init__(dp)

        self.name = None
        
        # peer switch -> local port number
        self.peer_to_local_port = {}

        # port_no -> Port, eg. ports[port_no] = Port
        # note that this variable overshadows super.ports
        self.ports = {}

        # temporarily store packets we don't know MAC address yet.
        self.msg_buffer = []

        # ip_to_mac[ip_addr] = (mac_addr, time_stamp)
        # maintains ARP table
        self.ip_to_mac = {}

    def update_from_config(self, config):
        if self.name == None:
            return

        try:
            d = config[self.name]
        except KeyError:
            print 'WARNING', self.name, 'is not configured'
            return
        for k, v in self.ports.iteritems():
            v.update_from_config(d)

    def __eq__(self, other):
        try:
            if self.dp.id == other.dp.id:
                return True
        except:
            return False
        return False

    def __str__(self):
        return '<Switch: %s>' % self.name
