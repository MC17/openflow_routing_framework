from ryu.topology import switches, switches
from ryu.lib.dpid import dpid_to_str
from ryu.lib.port_no import port_no_to_str

class Port(switches.Port):
    def __init__(self, port, peer = None):
        # port and peer are two switches.Port objects

        # init switches.Port variables
        self.dpid = port.dpid
        self._ofproto = port._ofproto
        self._config = port._config
        self._state = port._state

        self.port_no = port.port_no
        self.hw_addr = port.hw_addr
        self.name = port.name

        # below is our new variables
        if peer:
            self.peer_switch_dpid = peer.dpid
            self.peer_port_no = peer.port_no
        
        self.is_border = False  # if this is a border port of the network

    def to_dict(self):
        d = super(Port, self).to_dict()
        d['peer_switch_dpid'] = dpid_to_str(self.peer_switch_dpid)
        d['peer_port_no'] = port_no_to_str(self.peer_port_no)
        d['is_border'] = 'True' if self.is_border else 'False'
        return d


class Switch(switches.Switch):
    def __init__(self, dp):
        # dp here is not dpid, but a Datapath class object,
        # defined in ryu.controller.Datapath
        super(Switch, self).__init__(dp)
        
        # a 'self.name' should be here, but not found

        # peer switch -> local port
        self.peers = {}

        # port_no -> Port, eg. ports[port_no] = Port
        # note that this variable overshadows super.ports
        self.ports = {}
