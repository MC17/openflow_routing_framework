import gevent

from ryu.base import app_manager
from ryu.controller.handler import set_ev_handler, set_ev_cls
from ryu.controller.handler import (HANDSHAKE_DISPATCHER, MAIN_DISPATCHER,
                                    CONFIG_DISPATCHER, DEAD_DISPATCHER)
from ryu.controller import ofp_event
from ryu import topology
from ryu.ofproto import ofproto_v1_0

from switch import Port, Switch

class Routing(app_manager.RyuApp):

    def __init__(self, *args, **kwargs):
        super(Routing, self).__init__(*args, **kwargs)
        
        self.dpid_to_switch = {}    # dpid_to_switch[dpid] = Switch
                                    # maintains all the switches

        #gevent.spawn(self._test)

    def _test(self):
        while True:
            self.__test()
            gevent.sleep(3)

    def __test(self):
        print '-------------------'
        for k, switch in self.dpid_to_switch.iteritems():
            print switch, switch.name
            for k, port in switch.ports.iteritems():
                print port

        print '-------------------'


    def _pre_install_flow_entry(self, switch):
        # 'switch' is a Switch object
        pass

    @set_ev_handler(topology.event.EventSwitchEnter)
    def switch_enter_handler(self, event):
        # very strangely, EventSwitchEnter happens after 
        # EventOFPSwitchFeatures sometimes
        dpid = event.switch.dp.id
        try:
            s = self.dpid_to_switch[dpid]
        except KeyError:
            s = Switch(event.switch.dp)
            self.dpid_to_switch[dpid] = s

        self._pre_install_flow_entry(s)

    @set_ev_handler(topology.event.EventSwitchLeave)
    def switch_leave_handler(self, event):
        try:
            del self.dpid_to_switch[event.switch.dp.id]
        except KeyError:
            pass


    def _update_port_link(self, dpid, port):
        switch = self.dpid_to_switch[dpid]
        p = switch.ports.get(port.port_no, None)
        if p:
            p.peer_switch_dpid = port.peer_switch_dpid
            p.peer_port_no = port.peer_port_no
        else:
            switch.ports[port.port_no] = port


    @set_ev_handler(topology.event.EventLinkAdd)
    def link_add_handler(self, event):
        src_port = Port(port = event.link.src, peer = event.link.dst)
        dst_port = Port(port = event.link.dst, peer = event.link.src)
        self._update_port_link(src_port.dpid, src_port)
        self._update_port_link(dst_port.dpid, dst_port)

    def _delete_link(self, port):
        try:
            switch = self.dpid_to_switch[port.dpid]
            p = switch.ports[port.port_no]
        except KeyError:
            return

        p.peer_switch_dpid = None
        p.peer_port_no = None

    @set_ev_handler(topology.event.EventLinkDelete)
    def link_delete_handler(self, event):
        self._delete_link(event.link.src)
        self._delete_link(event.link.dst)

    @set_ev_handler(topology.event.EventPortAdd)
    def port_add_handler(self, event):
        port = Port(event.port)
        switch = self.dpid_to_switch[port.dpid]
        switch.ports[port.port_no] = port

    @set_ev_handler(topology.event.EventPortDelete)
    def port_delete_handler(self, event):
        port = Port(event.port)
        try:
            switch = self.dpid_to_switch[port.dpid]
            del switch.ports[port.port_no]
        except KeyError:
            pass


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, [MAIN_DISPATCHER, 
                                                CONFIG_DISPATCHER])
    # we must handle this event because ryu's topology discovery
    # only shows ports between switches
    def switch_feature_handler(self, event):
        dpid = event.msg.datapath_id
        try:
            switch = self.dpid_to_switch[dpid]
        except KeyError:
            self.dpid_to_switch[dpid] = Switch(event.msg.datapath)

        switch = self.dpid_to_switch[dpid]
        for port_no, port in event.msg.ports.iteritems():
            if port_no not in switch.ports:
                p = Port(port = port, dp = event.msg.datapath)
                switch.ports[p.port_no] = p
            if port_no == ofproto_v1_0.OFPP_LOCAL:
                switch.name = port.name
