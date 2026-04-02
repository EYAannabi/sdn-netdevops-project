from ryu.base import app_manager
from ryu.controller import handler, ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.lib import stplib
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.ofproto import ofproto_v1_3


class DatacenterController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"stplib": stplib.Stp}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.stp = kwargs["stplib"]
        self.mac_to_port = {}
        self.datapaths = {}

        # Keep STP priorities deterministic across the spine-leaf topology.
        self.stp.set_config({
            1: {"bridge": {"priority": 0x8000}},
            2: {"bridge": {"priority": 0x9000}},
            3: {"bridge": {"priority": 0xA000}},
            4: {"bridge": {"priority": 0xB000}},
        })

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id is not None:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                instructions=inst,
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                instructions=inst,
            )

        datapath.send_msg(mod)

    def delete_learned_flows(self, datapath):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        for mac in self.mac_to_port.get(datapath.id, {}):
            match = parser.OFPMatch(eth_dst=mac)
            mod = parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                priority=10,
                match=match,
            )
            datapath.send_msg(mod)

    @handler.set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        self.datapaths[datapath.id] = datapath
        self.mac_to_port.setdefault(datapath.id, {})

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @handler.set_ev_cls(stplib.EventPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]
        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Ignore LLDP frames used internally by topology discovery/STP.
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 10, match, actions, msg.buffer_id)
                return
            self.add_flow(datapath, 10, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)

    @handler.set_ev_cls(stplib.EventTopologyChange, MAIN_DISPATCHER)
    def topology_change_handler(self, ev):
        datapath = ev.dp
        dpid = datapath.id

        self.logger.info("Topology change detected on switch %s. Clearing learned state.", dpid)
        self.mac_to_port[dpid] = {}
        self.delete_learned_flows(datapath)

    @handler.set_ev_cls(stplib.EventPortStateChange, MAIN_DISPATCHER)
    def port_state_change_handler(self, ev):
        states = {
            stplib.PORT_STATE_DISABLE: "DISABLE",
            stplib.PORT_STATE_BLOCK: "BLOCK",
            stplib.PORT_STATE_LISTEN: "LISTEN",
            stplib.PORT_STATE_LEARN: "LEARN",
            stplib.PORT_STATE_FORWARD: "FORWARD",
        }
        self.logger.info(
            "STP port state changed: dpid=%s port=%s state=%s",
            ev.dp.id,
            ev.port_no,
            states.get(ev.port_state, ev.port_state),
        )
