import os
import yaml

from ryu.base import app_manager
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.controller import ofp_event
from ryu.ofproto import ofproto_v1_3
from ryu.lib import dpid as dpid_lib
from ryu.lib import stplib
from ryu.lib.packet import packet, ethernet, ether_types


class STPSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"stplib": stplib.Stp}

    def __init__(self, *args, **kwargs):
        super(STPSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.stp = kwargs["stplib"]

        stp_config = self._load_stp_config()
        if stp_config:
            self.stp.set_config(stp_config)
            self.logger.info("STP config loaded: %s", stp_config)
        else:
            self.logger.info("No STP config found, using default STP behavior.")

    def _load_stp_config(self):
        """
        Charge la configuration STP depuis /app/iac/stp_config.yml
        Format attendu:
        switches:
          "0000000000000001":
            bridge:
              priority: 28672
          "0000000000000002":
            bridge:
              priority: 32768
        """
        config_path = os.getenv("STP_CONFIG_PATH", "/app/iac/stp_config.yml")

        if not os.path.exists(config_path):
            return {}

        with open(config_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}

        result = {}
        for dpid_str, cfg in raw.get("switches", {}).items():
            try:
                dpid = dpid_lib.str_to_dpid(dpid_str)
                result[dpid] = cfg
            except Exception as e:
                self.logger.warning("Invalid STP config for %s: %s", dpid_str, e)

        return result

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Table-miss flow
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=0, match=match, actions=actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id is not None and buffer_id != ofproto.OFP_NO_BUFFER:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                instructions=instructions
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                instructions=instructions
            )

        datapath.send_msg(mod)

    def delete_flows(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(
            datapath=datapath,
            table_id=ofproto.OFPTT_ALL,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=parser.OFPMatch()
        )
        datapath.send_msg(mod)

    @set_ev_cls(stplib.EventPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return

        # Ignorer LLDP
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})

        self.logger.debug("packet in dpid=%s src=%s dst=%s in_port=%s",
                          dpid, src, dst, in_port)

        # Learn source MAC
        self.mac_to_port[dpid][src] = in_port

        # Determine output port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install a flow only for known destination
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)

            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, priority=1, match=match, actions=actions, buffer_id=msg.buffer_id)
                return
            else:
                self.add_flow(datapath, priority=1, match=match, actions=actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)

    @set_ev_cls(stplib.EventTopologyChange, MAIN_DISPATCHER)
    def topology_change_handler(self, ev):
        dp = ev.dp
        dpid_str = dpid_lib.dpid_to_str(dp.id)
        self.logger.warning("[dpid=%s] Topology change detected. Flushing MAC table and flows.", dpid_str)

        if dp.id in self.mac_to_port:
            del self.mac_to_port[dp.id]

        self.delete_flows(dp)

        # Reinstall table-miss after flush
        parser = dp.ofproto_parser
        ofproto = dp.ofproto
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(dp, priority=0, match=match, actions=actions)

    @set_ev_cls(stplib.EventPortStateChange, MAIN_DISPATCHER)
    def port_state_change_handler(self, ev):
        dpid_str = dpid_lib.dpid_to_str(ev.dp.id)
        of_state = {
            stplib.PORT_STATE_DISABLE: "DISABLE",
            stplib.PORT_STATE_BLOCK: "BLOCK",
            stplib.PORT_STATE_LISTEN: "LISTEN",
            stplib.PORT_STATE_LEARN: "LEARN",
            stplib.PORT_STATE_FORWARD: "FORWARD"
        }

        self.logger.info("[dpid=%s][port=%d] state=%s",
                         dpid_str, ev.port_no, of_state.get(ev.port_state, "UNKNOWN"))