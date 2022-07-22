use std::collections::HashMap;

use lazy_static::lazy_static;

use crate::dump::packet::Layer4::{ICMP, TCP, UDP};
use crate::dump::packet_parser::{EtherParser, IcmpParser, Ip4Parser, TcpParser, UdpParser};

const ETH_TYPE_IP: u16 = 0x0800;
const ETH_TYPE_ARP: u16 = 0x0806;
const IP_PROTO_ICMP: u8 = 0x01;
const IP_PROTO_TCP: u8 = 0x06;
const IP_PROTO_UDP: u8 = 0x11;
const ICMP_TYPE_ECHO_REPLY: u8 = 0x0;
const ICMP_TYPE_ECHO_REQUEST: u8 = 0x8;

lazy_static! {
    static ref eth_type_map: HashMap<u16, &'static str> = {
        let map = HashMap::from([
            (ETH_TYPE_IP ,"ipv4"),
            (ETH_TYPE_ARP ,"arp"),
        ]);
        return map;
    };

    static ref ip_proto_map: HashMap<u8, &'static str> = {
        let map = HashMap::from([
            (IP_PROTO_ICMP ,"icmp"),
            (IP_PROTO_TCP ,"tcp"),
            (IP_PROTO_UDP ,"udp"),
        ]);
        return map;
    };
 static ref icmp_type_map: HashMap<u8, &'static str> = {
        let map = HashMap::from([
            (ICMP_TYPE_ECHO_REPLY ,"icmp ping reply"),
            (ICMP_TYPE_ECHO_REQUEST ,"icmp ping request"),
        ]);
        return map;
    };
}

enum Layer4 {
    //icmp 原则上不算4层,这里只是方便分类
    ICMP(IcmpData),
    UDP(UdpHdr),
    TCP(TcpHdr),
}


// 完整数据包, 由原始字节数组逐层解析, 遇到错误则停止解析,并将错误写到ext_info
pub struct Packet {
    eth_hdr: Option<EthHdr>,
    ip_hdr: Option<IP4Hdr>,
    l4: Option<Layer4>,
    ext_info: Option<String>,
}


impl Packet {
    // 原始字节数组解析包
    pub fn from_bytes(b: &[u8]) -> Packet {
        let mut packet = Packet {
            eth_hdr: None,
            ip_hdr: None,
            l4: None,
            ext_info: None,
        };
        let eth_type;
        let ip_proto;
        //解析以太网头部
        match EtherParser::parse_eth_hdr(b) {
            Ok(e) => {
                eth_type = e.proto;
                packet.eth_hdr = Some(e);
            }
            Err(e) => {
                packet.ext_info = Some(String::from(e.info));
                return packet;
            }
        }

        let mut off: usize = 14; // 字节偏移
        match eth_type {
            ETH_TYPE_IP => {
                //解析ip头部
                match Ip4Parser::parse_ip4_hdr(&b[off..]) {
                    Ok(ip) => {
                        ip_proto = ip.proto;
                        off += (ip.ihl as usize) * 4;
                        packet.ip_hdr = Some(ip);
                        if off > b.len() {
                            return packet;
                        }
                    }
                    Err(e) => {
                        packet.ext_info = Some(String::from(e.info));
                        return packet;
                    }
                }
            }
            _ => {
                //不是ip头 停止解析
                packet.ext_info = Some(String::from("not ip frame"));
                return packet;
            }
        }
        match ip_proto {
            IP_PROTO_ICMP => {
                //解析icmp包
                match IcmpParser::parse_icmp(&b[off..]) {
                    Ok(icmp) => {
                        packet.l4 = Some(ICMP(icmp));
                    }
                    Err(e) => {
                        packet.ext_info = Some(String::from(e.info));
                        return packet;
                    }
                }
            }
            IP_PROTO_UDP => {
                //解析udp头
                match UdpParser::parse_udp(&b[off..]) {
                    Ok(udp) => {
                        packet.l4 = Some(UDP(udp));
                        off += 8;
                        if off > b.len() {
                            return packet;
                        }
                    }
                    Err(e) => {
                        packet.ext_info = Some(String::from(e.info));
                        return packet;
                    }
                }
            }
            IP_PROTO_TCP => {
                //解析tcp头
                match TcpParser::parse_tcp(&b[off..]) {
                    Ok(tcp) => {
                        off += 20 + (tcp.data_off as usize) * 4;
                        packet.l4 = Some(TCP(tcp));
                    }
                    Err(e) => {
                        packet.ext_info = Some(String::from(e.info));
                        return packet;
                    }
                }
            }
            _ => {}
        }

        return packet;
    }


    pub fn to_string(&self) -> String {
        let mut s = String::from("==========packet=========\r\n");
        if let Some(e) = &self.eth_hdr {
            s.push_str(e.to_string().as_str());
        }

        if let Some(ip) = &self.ip_hdr {
            s.push_str(ip.to_string().as_str());
        }

        match &self.l4 {
            Some(ICMP(icmp)) => {
                s.push_str(icmp.to_string().as_str());
            }
            Some(UDP(udp)) => {
                s.push_str(udp.to_string().as_str());
            }
            Some(TCP(tcp)) => {
                s.push_str(tcp.to_string().as_str());
            }
            _ => {}
        }


        s.push_str("\r\n");
        if let Some(ext) = &self.ext_info {
            s.push_str(ext.as_str());
            s.push_str("\r\n");
        }
        return s;
    }
}

pub struct EthHdr {
    pub d_mac: [u8; 6],
    pub s_mac: [u8; 6],
    pub proto: u16,
}

impl EthHdr {
    pub fn to_string(&self) -> String {
        let mac_fmt = |mac: &[u8]| -> String{
            let mut dmac = String::from("");
            let mut idx = 0;
            while idx < 6 {
                dmac.push_str(format!("{:x}", mac[idx]).as_str());
                idx += 1;
                if idx != 6 {
                    dmac.push_str(":")
                }
            }
            return dmac;
        };

        let mut s = String::from("===== ether hdr =====\r\n");

        s.push_str(format!("dmac: {}\r\n", mac_fmt(&self.d_mac[0..6])).as_str());
        s.push_str(format!("smac: {}\r\n", mac_fmt(&self.s_mac[0..6])).as_str());
        match eth_type_map.get(&self.proto) {
            Some(p) => {
                s.push_str(format!("proto: {}\r\n", p).as_str());
            }
            None => {
                s.push_str(format!("proto: {}\r\n", self.proto.to_string()).as_str());
            }
        }
        return s;
    }
}

pub struct IP4Hdr {
    pub version: u8,
    pub ihl: u8,
    pub tos: u8,
    pub enc_f0: bool,
    pub enc_f1: bool,
    pub total_len: u16,
    pub id: u16,
    pub flag_re: bool,
    pub flag_df: bool,
    pub flag_mf: bool,
    pub frag_off: u16,
    pub ttl: u8,
    pub proto: u8,
    pub checksum: u16,
    pub saddr: u32,
    pub daddr: u32,
}

impl IP4Hdr {
    pub fn new_with_zero() -> IP4Hdr {
        return IP4Hdr {
            version: 0,
            ihl: 0,
            tos: 0,
            enc_f0: false,
            enc_f1: false,
            total_len: 0,
            id: 0,
            flag_re: false,
            flag_df: false,
            flag_mf: false,
            frag_off: 0,
            ttl: 0,
            proto: 0,
            checksum: 0,
            saddr: 0,
            daddr: 0,
        };
    }

    fn inet_aton(ip: u32) -> String {
        let mut s = String::new();
        s.push_str(format!("{}.", ip >> 24).as_str());
        s.push_str(format!("{}.", (ip >> 16) & 255).as_str());
        s.push_str(format!("{}.", (ip >> 8) & 255).as_str());
        s.push_str(format!("{}", ip & 255).as_str());
        return s;
    }

    pub fn to_string(&self) -> String {
        let mut s = String::from("====ip====\r\n");
        s.push_str(format!("version: {}\r\n", self.version).as_str());
        s.push_str(format!("header len: {}\r\n", self.ihl * 4).as_str());
        s.push_str(format!("tos: {}\r\n", self.tos).as_str());
        s.push_str(format!("enc flag: {}{}\r\n",
                           if self.enc_f0 { 1 } else { 0 }, if self.enc_f1 { 1 } else { 0 }).as_str());
        s.push_str(format!("total len: {}\r\n", self.total_len).as_str());
        s.push_str(format!("id: {}\r\n", self.id).as_str());
        s.push_str(format!("frag flag re|df|mf: {}{}{}\r\n",
                           if self.flag_re { 1 } else { 0 },
                           if self.flag_df { 1 } else { 0 },
                           if self.flag_mf { 1 } else { 0 }).as_str());
        s.push_str(format!("frag offset: {}\r\n", self.frag_off).as_str());
        s.push_str(format!("ttl: {}\r\n", self.ttl).as_str());
        if let Some(proto) = ip_proto_map.get(&self.proto) {
            s.push_str(format!("proto: {}\r\n", proto).as_str());
        } else {
            s.push_str(format!("proto: {}\r\n", self.proto).as_str());
        }
        s.push_str(format!("checksum: 0x{:x}\r\n", self.checksum).as_str());
        s.push_str(format!("saddr: {}\r\n", IP4Hdr::inet_aton(self.saddr)).as_str());
        s.push_str(format!("daddr: {}\r\n", IP4Hdr::inet_aton(self.daddr)).as_str());
        return s;
    }
}


pub struct IcmpData {
    pub typ: u8,
    pub code: u8,
    pub checksum: u16,
}

impl IcmpData {
    pub fn to_string(&self) -> String {
        let mut s = String::from("\r\n===icmp===\r\n");
        if let Some(typ) = icmp_type_map.get(&self.typ) {
            s.push_str(format!("type: {}\r\n", typ).as_str());
        } else {
            s.push_str(format!("type: {}\r\n", self.typ).as_str());
        }
        s.push_str(format!("code: {}\r\n", self.code).as_str());
        s.push_str(format!("checksum: 0x{:x}\r\n", self.checksum).as_str());
        return s;
    }
}

pub struct UdpHdr {
    pub sport: u16,
    pub dport: u16,
    pub len: u16,
    pub checksum: u16,
}

impl UdpHdr {
    pub fn to_string(&self) -> String {
        let mut s = String::from("\r\n===udp===\r\n");
        s.push_str(format!("sport: {}\r\n", self.sport).as_str());
        s.push_str(format!("dport: {}\r\n", self.dport).as_str());
        s.push_str(format!("len: {}\r\n", self.len).as_str());
        s.push_str(format!("checksum: 0x{:x}\r\n", self.checksum).as_str());
        return s;
    }
}

pub struct TcpHdr {
    pub sport: u16,
    pub dport: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_off: u8,
    pub flag_r0: bool,
    pub flag_r1: bool,
    pub flag_r2: bool,
    pub flag_ns: bool,
    pub flag_cwr: bool,
    pub flag_ece: bool,
    pub flag_ugr: bool,
    pub flag_ack: bool,
    pub flag_psh: bool,
    pub flag_rst: bool,
    pub flag_syn: bool,
    pub flag_fin: bool,
    pub win_size: u16,
    pub checksum: u16,
    pub urg_p: u16,
}

impl TcpHdr {
    pub fn new_from_zero() -> TcpHdr {
        return TcpHdr {
            sport: 0,
            dport: 0,
            seq_num: 0,
            ack_num: 0,
            data_off: 0,
            flag_r0: false,
            flag_r1: false,
            flag_r2: false,
            flag_ns: false,
            flag_cwr: false,
            flag_ece: false,
            flag_ugr: false,
            flag_ack: false,
            flag_psh: false,
            flag_rst: false,
            flag_syn: false,
            flag_fin: false,
            win_size: 0,
            checksum: 0,
            urg_p: 0,
        };
    }

    pub fn to_string(&self) -> String {
        let mut s = String::from("\r\n===tcp===\r\n");
        s.push_str(format!("sport: {}\r\n", self.sport).as_str());
        s.push_str(format!("dport: {}\r\n", self.dport).as_str());
        s.push_str(format!("seq num: {}\r\n", self.seq_num).as_str());
        s.push_str(format!("ack num: {}\r\n", self.ack_num).as_str());
        s.push_str(format!("data offset: {}\r\n", self.data_off).as_str());
        s.push_str(format!("flag re: {}|{}|{}\r\n",
                           if self.flag_r0 { 1 } else { 0 },
                           if self.flag_r1 { 1 } else { 0 },
                           if self.flag_r2 { 1 } else { 0 }).as_str());
        s.push_str(format!("flag ns|cwr|ece: {}|{}|{}\r\n",
                           if self.flag_ns { 1 } else { 0 },
                           if self.flag_cwr { 1 } else { 0 },
                           if self.flag_ece { 1 } else { 0 }).as_str());

        s.push_str(format!("flag urg|ack|psh|rst|syn|fin: {}|{}|{}|{}|{}|{}\r\n",
                           if self.flag_ugr { 1 } else { 0 },
                           if self.flag_ack { 1 } else { 0 },
                           if self.flag_psh { 1 } else { 0 },
                           if self.flag_rst { 1 } else { 0 },
                           if self.flag_syn { 1 } else { 0 },
                           if self.flag_fin { 1 } else { 0 }).as_str());
        s.push_str(format!("win size(before scale): {}\r\n", self.win_size).as_str());
        s.push_str(format!("checksum: 0x{:x}\r\n", self.checksum).as_str());
        s.push_str(format!("urg pointer: 0x{:x}\r\n", self.urg_p).as_str());
        return s;
    }
}