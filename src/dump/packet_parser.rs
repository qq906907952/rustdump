use crate::dump::endian::{bigendian_u16, bigendian_u32};
use crate::dump::error::DumpErr;
use crate::dump::packet::{EthHdr, IcmpData, IP4Hdr, TcpHdr, UdpHdr};

pub struct EtherParser {}

// 从字节数组解析以太网头部
impl EtherParser {
    pub fn parse_eth_hdr(b: &[u8]) -> Result<EthHdr, DumpErr> {
        if b.len() < 14 {
            return Err(DumpErr { info: String::from("ether header len too short") });
        }
        let mut eth_hdr = EthHdr {
            d_mac: [0; 6],
            s_mac: [0; 6],
            proto: 0,
        };
        eth_hdr.d_mac.copy_from_slice(&b[0..6]);
        eth_hdr.s_mac.copy_from_slice(&b[6..12]);
        eth_hdr.proto = bigendian_u16(&b[12..14]);
        return Ok(eth_hdr);
    }
}

pub struct Ip4Parser {}

// 从字节数组解析以ipv4头部, 目前不支持ip option
impl Ip4Parser {
    pub fn parse_ip4_hdr(b: &[u8]) -> Result<IP4Hdr, DumpErr> {
        if b.len() < 20 {
            return Err(DumpErr { info: String::from("ip header len too short") });
        }
        let mut ip_hdr = IP4Hdr::new_with_zero();
        ip_hdr.version = b[0] & 0b1111;
        ip_hdr.ihl = b[0] & 0b1111;
        ip_hdr.tos = b[1] & 0b111111;
        ip_hdr.enc_f0 = (b[1] >> 1) & 1 == 1;
        ip_hdr.enc_f1 = b[1] & 1 == 1;
        ip_hdr.total_len = bigendian_u16(&b[2..=3]);
        ip_hdr.id = bigendian_u16(&b[4..=5]);
        ip_hdr.flag_re = b[6] & (1 << 7) == 1;
        ip_hdr.flag_df = b[6] & (1 << 6) == 1;
        ip_hdr.flag_mf = b[6] & (1 << 5) == 1;
        ip_hdr.frag_off = ((b[6] as u16 & 0b11111) << 8) + b[7] as u16;
        ip_hdr.ttl = b[8];
        ip_hdr.proto = b[9];
        ip_hdr.checksum = bigendian_u16(&b[10..=11]);
        ip_hdr.saddr = bigendian_u32(&b[12..=15]);
        ip_hdr.daddr = bigendian_u32(&b[16..=19]);
        return Ok(ip_hdr);
    }
}

pub struct IcmpParser {}

impl IcmpParser {
    pub fn parse_icmp(b: &[u8]) -> Result<IcmpData, DumpErr> {
        if b.len() < 4 {
            return Err(DumpErr { info: String::from("icmp data too short") });
        }
        let icmp = IcmpData {
            typ: b[0],
            code: b[1],
            checksum: bigendian_u16(&b[2..4]),
        };
        return Ok(icmp);
    }
}

pub struct UdpParser {}

impl UdpParser {
    pub fn parse_udp(b: &[u8]) -> Result<UdpHdr, DumpErr> {
        if b.len() < 8 {
            return Err(DumpErr { info: String::from("udp hdr len too short") });
        }
        let udp = UdpHdr {
            sport: bigendian_u16(&b[0..2]),
            dport: bigendian_u16(&b[2..4]),
            len: bigendian_u16(&b[4..6]),
            checksum: bigendian_u16(&b[6..8]),
        };
        return Ok(udp);
    }
}

pub struct TcpParser {}

impl TcpParser {
    pub fn parse_tcp(b: &[u8]) -> Result<TcpHdr, DumpErr> {
        if b.len() < 20 {
            return Err(DumpErr { info: String::from("") });
        }
        let mut tcp_hdr = TcpHdr::new_from_zero();

        tcp_hdr.sport = bigendian_u16(&b[0..2]);
        tcp_hdr.dport = bigendian_u16(&b[2..4]);
        tcp_hdr.seq_num = bigendian_u32(&b[4..8]);
        tcp_hdr.ack_num = bigendian_u32(&b[8..12]);
        tcp_hdr.data_off = b[12] >> 4;
        tcp_hdr.flag_r0 = b[12] & 0b00001000 == 0b00001000;
        tcp_hdr.flag_r1 = b[12] & 0b00000100 == 0b00000100;
        tcp_hdr.flag_r2 = b[12] & 0b00000010 == 0b00000010;
        tcp_hdr.flag_ns = b[12] & 0b00000001 == 0b00000001;
        tcp_hdr.flag_cwr = b[13] & 0b10000000 == 0b10000000;
        tcp_hdr.flag_ece = b[13] & 0b01000000 == 0b01000000;
        tcp_hdr.flag_ugr = b[13] & 0b00100000 == 0b00100000;
        tcp_hdr.flag_ack = b[13] & 0b00010000 == 0b00010000;
        tcp_hdr.flag_psh = b[13] & 0b00001000 == 0b00001000;
        tcp_hdr.flag_rst = b[13] & 0b00000100 == 0b00000100;
        tcp_hdr.flag_syn = b[13] & 0b00000010 == 0b00000010;
        tcp_hdr.flag_fin = b[13] & 0b00000001 == 0b00000001;
        tcp_hdr.win_size = bigendian_u16(&b[14..16]);
        tcp_hdr.checksum = bigendian_u16(&b[16..18]);
        tcp_hdr.urg_p = bigendian_u16(&b[18..20]);
        return Ok(tcp_hdr);
    }
}
