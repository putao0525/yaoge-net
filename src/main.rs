fn main() {
    println!("Hello, world!");
}

use pnet::datalink;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::{MutablePacket, Packet};
use byteorder::{BigEndian, ByteOrder};
use pnet::datalink::MacAddr;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes, MutableEthernetPacket};
use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::util::checksum;
use pnet::transport::{icmp_packet_iter, transport_channel};
use pnet::transport::TransportChannelType::Layer3;


/**
构建一个IP数据包
 */
#[test]
fn test01() {
    // 假设您已经有了一个IP包的字节数组data
    let data: [u8; 20] = [0x45, 0x00, 0x00, 0x28, 0xab, 0xcd, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01, 0xc0, 0xa8, 0x01, 0x02];

    // 解析IP包
    if let Some(ipv4_packet) = Ipv4Packet::new(&data) {
        // 打印IP包的各个部分信息
        println!("Version: {}", ipv4_packet.get_version());
        println!("Header Length: {}", ipv4_packet.get_header_length());
        println!("Total Length: {}", ipv4_packet.get_total_length());
        println!("Identification: {}", ipv4_packet.get_identification());
        println!("Flags: {}", ipv4_packet.get_flags());
        println!("Fragment Offset: {}", ipv4_packet.get_fragment_offset());
        println!("Time To Live: {}", ipv4_packet.get_ttl());
        println!("Protocol: {:?}", ipv4_packet.get_next_level_protocol());
        println!("Source IP: {}", ipv4_packet.get_source());
        println!("Destination IP: {}", ipv4_packet.get_destination());
    }

    //大端小端
    let value: u8 = 0x45;
    let upper: u8 = value >> 4;
    let lower: u8 = value & 0x0F;

    println!("Upper: 0x{:X}", upper);
    println!("Lower: 0x{:X}", lower);
}

/**
输出mac地址
 */
#[test]
fn test02() {
    // 获取网络接口列表
    //NetworkInterface 对应物理网卡
    let interfaces = datalink::interfaces();

    // 遍历接口列表，输出MAC地址
    for interface in interfaces {
        //可以debug
        if let Some(mac) = interface.mac {
            println!("Interface: {}, MAC Address: {}", interface.name, mac);
        }
    }
}

/**
构建数据帧
 */
#[test]
fn test03() {
    let mut frame = vec![0u8; 14]; // 14字节的以太网帧
    // 目标MAC地址
    frame[0..6].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    // 源MAC地址
    frame[6..12].copy_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]);
    // 类型/长度字段
    BigEndian::write_u16(&mut frame[12..14], 0x0800); // IPv4的类型值
    // 在这里可以添加更多的字段，如IP头部、TCP/UDP头部等
    // 打印数据帧
    for byte in &frame {
        print!("{:02X} ", byte);
    }
    println!();
}

/**
构建数据帧
 */
#[test]
fn test04() {
    // 创建一个MutableEthernetPacket对象
    let mut packet = MutableEthernetPacket::owned(vec![0; EthernetPacket::minimum_packet_size()]).unwrap();
    // 设置数据帧的源MAC地址、目标MAC地址和以太网类型
    packet.set_source(MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55));
    packet.set_destination(MacAddr::new(0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB));
    packet.set_ethertype(EtherTypes::Ipv4);

    // 构建数据帧
    let ethernet_packet = EthernetPacket::new(packet.packet()).unwrap();

    // 打印数据帧的源MAC地址、目标MAC地址和以太网类型
    println!("源MAC地址: {:?}", ethernet_packet.get_source());
    println!("目标MAC地址: {:?}", ethernet_packet.get_destination());
    println!("以太网类型: {:?}", ethernet_packet.get_ethertype());
}

/**
解析数据帧
 */
#[test]
fn test05() {
    let data: [u8; 14] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // 源MAC地址
        0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, // 目标MAC地址
        0x08, 0x00 // 以太网类型（IPv4）
    ];
    let ethernet_packet = EthernetPacket::new(&data).unwrap();
    let source_mac = ethernet_packet.get_source();
    let destination_mac = ethernet_packet.get_destination();
    let ethertype = ethernet_packet.get_ethertype();
    println!("源MAC地址: {:?}", source_mac);
    println!("目标MAC地址: {:?}", destination_mac);
    println!("以太网类型: {:?}", ethertype);
}

#[test]
fn test06() {
    // 获取网络接口
    let interface_name = "eth0";
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .expect("Failed to find network interface");

    // 构建ARP请求包
    let source_mac = MacAddr::zero();
    let source_ip = [192, 168, 0, 1];
    let target_ip = [192, 168, 0, 2];
    let mut buffer = [0u8; 42];
    let mut ethernet_packet = EthernetPacket::new(&mut buffer[..]).unwrap();
    ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(source_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = ArpPacket::new(&mut arp_buffer).unwrap();
    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(source_mac);
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);

    ethernet_packet.set_payload(arp_packet.packet_mut());

    // 发送ARP请求包
    let (mut tx, _) = match datalink::channel(&interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unsupported channel type"),
        Err(e) => panic!("Failed to create channel: {}", e),
    };
    tx.send_to(ethernet_packet.packet(), None).expect("Failed to send packet");

    // 接收ARP响应包
    let mut rx_buffer = [0u8; 1500];
    loop {
        match tx.recv_from(&mut rx_buffer) {
            Ok((size, _)) => {
                let ethernet_packet = EthernetPacket::new(&rx_buffer[..size]).unwrap();
                if ethernet_packet.get_ethertype() == EtherTypes::Arp {
                    let arp_packet = ArpPacket::new(ethernet_packet.payload()).unwrap();
                    if arp_packet.get_operation() == ArpOperations::Reply
                        && arp_packet.get_target_proto_addr() == source_ip
                    {
                        println!("Received ARP reply: {:?}", arp_packet);
                        break;
                    }
                }
            }
            Err(e) => panic!("Failed to receive packet: {}", e),
        }
    }
}

#[test]
fn test07() {
    // 获取网络接口
    let interface_name = "eth0";
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .expect("Failed to find network interface");

    // 构建ICMP请求包
    let source_ip = [192, 168, 0, 1];
    let target_ip = [192, 168, 0, 2];
    let mut buffer = [0u8; 42];
    let mut ipv4_packet = MutableIpv4Packet::new(&mut buffer[..]).unwrap();
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(5);
    ipv4_packet.set_total_length(42);
    ipv4_packet.set_identification(0);
    ipv4_packet.set_ttl(64);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ipv4_packet.set_source(source_ip.into());
    ipv4_packet.set_destination(target_ip.into());

    let mut icmp_buffer = [0u8; 8];
    let mut icmp_packet = echo_request::MutableEchoRequestPacket::new(&mut icmp_buffer).unwrap();
    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
    icmp_packet.set_identifier(0);
    icmp_packet.set_sequence_number(0);
    icmp_packet.set_payload(b"Hello ICMP");

    let checksum = checksum(&icmp_packet.packet(), 1);
    icmp_packet.set_checksum(checksum);

    ipv4_packet.set_payload(icmp_packet.packet_mut());

    // 发送ICMP请求包
    let (mut tx, _) = match datalink::channel(&interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unsupported channel type"),
        Err(e) => panic!("Failed to create channel: {}", e),
    };
    tx.send_to(ipv4_packet.packet(), None)
        .expect("Failed to send packet");

    // 接收ICMP响应包
    let mut rx_buffer = [0u8; 1500];
    loop {
        match tx.recv_from(&mut rx_buffer) {
            Ok((size, _)) => {
                let ipv4_packet = Ipv4Packet::new(&rx_buffer[..size]).unwrap();
                if ipv4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
                    let icmp_packet = echo_reply::EchoReplyPacket::new(ipv4_packet.payload()).unwrap();
                    if icmp_packet.get_icmp_type() == IcmpTypes::EchoReply
                        && icmp_packet.get_destination_ip() == source_ip
                    {
                        println!("Received ICMP reply: {:?}", icmp_packet);
                        break;
                    }
                }
            }
            Err(e) => panic!("Failed to receive packet: {}", e),
        }
    }
}