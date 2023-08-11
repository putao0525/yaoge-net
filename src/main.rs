fn main() {
    println!("Hello, world!");
}

use pnet::datalink;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use byteorder::{BigEndian, ByteOrder};
use pnet::datalink::MacAddr;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes, MutableEthernetPacket};


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