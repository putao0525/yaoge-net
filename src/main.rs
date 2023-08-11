fn main() {
    println!("Hello, world!");
}
use pnet::datalink;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;

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


    let value: u8 = 0x45;
    let upper: u8 = value >> 4;
    let lower: u8 = value & 0x0F;

    println!("Upper: 0x{:X}", upper);
    println!("Lower: 0x{:X}", lower);
}

#[test]
fn test02() {
    // 获取网络接口列表
    //NetworkInterface 对应物理网卡
    let interfaces = datalink::interfaces();

    // 遍历接口列表，输出MAC地址
    for interface in interfaces {
        if let Some(mac) = interface.mac {
            println!("Interface: {}, MAC Address: {}", interface.name, mac);
        }
    }
}

