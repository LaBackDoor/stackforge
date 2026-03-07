#![no_main]
use libfuzzer_sys::fuzz_target;
use stackforge_core::layer::{
    Layer, LayerIndex, LayerKind,
    arp::ArpLayer,
    ethernet::EthernetLayer,
    icmp::IcmpLayer,
    ipv4::Ipv4Layer,
    tcp::TcpLayer,
    udp::UdpLayer,
};
use stackforge_core::layer::quic::QuicLayer;
use stackforge_core::layer::mqtt::MqttLayer;
use stackforge_core::layer::modbus::ModbusLayer;

fuzz_target!(|data: &[u8]| {
    let end = data.len();

    if end >= 14 {
        let eth = EthernetLayer::new(0, 14);
        let _ = eth.summary(data);
        let _ = eth.dst(data);
        let _ = eth.src(data);
        let _ = eth.ethertype(data);
    }

    if end >= 20 {
        let ip = Ipv4Layer::new(0, 20);
        let _ = ip.summary(data);
        let _ = ip.src(data);
        let _ = ip.dst(data);
        let _ = ip.protocol(data);
        let _ = ip.ttl(data);
    }

    if end >= 28 {
        let arp = ArpLayer::new(0, 28);
        let _ = arp.summary(data);
    }

    if end >= 20 {
        let tcp = TcpLayer::new(0, 20);
        let _ = tcp.summary(data);
        let _ = tcp.sport(data);
        let _ = tcp.dport(data);
        let _ = tcp.seq(data);
        let _ = tcp.flags(data);
    }

    if end >= 8 {
        let udp = UdpLayer::new(LayerIndex::new(LayerKind::Udp, 0, 8));
        let _ = udp.summary(data);
        let _ = udp.src_port(data);
        let _ = udp.dst_port(data);
    }

    if end >= 8 {
        let icmp = IcmpLayer::new(LayerIndex::new(LayerKind::Icmp, 0, end));
        let _ = icmp.summary(data);
    }

    if end >= 5 {
        let quic = QuicLayer::new(0, end);
        let _ = quic.summary(data);
    }

    if end >= 2 {
        let mqtt = MqttLayer::new(LayerIndex::new(LayerKind::Mqtt, 0, end));
        let _ = mqtt.summary(data);
    }

    if end >= 8 {
        let modbus = ModbusLayer::new(LayerIndex::new(LayerKind::Modbus, 0, end));
        let _ = modbus.summary(data);
    }
});
