use lapin::{options::*, types::FieldTable, BasicProperties, Connection, ConnectionProperties};
use pnet::datalink::{self};
use pnet::packet::{ethernet::EthernetPacket, ipv4::Ipv4Packet, udp::UdpPacket, Packet};
use serde::{Deserialize, Serialize};
use structopt::StructOpt;
use tokio::sync::mpsc;
use tokio_amqp::LapinTokioExt;
use trust_dns_proto::op::{Message, MessageType};
use trust_dns_proto::rr::{RData, RecordType};

#[derive(StructOpt, Debug)]
#[structopt(name = "dns_sniffer")]
struct Opt {
    #[structopt(short, long)]
    ifname: String,
    #[structopt(short, long, default_value = "amqp://guest:guest@localhost:5672/%2f")]
    amqp_url: String,
    #[structopt(short, long, default_value = "dns_records")]
    queue_name: String,
}

#[derive(Serialize, Deserialize)]
struct DnsRecord {
    q: String,
    t: i32,
    a: String,
}

fn remove_trailing_dot(s: String) -> String {
    if s.ends_with('.') {
        s.trim_end_matches('.').to_string()
    } else {
        s.to_string()
    }
}

#[tokio::main]
async fn main() {
    let opt = Opt::from_args();
    let (tx, mut rx) = mpsc::channel(100);
    let amqp_url = opt.amqp_url.clone();
    let queue_name = opt.queue_name.clone();
    tokio::spawn(async move {
        consume_records(&mut rx, &amqp_url, &queue_name).await;
    });

    let interfaces = datalink::interfaces();

    let interface_name = opt.ifname;
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .expect("Network interface not found");

    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(ethernet_packet) = EthernetPacket::new(packet) {
                    handle_ethernet_packet(&ethernet_packet, &tx).await;
                }
            }
            Err(e) => {
                eprintln!("An error occurred while reading: {}", e);
            }
        }
    }
}

async fn handle_ethernet_packet<'a>(ethernet: &'a EthernetPacket<'a>, tx: &mpsc::Sender<String>) {
    if let Some(ipv4_packet) = Ipv4Packet::new(ethernet.payload()) {
        handle_ipv4_packet(&ipv4_packet, tx).await;
    }
}

async fn handle_ipv4_packet<'a>(ipv4: &'a Ipv4Packet<'a>, tx: &mpsc::Sender<String>) {
    if let Some(udp_packet) = UdpPacket::new(ipv4.payload()) {
        handle_udp_packet(&udp_packet, tx).await;
    }
}

async fn handle_udp_packet<'a>(udp: &'a UdpPacket<'a>, tx: &mpsc::Sender<String>) {
    if udp.get_source() == 53 {
        if let Ok(message) = Message::from_vec(udp.payload()) {
            if message.header().message_type() == MessageType::Response {
                for answer in message.answers() {
                    let mut q = "".to_string();
                    let mut t = 1;
                    let mut a = "".to_string();
                    let _record = match answer.record_type() {
                        RecordType::A => {
                            q = remove_trailing_dot(answer.name().to_string());
                            t = 1;
                            a = if let Some(RData::A(ip)) = answer.data() {
                                ip.to_string()
                            } else {
                                "".to_string()
                            };
                        }
                        RecordType::AAAA => {
                            q = remove_trailing_dot(answer.name().to_string());
                            t = 28;
                            a = if let Some(RData::AAAA(ip)) = answer.data() {
                                ip.to_string()
                            } else {
                                "".to_string()
                            };
                        }
                        RecordType::CNAME => {
                            q = remove_trailing_dot(answer.name().to_string());
                            t = 5;
                            a = if let Some(RData::CNAME(name)) = answer.data() {
                                remove_trailing_dot(name.to_string())
                            } else {
                                "".to_string()
                            };
                        }
                        _ => continue,
                    };

                    let dns_record = DnsRecord { q: q, t: t, a: a };

                    let data =
                        serde_json::to_string(&dns_record).expect("Failed to serialize record");
                    tx.send(data).await.expect("Failed to send record");
                }
            }
        }
    }
}

async fn consume_records(rx: &mut mpsc::Receiver<String>, amqp_url: &str, queue_name: &str) {
    // 连接到 RabbitMQ
    let conn = Connection::connect(amqp_url, ConnectionProperties::default().with_tokio())
        .await
        .expect("Failed to connect to RabbitMQ");
    let channel = conn
        .create_channel()
        .await
        .expect("Failed to create channel");

    // 声明队列
    channel
        .queue_declare(
            queue_name,
            QueueDeclareOptions::default(),
            FieldTable::default(),
        )
        .await
        .expect("Failed to declare queue");

    // 消费记录
    while let Some(record) = rx.recv().await {
        channel
            .basic_publish(
                "",
                queue_name,
                BasicPublishOptions::default(),
                record.as_bytes(),
                BasicProperties::default(),
            )
            .await
            .expect("Failed to publish message");
        println!("Published message: {}", record);
    }
}
