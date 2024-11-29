use idna;
use lapin::{
    options::*, types::FieldTable, BasicProperties, Connection, ConnectionProperties,
    Result as LapinResult,
};
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::{ethernet::EthernetPacket, ipv4::Ipv4Packet, udp::UdpPacket, Packet};
use serde::{Deserialize, Serialize};
use std::{
    net::IpAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use structopt::StructOpt;
use tokio::sync::{mpsc, Mutex};
use trust_dns_proto::op::{Message, MessageType};
use trust_dns_proto::rr::{RData, RecordType};

const CHANNEL_SIZE: usize = 10000;
const PACKET_CHANNEL_SIZE: usize = 10000;
const RECONNECT_DELAY: Duration = Duration::from_secs(5);
const RETRY_ATTEMPTS: u32 = 3;

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

#[derive(Serialize, Deserialize, Debug, Clone)]
struct DnsRecord {
    q: String,
    t: i32,
    a: String,
    created_at: u64,
}

struct ConnectionManager {
    conn: Option<Connection>,
    url: String,
    reconnect_attempts: u32,
}

impl ConnectionManager {
    fn new(url: String) -> Self {
        Self {
            conn: None,
            url,
            reconnect_attempts: 0,
        }
    }

    async fn get_connection(&mut self) -> LapinResult<&Connection> {
        if self.conn.is_none() {
            self.conn = Some(
                Connection::connect(&self.url, ConnectionProperties::default())
                    .await?,
            );
            self.reconnect_attempts = 0;
            println!("Successfully connected to RabbitMQ");
        }
        Ok(self.conn.as_ref().unwrap())
    }

    async fn reconnect(&mut self) -> LapinResult<&Connection> {
        self.conn = None;
        self.reconnect_attempts += 1;
        println!("Attempting to reconnect (attempt {})", self.reconnect_attempts);
        tokio::time::sleep(RECONNECT_DELAY).await;
        self.get_connection().await
    }
}

#[inline]
fn process_domain(domain: &str) -> String {
    let domain = domain.trim_end_matches('.');
    idna::domain_to_ascii(domain).unwrap_or_else(|_| domain.to_string())
}

#[inline]
fn is_ip_address(s: &str) -> bool {
    s.parse::<IpAddr>().is_ok()
}

#[inline]
fn get_current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

async fn setup_interface(ifname: &str) -> Result<NetworkInterface, Box<dyn std::error::Error>> {
    datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == ifname)
        .ok_or_else(|| "Network interface not found".into())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::from_args();
    let (tx, rx) = mpsc::channel(CHANNEL_SIZE);
    let amqp_url = opt.amqp_url.clone();
    let queue_name = opt.queue_name.clone();

    println!("Starting DNS sniffer...");
    println!("Interface: {}", opt.ifname);
    println!("Queue: {}", queue_name);

    let consumer_handle = tokio::spawn(async move {
        if let Err(e) = consume_records(rx, &amqp_url, &queue_name).await {
            eprintln!("Error in consume_records: {}", e);
        }
    });

    let interface = setup_interface(&opt.ifname).await?;
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err("Unhandled channel type".into()),
        Err(e) => return Err(format!("Error creating datalink channel: {}", e).into()),
    };

    let (packet_tx, packet_rx) = mpsc::channel(PACKET_CHANNEL_SIZE);
    let packet_rx = Arc::new(Mutex::new(packet_rx));

    let packet_handle = std::thread::spawn(move || {
        while let Ok(packet) = rx.next() {
            if let Err(e) = packet_tx.blocking_send(packet.to_vec()) {
                eprintln!("Failed to send packet: {}", e);
                break;
            }
        }
    });

    let num_threads = num_cpus::get();
    println!("Starting {} packet processing threads", num_threads);

    let msg_sender = Arc::new(Mutex::new(tx));
    let mut handles = vec![];

    for thread_id in 0..num_threads {
        let packet_rx = Arc::clone(&packet_rx);
        let tx = Arc::clone(&msg_sender);
        
        let handle = tokio::spawn(async move {
            println!("Started packet processing thread {}", thread_id);
            
            loop {
                let packet = {
                    let mut rx = packet_rx.lock().await;
                    match rx.recv().await {
                        Some(packet) => packet,
                        None => break,
                    }
                };

                if let Some(ethernet_packet) = EthernetPacket::new(&packet) {
                    handle_ethernet_packet(&ethernet_packet, &tx).await;
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await?;
    }
    
    if let Err(e) = packet_handle.join() {
        eprintln!("Packet receiver thread panicked: {:?}", e);
    }
    consumer_handle.await?;

    Ok(())
}

async fn handle_ethernet_packet<'a>(
    ethernet: &'a EthernetPacket<'a>,
    tx: &Arc<Mutex<mpsc::Sender<String>>>,
) {
    if let Some(ipv4_packet) = Ipv4Packet::new(ethernet.payload()) {
        handle_ipv4_packet(&ipv4_packet, tx).await;
    }
}

async fn handle_ipv4_packet<'a>(
    ipv4: &'a Ipv4Packet<'a>,
    tx: &Arc<Mutex<mpsc::Sender<String>>>,
) {
    if let Some(udp_packet) = UdpPacket::new(ipv4.payload()) {
        handle_udp_packet(&udp_packet, tx).await;
    }
}

async fn handle_udp_packet<'a>(
    udp: &'a UdpPacket<'a>,
    tx: &Arc<Mutex<mpsc::Sender<String>>>,
) {
    if udp.get_source() != 53 {
        return;
    }

    if let Ok(message) = Message::from_vec(udp.payload()) {
        if message.header().message_type() != MessageType::Response {
            return;
        }

        let timestamp = get_current_timestamp();

        for answer in message.answers() {
            let record = match answer.record_type() {
                RecordType::A => {
                    let q = process_domain(&answer.name().to_string());
                    if let Some(RData::A(ip)) = answer.data() {
                        Some(DnsRecord {
                            q,
                            t: 1,
                            a: ip.to_string(),
                            created_at: timestamp,
                        })
                    } else {
                        None
                    }
                }
                RecordType::AAAA => {
                    let q = process_domain(&answer.name().to_string());
                    if let Some(RData::AAAA(ip)) = answer.data() {
                        Some(DnsRecord {
                            q,
                            t: 28,
                            a: ip.to_string(),
                            created_at: timestamp,
                        })
                    } else {
                        None
                    }
                }
                RecordType::CNAME => {
                    let q = process_domain(&answer.name().to_string());
                    if let Some(RData::CNAME(name)) = answer.data() {
                        let a = name.to_string();
                        Some(DnsRecord {
                            q,
                            t: 5,
                            a: if !is_ip_address(&a) {
                                process_domain(&a)
                            } else {
                                a
                            },
                            created_at: timestamp,
                        })
                    } else {
                        None
                    }
                }
                _ => None,
            };

            if let Some(record) = record {
                if let Ok(data) = serde_json::to_string(&record) {
                    let tx = tx.lock().await;
                    if let Err(e) = tx.send(data.clone()).await {
                        eprintln!("Failed to send record: {}", e);
                    }
                }
            }
        }
    }
}

async fn consume_records(
    mut rx: mpsc::Receiver<String>,
    amqp_url: &str,
    queue_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut conn_manager = ConnectionManager::new(amqp_url.to_string());

    loop {
        let conn = match conn_manager.get_connection().await {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("Failed to get connection: {}", e);
                if conn_manager.reconnect_attempts >= RETRY_ATTEMPTS {
                    return Err("Max reconnection attempts reached".into());
                }
                conn_manager.reconnect().await?;
                continue;
            }
        };

        let channel = conn.create_channel().await?;

        channel
            .queue_declare(
                queue_name,
                QueueDeclareOptions::default(),
                FieldTable::default(),
            )
            .await?;

        println!("Ready to process DNS records");

        while let Some(record) = rx.recv().await {
            match channel
                .basic_publish(
                    "",
                    queue_name,
                    BasicPublishOptions::default(),
                    record.as_bytes(),
                    BasicProperties::default(),
                )
                .await
            {
                Ok(_) => {
                    println!("Published record: {}", record);
                }
                Err(e) => {
                    eprintln!("Failed to publish record: {}", e);
                    conn_manager.reconnect().await?;
                    break;
                }
            }
        }
    }
}