use crate::encryption::EncryptionLayer;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use std::io;
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::{Mutex, oneshot};
use std::time::Duration;
use chrono::Local;
use std::fs::OpenOptions;
use std::io::Write;

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum MessageType {
    Data = 0x00,
    Ack = 0x01,
    Ping = 0x02,
    Pong = 0x03,
}

impl MessageType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::Data),
            0x01 => Some(Self::Ack),
            0x02 => Some(Self::Ping),
            0x03 => Some(Self::Pong),
            _ => None,
        }
    }
}

pub struct DeliveryControl {
    pending_acks: Mutex<HashMap<u32, oneshot::Sender<()>>>,
    next_seq: std::sync::atomic::AtomicU32,
    retransmission_count: u32,
}

impl DeliveryControl {
    pub fn new() -> Self {
        let count = std::env::var("RETRANSMISSION_COUNT")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(10);
            
        Self {
            pending_acks: Mutex::new(HashMap::new()),
            next_seq: std::sync::atomic::AtomicU32::new(1),
            retransmission_count: count,
        }
    }

    pub fn next_seq(&self) -> u32 {
        self.next_seq.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    pub async fn register_waiter(&self, seq: u32) -> oneshot::Receiver<()> {
        let (tx, rx) = oneshot::channel();
        self.pending_acks.lock().await.insert(seq, tx);
        rx
    }

    pub async fn notify_ack(&self, seq: u32) {
        let mut map = self.pending_acks.lock().await;
        if let Some(tx) = map.remove(&seq) {
            let _ = tx.send(());
        }
    }

    pub fn log_error(&self, message: &str) {
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open("noski_errors.log")
        {
            let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
            let _ = writeln!(file, "[{}] [DELIVERY] {}", timestamp, message);
        }
    }
}

pub struct EncryptedReader<R> {
    inner: R,
    encryption: Arc<Box<dyn EncryptionLayer>>,
    buffer: Vec<u8>,
    max_message_size: usize,
    signature: Option<Vec<u8>>,
    control: Arc<DeliveryControl>,
    seen_seqs: std::collections::HashSet<u32>,
}

impl<R: AsyncRead + Unpin> EncryptedReader<R> {
    pub fn new(inner: R, encryption: Arc<Box<dyn EncryptionLayer>>, max_message_size: usize, signature: Option<Vec<u8>>, control: Arc<DeliveryControl>) -> Self {
        Self {
            inner,
            encryption,
            buffer: Vec::new(),
            max_message_size,
            signature,
            control,
            seen_seqs: std::collections::HashSet::new(),
        }
    }

    pub async fn read_encrypted(&mut self, buf: &mut [u8]) -> io::Result<(usize, u32)> {
        if !self.buffer.is_empty() {
            let copy_len = self.buffer.len().min(buf.len());
            buf[..copy_len].copy_from_slice(&self.buffer[..copy_len]);
            self.buffer.drain(..copy_len);
            // Internal buffer doesn't have seq, return 0 or track it?
            // Usually we only have one message in buffer.
            return Ok((copy_len, 0));
        }

        loop {
            if let Some(ref sig) = self.signature {
                let mut sig_buf = vec![0u8; sig.len()];
                self.inner.read_exact(&mut sig_buf).await?;
                if sig_buf != *sig {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid signature"));
                }
            }

            let mut len_bytes = [0u8; 4];
            self.inner.read_exact(&mut len_bytes).await?;
            let len = u32::from_be_bytes(len_bytes) as usize;

            if len > self.max_message_size {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Message too large"));
            }

            let mut encrypted_data = vec![0u8; len];
            self.inner.read_exact(&mut encrypted_data).await?;

            let decrypted = self.encryption.decrypt(&encrypted_data)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

            if decrypted.len() < 5 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Package too small"));
            }

            let msg_type = MessageType::from_u8(decrypted[0])
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Unknown message type"))?;
            
            let seq = u32::from_be_bytes([decrypted[1], decrypted[2], decrypted[3], decrypted[4]]);
            let payload = &decrypted[5..];

            match msg_type {
                MessageType::Data => {
                    if seq != 0 && self.seen_seqs.contains(&seq) {
                        // Duplicate data, return 0 bytes but provide seq so relay loop sends ACK
                        return Ok((0, seq));
                    }
                    if seq != 0 {
                        self.seen_seqs.insert(seq);
                        // Simple cleanup to prevent unbounded growth
                        if self.seen_seqs.len() > 1000 {
                            let min_seq = *self.seen_seqs.iter().min().unwrap_or(&0);
                            self.seen_seqs.retain(|&s| s > min_seq || s == seq);
                        }
                    }

                    let copy_len = payload.len().min(buf.len());
                    buf[..copy_len].copy_from_slice(&payload[..copy_len]);
                    if payload.len() > buf.len() {
                        self.buffer.extend_from_slice(&payload[copy_len..]);
                    }
                    return Ok((copy_len, seq));
                }
                MessageType::Ack => {
                    self.control.notify_ack(seq).await;
                }
                MessageType::Ping => {
                    // PINGs need response. We return it to the caller to handle if they have the writer.
                    return Ok((0, seq | 0x80000000)); // Hack to signal PING
                }
                MessageType::Pong => {
                    self.control.notify_ack(seq).await;
                }
            }
        }
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}

pub struct EncryptedWriter<W> {
    inner: W,
    encryption: Arc<Box<dyn EncryptionLayer>>,
    signature: Option<Vec<u8>>,
    control: Arc<DeliveryControl>,
}

impl<W: AsyncWrite + Unpin> EncryptedWriter<W> {
    pub fn new(inner: W, encryption: Arc<Box<dyn EncryptionLayer>>, signature: Option<Vec<u8>>, control: Arc<DeliveryControl>) -> Self {
        Self {
            inner,
            encryption,
            signature,
            control,
        }
    }

    async fn write_raw(&mut self, msg_type: MessageType, seq: u32, payload: &[u8]) -> io::Result<()> {
        let mut data = Vec::with_capacity(5 + payload.len());
        data.push(msg_type as u8);
        data.extend_from_slice(&seq.to_be_bytes());
        data.extend_from_slice(payload);

        let encrypted = self.encryption.encrypt(&data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        let len = encrypted.len() as u32;
        if let Some(ref sig) = self.signature {
            self.inner.write_all(sig).await?;
        }
        self.inner.write_all(&len.to_be_bytes()).await?;
        self.inner.write_all(&encrypted).await?;
        self.inner.flush().await?;
        Ok(())
    }

    pub async fn write_encrypted(&mut self, buf: &[u8]) -> io::Result<usize> {
        let seq = self.control.next_seq();
        let mut attempts = 0;
        let max_attempts = self.control.retransmission_count;

        loop {
            let rx = self.control.register_waiter(seq).await;
            self.write_raw(MessageType::Data, seq, buf).await?;
            
            match tokio::time::timeout(Duration::from_secs(2), rx).await {
                Ok(_) => return Ok(buf.len()),
                Err(_) => {
                    attempts += 1;
                    let log_msg = format!("Retransmission attempt {}/{} for seq {}", attempts, max_attempts, seq);
                    self.control.log_error(&log_msg);
                    
                    if attempts >= max_attempts {
                        let fail_msg = format!("Delivery failed after {} attempts for seq {}", max_attempts, seq);
                        self.control.log_error(&fail_msg);
                        return Err(io::Error::new(io::ErrorKind::TimedOut, fail_msg));
                    }
                }
            }
        }
    }

    pub async fn send_ack(&mut self, seq: u32) -> io::Result<()> {
        self.write_raw(MessageType::Ack, seq, &[]).await
    }

    pub async fn send_ping(&mut self) -> io::Result<()> {
        let seq = self.control.next_seq();
        self.write_raw(MessageType::Ping, seq, &[]).await
    }

    pub async fn send_pong(&mut self, seq: u32) -> io::Result<()> {
        self.write_raw(MessageType::Pong, seq, &[]).await
    }


    pub fn into_inner(self) -> W {
        self.inner
    }
}
