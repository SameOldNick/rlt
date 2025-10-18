use tokio::net::TcpStream;

pub struct Tunnel {
    pub stream: TcpStream,
    pub endpoint: String,
}

impl Tunnel {
    pub fn new(stream: TcpStream, endpoint: String) -> Self {
        Tunnel { stream, endpoint }
    }
}
