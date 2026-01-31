#[cfg(feature = "web")]
mod web_tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    use wa_core::web::{WebServerConfig, start_web_server};

    async fn fetch_health(addr: SocketAddr) -> std::io::Result<String> {
        let request = b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        let mut last_err = None;

        for _ in 0..50 {
            match TcpStream::connect(addr).await {
                Ok(mut stream) => {
                    stream.write_all(request).await?;
                    let mut buf = Vec::new();
                    stream.read_to_end(&mut buf).await?;
                    return Ok(String::from_utf8_lossy(&buf).to_string());
                }
                Err(err) => {
                    last_err = Some(err);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "server not ready")
        }))
    }

    #[tokio::test]
    async fn web_health_ephemeral_port() -> Result<(), Box<dyn std::error::Error>> {
        let server = start_web_server(WebServerConfig::default().with_port(0)).await?;
        let addr = server.bound_addr();

        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));

        let response = fetch_health(addr).await;
        let shutdown = server.shutdown().await;

        let response = response?;
        shutdown?;

        assert!(response.contains("200"));
        assert!(response.contains("\"ok\":true"));
        Ok(())
    }
}
