//! Production transport bounds, exercised against owned loopback listeners
//! through the isolated test seam.

use std::net::SocketAddr;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;

use super::*;
use crate::transport::HttpsTransport;

fn limits() -> TransportLimits {
    TransportLimits {
        request_timeout: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(5),
        max_response_bytes: 1_024,
        max_hint_bytes: 256,
    }
}

fn loopback(address: SocketAddr, limits: TransportLimits) -> HttpsTransport {
    HttpsTransport::loopback_for_tests(
        address,
        ApiKey::new(ADMIN_KEY.to_string()).expect("admin key"),
        ApiKey::new(INVOICE_KEY.to_string()).expect("invoice key"),
        limits,
    )
    .expect("loopback transport")
}

/// Read one HTTP/1.1 request head and its body.
async fn read_request(socket: &mut TcpStream) -> String {
    let mut data = Vec::new();
    let mut buffer = [0_u8; 1_024];
    loop {
        let read = socket.read(&mut buffer).await.expect("read request");
        if read == 0 {
            break;
        }
        data.extend_from_slice(&buffer[..read]);
        let text = String::from_utf8_lossy(&data).to_string();
        if let Some(head_end) = text.find("\r\n\r\n") {
            let length = text[..head_end]
                .lines()
                .find_map(|line| {
                    let lower = line.to_ascii_lowercase();
                    lower
                        .strip_prefix("content-length:")
                        .map(|value| value.trim().parse::<usize>().expect("length"))
                })
                .unwrap_or(0);
            if data.len() >= head_end + 4 + length {
                return text;
            }
        }
    }
    String::from_utf8_lossy(&data).to_string()
}

/// Serve scripted responses, one per connection, and return each request.
async fn serve(responses: Vec<Vec<u8>>) -> (SocketAddr, tokio::task::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    let handle = tokio::spawn(async move {
        let mut requests = Vec::new();
        for response in responses {
            let (mut socket, _) = listener.accept().await.expect("accept");
            requests.push(read_request(&mut socket).await);
            socket.write_all(&response).await.expect("write");
            socket.shutdown().await.expect("shutdown");
        }
        requests
    });
    (address, handle)
}

fn http(status: &str, headers: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\nconnection: close\r\ncontent-length: {}\r\n{headers}\r\n{body}",
        body.len()
    )
    .into_bytes()
}

#[test]
fn api_origin_requires_https_without_credentials_path_or_query() {
    assert!(ApiOrigin::parse("https://lnbits.example").is_ok());
    assert!(ApiOrigin::parse("https://lnbits.example:8443/").is_ok());
    for value in [
        "http://lnbits.example",
        "ws://lnbits.example",
        "https://user:pass@lnbits.example",
        "https://lnbits.example/wallet",
        "https://lnbits.example/?usr=1",
        "https://lnbits.example/#x",
        "not a url",
    ] {
        assert!(ApiOrigin::parse(value).is_err(), "{value} must be refused");
    }
}

#[test]
fn api_keys_are_validated_and_redacted() {
    let key = ApiKey::new(ADMIN_KEY.to_string()).expect("key");
    assert_eq!(format!("{key:?}"), "ApiKey([REDACTED])");
    let config = config(OutgoingPayments::Disabled);
    let shown = format!("{config:?}");
    assert!(!shown.contains(ADMIN_KEY));
    assert!(!shown.contains(INVOICE_KEY));
    for value in ["", "has space", "slash/key", "x".repeat(129).as_str()] {
        assert!(ApiKey::new(value.to_string()).is_err());
    }
}

#[tokio::test]
async fn status_read_uses_the_invoice_key_and_payment_uses_the_admin_key() {
    let (address, server) = serve(vec![
        http("200 OK", "", r#"{"paid":false}"#),
        http("201 Created", "", "{}"),
    ])
    .await;
    let transport = loopback(address, limits());

    let status = transport.get_payment("ab").await.expect("status reply");
    let paid = transport
        .pay_invoice(br#"{"out":true}"#.to_vec())
        .await
        .expect("payment reply");
    let requests = within(server).await.expect("server");

    assert_eq!(status.status, 200);
    assert_eq!(status.body, br#"{"paid":false}"#.to_vec());
    assert_eq!(paid.status, 201);
    assert!(requests[0].starts_with("GET /api/v1/payments/ab "));
    assert!(requests[0]
        .to_ascii_lowercase()
        .contains(&format!("x-api-key: {}", INVOICE_KEY.to_ascii_lowercase())));
    assert!(!requests[0].contains(ADMIN_KEY));
    assert!(requests[1].starts_with("POST /api/v1/payments "));
    assert!(requests[1]
        .to_ascii_lowercase()
        .contains(&format!("x-api-key: {}", ADMIN_KEY.to_ascii_lowercase())));
    assert!(!requests[1].contains(INVOICE_KEY));
}

#[tokio::test]
async fn fee_reserve_observation_sends_no_key() {
    let (address, server) = serve(vec![http("200 OK", "", r#"{"fee_reserve":1}"#)]).await;
    let transport = loopback(address, limits());

    transport.get_fee_reserve("lnbc1x").await.expect("reply");
    let requests = within(server).await.expect("server");

    assert!(requests[0].starts_with("GET /api/v1/payments/fee-reserve?invoice=lnbc1x "));
    assert!(!requests[0].to_ascii_lowercase().contains("x-api-key"));
}

#[tokio::test]
async fn redirects_are_not_followed() {
    let (address, server) = serve(vec![http(
        "302 Found",
        "location: /api/v1/elsewhere\r\n",
        "",
    )])
    .await;
    let transport = loopback(address, limits());

    let reply = transport.get_payment("ab").await.expect("reply");
    let requests = within(server).await.expect("server");

    assert_eq!(reply.status, 302);
    assert_eq!(requests.len(), 1);
}

#[tokio::test]
async fn oversized_bodies_are_refused() {
    let large = "x".repeat(2_048);
    let (address, server) = serve(vec![
        http("200 OK", "", &large),
        format!(
            "HTTP/1.1 200 OK\r\nconnection: close\r\ntransfer-encoding: chunked\r\n\r\n800\r\n{large}\r\n0\r\n\r\n"
        )
        .into_bytes(),
    ])
    .await;
    let transport = loopback(address, limits());

    let declared = transport.get_payment("ab").await;
    let chunked = transport.get_payment("ab").await;
    within(server).await.expect("server");

    assert_eq!(declared, Err(TransportError::BodyTooLarge));
    assert_eq!(chunked, Err(TransportError::BodyTooLarge));
}

#[tokio::test(start_paused = true)]
async fn a_silent_server_times_out() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    let (accepted_sender, accepted) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        let _ = accepted_sender.send(());
        // Hold the connection open without a reply until the client gives up.
        socket
    });
    let transport = loopback(address, limits());

    // The paused clock advances only when every task is idle, so the request
    // timeout fires without a real-time wait.
    let result = transport.get_payment("ab").await;

    assert_eq!(result.err(), Some(TransportError::Timeout));
    accepted.await.expect("accepted");
    drop(server.await.expect("server"));
}

// The handshake callback signature, including its large error type, is
// fixed by tungstenite.
#[allow(clippy::result_large_err)]
#[tokio::test]
async fn websocket_uses_the_invoice_key_path_and_bounds_message_size() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        let (path_sender, path) = std::sync::mpsc::channel();
        let mut socket = tokio_tungstenite::accept_hdr_async(
            socket,
            move |request: &tokio_tungstenite::tungstenite::handshake::server::Request,
                  response| {
                path_sender
                    .send(request.uri().path().to_string())
                    .expect("path");
                Ok(response)
            },
        )
        .await
        .expect("handshake");
        socket
            .send(Message::text("small hint"))
            .await
            .expect("send small");
        socket
            .send(Message::text("y".repeat(1_024)))
            .await
            .expect("send large");
        let path = path.recv().expect("path");
        // Wait for the client to close after it refuses the large message.
        while let Some(Ok(_)) = socket.next().await {}
        path
    });
    let transport = loopback(address, limits());

    let mut hints = transport.connect_hints().await.expect("connect");
    let first = within(hints.next()).await;
    let second = within(hints.next()).await;
    let third = within(hints.next()).await;
    drop(hints);
    let path = within(server).await.expect("server");

    assert_eq!(first, Some(Ok("small hint".to_string())));
    assert_eq!(second, Some(Err(TransportError::Protocol)));
    assert_eq!(third, None);
    assert_eq!(path, format!("/api/v1/ws/{INVOICE_KEY}"));
}
