use super::{Finding, TIMEOUT, port};
use crate::contract::Source;
use reqwest::{Client, header, redirect, retry};
use scraper::{Html, Selector};
use serde_json::json;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::LazyLock;

const MAX_BODY: usize = 65_536;

static CLIENT: LazyLock<Result<Client, reqwest::Error>> = LazyLock::new(|| {
    Client::builder()
        .no_proxy()
        .redirect(redirect::Policy::none())
        .retry(retry::never())
        .http1_only()
        .tls_danger_accept_invalid_certs(true)
        .tls_danger_accept_invalid_hostnames(true)
        .tls_certs_only([])
        .timeout(TIMEOUT)
        .build()
});

pub async fn probe(target: Ipv4Addr, number: u16, tls: bool) -> Result<Option<Finding>, String> {
    let source = if tls { Source::Https } else { Source::Http };
    let protocol = source.label();
    let client = CLIENT
        .as_ref()
        .map_err(|_| "HTTP discovery client initialization failed".to_string())?;
    crate::traffic::wait().await;
    let mut response = match client
        .get(format!("{protocol}://{target}:{number}/"))
        .header(header::ACCEPT_ENCODING, "identity")
        .header(header::CONNECTION, "close")
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) if error.is_timeout() => {
            return Err(format!(
                "{protocol} request to TCP port {number} timed out: {error}"
            ));
        }
        Err(error) if error.is_connect() => return Ok(None),
        Err(error) => {
            return Err(format!(
                "{protocol} request to {target}:{number} failed before an HTTP response: {error}"
            ));
        }
    };
    let status = response.status().as_u16();
    let server = response
        .headers()
        .get(header::SERVER)
        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned());
    let mut body = Vec::new();
    let mut warnings = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                let remaining = MAX_BODY - body.len();
                body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
                if chunk.len() > remaining {
                    warnings.push(
                        "HTTP title collection limited to the first 65536 body bytes.".into(),
                    );
                    break;
                }
            }
            Ok(None) => break,
            Err(_) => {
                warnings.push("HTTP body collection failed or timed out; response status and Server header retained.".into());
                break;
            }
        }
    }
    let raw = json!({
        "protocol": protocol,
        "port": number,
        "tls": tls,
        "certificateValidation": if tls { Some(false) } else { None },
        "statusCode": status,
        "title": title(&body),
        "server": server,
    });
    Ok(Some(Finding {
        source,
        fields: BTreeMap::from([("protocols".into(), json!([protocol]))]),
        raw: raw.clone(),
        ports: vec![port("tcp", number, source, raw)],
        warnings,
    }))
}

fn title(body: &[u8]) -> Option<String> {
    let document = Html::parse_document(&String::from_utf8_lossy(body));
    let selector = Selector::parse("head > title").ok()?;
    let text = document
        .select(&selector)
        .next()?
        .text()
        .collect::<String>();
    let title = text.split_whitespace().collect::<Vec<_>>().join(" ");
    (!title.is_empty()).then(|| title.chars().take(1024).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn extracts_html_title_without_matching_comments_scripts_or_svg_titles() {
        assert_eq!(
            title(b"<!-- <title>fake</title> --><script>let x = '<title>fake</title>';</script><TITLE class='x'> Control &amp;\nPanel &#169; </TITLE>"),
            Some("Control & Panel ©".into())
        );
        assert_eq!(
            title(b"<html><body><svg><title>icon</title></svg></body></html>"),
            None
        );
        assert_eq!(title(b"<title> \t </title>"), None);
        assert_eq!(title(b"plain text"), None);
    }

    async fn serve(response: Vec<u8>) -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let number = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            let count = stream.read(&mut request).await.unwrap();
            assert!(request[..count].starts_with(b"GET / HTTP/1.1\r\n"));
            assert!(!String::from_utf8_lossy(&request[..count]).contains("authorization:"));
            let _ = stream.write_all(&response).await;
        });
        (number, task)
    }

    #[tokio::test]
    async fn retains_error_status_title_and_server_without_following_redirects() {
        for status in ["404 Not Found", "302 Found"] {
            let (number, task) = serve(format!("HTTP/1.1 {status}\r\nServer: Embedded/1.2\r\nLocation: http://127.0.0.1:1/outside\r\nConnection: close\r\n\r\n<title>Device &amp; UI</title>").into_bytes()).await;
            let finding = probe(Ipv4Addr::LOCALHOST, number, false)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                finding.raw["statusCode"],
                status[..3].parse::<u16>().unwrap()
            );
            assert_eq!(finding.raw["title"], "Device & UI");
            assert_eq!(finding.raw["server"], "Embedded/1.2");
            assert_eq!(finding.source, Source::Http);
            assert_eq!(serde_json::to_value(finding.source).unwrap(), "http");
            assert_eq!(finding.fields["protocols"], json!(["http"]));
            assert_eq!(finding.raw["protocol"], "http");
            assert_eq!(finding.ports[0].source, "http");
            assert_eq!(finding.ports[0].key, format!("tcp:{number}"));
            assert!(finding.warnings.is_empty());
            task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn retains_headers_when_body_is_truncated_or_oversized() {
        for response in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nServer: Device\r\n\r\n".to_vec(),
            [
                b"HTTP/1.1 200 OK\r\nServer: Device\r\nConnection: close\r\n\r\n".as_slice(),
                &vec![b'x'; MAX_BODY + 1],
            ]
            .concat(),
        ] {
            let (number, task) = serve(response).await;
            let finding = probe(Ipv4Addr::LOCALHOST, number, false)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(finding.raw["statusCode"], 200);
            assert_eq!(finding.raw["server"], "Device");
            assert!(finding.raw["title"].is_null());
            assert_eq!(finding.warnings.len(), 1);
            task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn https_accepts_untrusted_certificate_with_wrong_hostname() {
        let identity =
            native_tls::Identity::from_pkcs12(include_bytes!("fixtures/https-identity.p12"), "")
                .unwrap();
        let acceptor =
            tokio_native_tls::TlsAcceptor::from(native_tls::TlsAcceptor::new(identity).unwrap());
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let number = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            let mut request = [0; 4096];
            let count = stream.read(&mut request).await.unwrap();
            assert!(request[..count].starts_with(b"GET / HTTP/1.1\r\n"));
            stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nServer: TLS Device\r\nContent-Length: 25\r\n\r\n<title>TLS Panel</title>\n").await.unwrap();
        });
        let finding = probe(Ipv4Addr::LOCALHOST, number, true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(finding.raw["protocol"], "https");
        assert_eq!(finding.source, Source::Https);
        assert_eq!(serde_json::to_value(finding.source).unwrap(), "https");
        assert_eq!(finding.fields["protocols"], json!(["https"]));
        assert_eq!(finding.ports[0].source, "https");
        assert_eq!(finding.raw["statusCode"], 503);
        assert_eq!(finding.raw["title"], "TLS Panel");
        assert_eq!(finding.raw["server"], "TLS Device");
        assert_eq!(finding.raw["certificateValidation"], false);
        assert!(finding.warnings.is_empty());
        task.await.unwrap();
    }

    #[tokio::test]
    async fn closed_tcp_port_is_no_response() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let number = listener.local_addr().unwrap().port();
        drop(listener);

        // Windows may reach the request deadline before reporting connection refusal.
        match probe(Ipv4Addr::LOCALHOST, number, false).await {
            Ok(finding) => assert!(finding.is_none()),
            Err(error) => assert!(super::super::timed_out(&error), "{error}"),
        }
    }

    #[tokio::test]
    async fn silent_listener_retains_timeout_diagnostic() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let number = listener.local_addr().unwrap().port();

        let result = probe(Ipv4Addr::LOCALHOST, number, false).await;
        drop(listener);

        let error = result.err().expect("silent listener must time out");
        assert!(super::super::timed_out(&error), "{error}");
        assert!(error.contains(&format!("TCP port {number}")), "{error}");
    }

    #[tokio::test]
    async fn malformed_http_response_is_reported_without_a_finding() {
        let (number, responder) = serve(b"not an HTTP response\r\n\r\n".to_vec()).await;

        let error = probe(Ipv4Addr::LOCALHOST, number, false)
            .await
            .err()
            .expect("malformed response must be rejected");

        assert!(error.contains("failed before an HTTP response"), "{error}");
        responder.await.unwrap();
    }
}
