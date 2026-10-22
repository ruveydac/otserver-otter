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
    let protocol = if tls { "https" } else { "http" };
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
        Err(error) if error.is_connect() || error.is_timeout() => return Ok(None),
        Err(_) => {
            return Err(format!(
                "HTTP discovery {target}:{number}: invalid response"
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
        source: Source::Unknown,
        fields: BTreeMap::from([("protocols".into(), json!([protocol]))]),
        raw: raw.clone(),
        ports: vec![port("tcp", number, Source::Unknown, raw)],
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
        let identity = native_tls::Identity::from_pkcs8(
            b"-----BEGIN CERTIFICATE-----
MIIDETCCAfmgAwIBAgIUaI45fMisED+mWzXzJpmQgpUDltcwDQYJKoZIhvcNAQEL
BQAwGDEWMBQGA1UEAwwNd3JvbmcuZXhhbXBsZTAeFw0yNjEwMjEyMDM0MzFaFw0y
NjEwMjIyMDM0MzFaMBgxFjAUBgNVBAMMDXdyb25nLmV4YW1wbGUwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDBjnfA0yfAONcj04tRa2PpWyJEQWLDnFuZ
jZajCRVXVqTJfytYwh0betIMJEX7IDXbjELkQs5eKP5FygNh2pO+c9KGF69v1HlA
UNJBlEGgbsxp4Clwfso9OOvtHD8sDJ63KSP1+2jQ6QvbSM3d3NNpPPPG+uzo0oMd
ez+mdjMh1tezbeXkBaqJ1NXpqFn8ItRtWRSyTuimqZf1dpVproWq/OWPxyi2ML55
ZhzXUd0t5hwgsGJ3nqeuNiuQ6r6agz2/tB/y2QA0lNe7CXawSaU7SiEidtJeClnL
XVEgv1PIFcJPGHW2asnYeW5AR/thR/nZZMK8tprdYc0q51RKFc2vAgMBAAGjUzBR
MB0GA1UdDgQWBBTXRf1TPbEOfXtuvmuYynwMzOxkojAfBgNVHSMEGDAWgBTXRf1T
PbEOfXtuvmuYynwMzOxkojAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUA
A4IBAQASSg6Qg6Z2x0GyYb/xA9UWi9u4M8CWaogqZIsgxZK9z56oOdpT7BZQlPwl
BT47K9t8c9vTLvscJnUa2N08pqwOAXR3MwcdfqwqXl7qTovqSdKQ6RCEDlbn1zz7
ZiTPQ4QAa+d2At9GXzdYlMWfpQUiye5DQKoI8sPFccLol/uhWFdUbZES1SWUb4ei
abicFkYCa98dGKaW1riYbn8xtx+YUJhcvhWaCbLwkeJkNeg0cAIMyPVtpIez8zHx
+G5SRurnR1WXSWLQncr/StcslD8lQOVqnCRkzJchasK1Hn5tXEQDKhj5RUYFdvzM
Rn6qZEtPslPCwCbQxFU2RvHgSyev
-----END CERTIFICATE-----",
            b"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDBjnfA0yfAONcj
04tRa2PpWyJEQWLDnFuZjZajCRVXVqTJfytYwh0betIMJEX7IDXbjELkQs5eKP5F
ygNh2pO+c9KGF69v1HlAUNJBlEGgbsxp4Clwfso9OOvtHD8sDJ63KSP1+2jQ6Qvb
SM3d3NNpPPPG+uzo0oMdez+mdjMh1tezbeXkBaqJ1NXpqFn8ItRtWRSyTuimqZf1
dpVproWq/OWPxyi2ML55ZhzXUd0t5hwgsGJ3nqeuNiuQ6r6agz2/tB/y2QA0lNe7
CXawSaU7SiEidtJeClnLXVEgv1PIFcJPGHW2asnYeW5AR/thR/nZZMK8tprdYc0q
51RKFc2vAgMBAAECggEAAanrLER5t6nwFNDBW9Ej1LesfbsKJvWgcUYe9gZ39n46
Kw6QHX0y/tokFWf3v1wxhPzu/kNMvtEfY74uypffDpNe9eQc5UXa8ks/jhdre6ji
0kN+V7HfTyi+w7+rE1fbGBFJy9gouH2oVRmKcM5wdXEer1Es2Xt7Fl/JgPF3KGKf
4tdrriDInP/sfkEnL9yybn/JAbt44O/y25kADfFxZjpWmcFM50JAhB18hBmgN7YK
6ePJx0tD5AMqpfP32yk8uMzt+LLG9lXBaXB9q+QW1xXDML1IdFwLc6E62IrUWbqI
Een/TeOtJ9dK/kcSJ2osSlJqouWwR+vJcdjrJk2CEQKBgQDi+ppIPlDvTKd+FrDM
YjsRl/VAxjAmcaq/Lsu4xU80snW+zkRn4UZUGh7RVJhWlXCGz25634flbqJo5o/A
qSU61feZF9lzkDdUohzuI2rQWWMqUorMdUQLjp61zMWTlruL469mTFtRgJEVwCyU
v81zJB0dDmnVe6bVmsSIFKS66wKBgQDaTeTzSWVSg4W8BbjKo/SnoS67TIvZWUcL
Rfl8en1OFz75RQot8hShCnLv5vCFFEBIF/t3T4Kt+bgeQY35y020bfwZqBBdyLJ0
nkUZMOE51wZYviKedbn4WE6ZT5QoKCpvx3qvH/7wOznD8WJmaPrPzJbjy9eYuKYM
VJdJYa1/TQKBgGdPEsvQ+TuB0zZTk5LjHumKFYmu6xmEYOf1n6nwvHVKyMbY0U/K
vBzpap9ydofqKrZhUXLBrPPjYC6IymMxWY2m97QJo+KygEyYILzPB/3ewYDw4tXe
heMQvfIXStI7KA+qyRmxpVq6Ps78kg3+Ir/Gby3bcpZFWpEciVk6tCOTAoGBAI12
7setJ0iqTC6EsrQ2PSOnsqXTO8j0LrKifMLqiWria3+S+r69Yhrdr4/A4toKPoG5
cM5nKvLcoTCSIJPf6BHlN/nUTA7KMMKbkYF6iGk36zf0tnBjL8k8SGrXA9Zl+OII
rXrwy/8XEh7kvHRK0UV5ecpSXPrtpUTWSFdYQdr9AoGBAJ1idvo4vQ68kvNu/S6z
I4AuOvPRgb+pZb0iXjzCSmvpBIGu/BDArq8YIVTwtmNfI3aJtfiWbng0+VQGtBE+
8THUTv7uQKRnjfygWX6iaIXCqVdvvm+FWLovdpm7hefCNWcUJtXHnTM0O1H9laK/
pDon0C2DRskV0xL08aDWMDQi
-----END PRIVATE KEY-----",
        )
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
        assert_eq!(finding.raw["statusCode"], 503);
        assert_eq!(finding.raw["title"], "TLS Panel");
        assert_eq!(finding.raw["server"], "TLS Device");
        assert_eq!(finding.raw["certificateValidation"], false);
        assert!(finding.warnings.is_empty());
        task.await.unwrap();
    }
}
