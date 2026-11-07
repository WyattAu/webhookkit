//! Outbound webhook delivery (opt-in `send` feature).
//!
//! One signed `POST` per call — no retries. Retry policy is the caller's:
//! [`DeliveryOutcome::Rejected`] carries the status so the caller can
//! classify it (e.g. retry 5xx/429, fail on other 4xx) and feed the call
//! into a retry/backoff kit.
//!
//! Transport errors never carry the endpoint URL: webhook URLs are
//! credentials (a Slack webhook URL grants posting rights), so the
//! underlying `reqwest::Error` is scrubbed with `without_url` before its
//! message is kept.

use std::time::Duration;

/// What the endpoint answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryOutcome {
    /// 2xx — the endpoint accepted the payload.
    Delivered,
    /// A non-2xx status. Retryability is the caller's policy.
    Rejected(u16),
}

/// Transport-level failure of a delivery attempt. The endpoint URL is
/// scrubbed out of the message before it is stored.
#[derive(Debug)]
pub struct DeliveryError {
    message: alloc::string::String,
}

impl std::fmt::Display for DeliveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DeliveryError {}

impl DeliveryError {
    /// Materialize a reqwest failure without its URL.
    #[must_use]
    pub fn transport(err: reqwest::Error) -> Self {
        Self {
            message: err.without_url().to_string(),
        }
    }
}

/// `POST` `body` to `url` as `application/json` — one attempt, no retries.
///
/// `signature` is an optional `(header name, header value)` pair, e.g.
/// `Some(("X-My-Signature", webhookkit::sign_hmac_sha256(&body, &secret)))`.
/// `timeout` bounds the whole request; any 2xx is
/// [`DeliveryOutcome::Delivered`], any other status is
/// [`DeliveryOutcome::Rejected`] (not an error — classification is the
/// caller's policy).
///
/// # Errors
///
/// Returns [`DeliveryError`] only on transport failure (connect, send,
/// timeout), with the endpoint URL scrubbed.
pub async fn post_json(
    client: &reqwest::Client,
    url: &str,
    body: Vec<u8>,
    signature: Option<(&str, alloc::string::String)>,
    timeout: Duration,
) -> Result<DeliveryOutcome, DeliveryError> {
    let mut request = client
        .post(url)
        .header("Content-Type", "application/json")
        .timeout(timeout);
    if let Some((name, value)) = signature {
        request = request.header(name, value);
    }

    match request.body(body).send().await {
        Ok(response) => {
            let status = response.status();
            if status.is_success() {
                Ok(DeliveryOutcome::Delivered)
            } else {
                Ok(DeliveryOutcome::Rejected(status.as_u16()))
            }
        }
        Err(err) => Err(DeliveryError::transport(err)),
    }
}

#[cfg(test)]
// Test code: unwrap is the idiomatic way to assert outcomes.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Hermetic HTTP stub: one thread per connection, records the raw
    /// request head, replies with `status`.
    struct Stub {
        addr: std::net::SocketAddr,
    }

    impl Stub {
        fn spawn(status: u16) -> (Self, Arc<Mutex<Vec<String>>>) {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let requests = Arc::new(Mutex::new(Vec::new()));
            let sink = requests.clone();
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { continue };
                    let sink = sink.clone();
                    std::thread::spawn(move || {
                        use std::io::{Read, Write};
                        let mut buf = vec![0u8; 8192];
                        let n = stream.read(&mut buf).unwrap_or(0);
                        let text = String::from_utf8_lossy(&buf[..n]).to_string();
                        // Keep the request head only.
                        let head = text
                            .split("\r\n\r\n")
                            .next()
                            .unwrap_or_default()
                            .to_string();
                        sink.lock().unwrap().push(head);
                        let response = format!(
                            "HTTP/1.1 {status} TEST\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                        let _ = stream.write_all(response.as_bytes());
                    });
                }
            });
            (Self { addr }, requests)
        }
    }

    #[tokio::test]
    async fn posts_signed_json_and_reports_delivered() {
        let (stub, requests) = Stub::spawn(200);
        let secret = b"secret-a";
        let body = b"{\"k\":1}".to_vec();
        let signature = sign_hmac_sha256(&body, secret);

        let outcome = post_json(
            &reqwest::Client::new(),
            &format!("http://{}", stub.addr),
            body.clone(),
            Some(("X-Test-Signature", signature.clone())),
            Duration::from_secs(10),
        )
        .await
        .unwrap();

        assert_eq!(outcome, DeliveryOutcome::Delivered);
        let heads = requests.lock().unwrap();
        assert_eq!(heads.len(), 1);
        let head = &heads[0];
        assert!(head.to_ascii_lowercase().starts_with("post / http/1.1"));
        assert!(
            head.to_ascii_lowercase()
                .contains("content-type: application/json")
        );
        let header = head
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("x-test-signature:"))
            .expect("signature header present");
        assert_eq!(
            header.split_once(':').map(|(_, v)| v.trim()).unwrap_or_default(),
            signature,
            "header carries exactly the computed hex signature"
        );
    }

    #[tokio::test]
    async fn unsigned_post_has_no_signature_header() {
        let (stub, requests) = Stub::spawn(204);
        let outcome = post_json(
            &reqwest::Client::new(),
            &format!("http://{}", stub.addr),
            b"{}".to_vec(),
            None,
            Duration::from_secs(10),
        )
        .await
        .unwrap();
        assert_eq!(outcome, DeliveryOutcome::Delivered);
        assert!(
            !requests.lock().unwrap()[0]
                .to_ascii_lowercase()
                .contains("signature")
        );
    }

    #[tokio::test]
    async fn non_2xx_is_rejected_not_an_error() {
        let (stub, requests) = Stub::spawn(500);
        let outcome = post_json(
            &reqwest::Client::new(),
            &format!("http://{}", stub.addr),
            b"{}".to_vec(),
            None,
            Duration::from_secs(10),
        )
        .await
        .unwrap();
        assert_eq!(outcome, DeliveryOutcome::Rejected(500));
        assert_eq!(requests.lock().unwrap().len(), 1, "one attempt, no retry");
    }

    #[tokio::test]
    async fn transport_errors_are_url_scrubbed() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener); // guaranteed connection refusal

        let err = post_json(
            &reqwest::Client::new(),
            &format!("http://{addr}"),
            b"{}".to_vec(),
            None,
            Duration::from_secs(10),
        )
        .await
        .expect_err("refused connection must fail");
        assert!(
            !err.to_string().contains(&addr.to_string()),
            "delivery error must not embed the endpoint URL: {err}"
        );
    }
}
