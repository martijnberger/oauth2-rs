#![warn(missing_docs)]
//! A [`reqwest`] client for [`oauth2`].
//!
//! # Motivation
//!
//! The `reqwest` client [bundled](https://docs.rs/oauth2/latest/oauth2/#http-clients) with `oauth2`
//! supports `reqwest` version 0.13. This separate crate allows support for future `reqwest`
//! versions to evolve independently of `oauth2`, without requiring breaking changes to
//! `oauth2`'s public API when `reqwest` introduces its own breaking changes.
//!
//! # Usage
//!
//! To get started, add the following dependencies to your crate's `Cargo.toml`:
//! ```toml
//! # Disables oauth2's default reqwest 0.13 client.
//! oauth2 = { version = "5", default-features = false }
//!
//! # Imports reqwest without any feature flags enabled.
#![doc = concat!("oauth2-reqwest = \"", env!("CARGO_PKG_VERSION"), "\"")]
//!
//! # Enables reqwest's default features.
//! reqwest = "0.13"
//! # Alternatively, specify the desired set of features:
//! # reqwest = { version = "0.13", default-features = false, features = ["native-tls"] }
//! ```
//!
//! For flexibility, this crate disables all of `reqwest`'s Cargo feature flags by default. To
//! enable specific `reqwest` features (including its default `rustls` feature), separately import
//! `reqwest` in your crate's `Cargo.toml` and specify the
//! [desired features](https://docs.rs/crate/reqwest/latest/features). This approach leverages Cargo
//! [feature unification](https://doc.rust-lang.org/cargo/reference/features.html#feature-unification).
//! While this approach requires a separate import, it provides maximum flexibility and reduces the
//! need for future breaking changes to this crate.
//!
//! ## Asynchronous Client
//!
//! To use the async `reqwest` client, simply wrap the `reqwest` [`Client`](reqwest::Client) with
//! this crate's [`ReqwestClient`] and pass the `ReqwestClient` to the desired `request_async`
//! method:
//!
//! ```rust,no_run
//! use oauth2_reqwest::ReqwestClient;
//!
//! # async fn err_wrapper() -> Result<(), anyhow::Error> {
//! # let client = oauth2::basic::BasicClient::new(oauth2::ClientId::new("client_id".to_string()))
//! #     .set_token_uri(oauth2::TokenUrl::new("http://token".to_string())?);
//! let reqwest_client = reqwest::ClientBuilder::new()
//!     // Following redirects opens the client up to SSRF vulnerabilities.
//!     .redirect(reqwest::redirect::Policy::none())
//!     .build()
//!     .expect("Client should build");
//! let http_client = ReqwestClient::from(reqwest_client);
//!
//! # let code = oauth2::AuthorizationCode::new("code".to_string());
//! // This code assumes `client` is a previously constructed `oauth2::Client` and `code` is an
//! // `oauth2::AuthorizationCode`.
//! let token_result = client
//!     .exchange_code(code)
//!     .request_async(&http_client)
//!     .await?;
//!
//! # Ok(())
//! # }
//! ```
//!
//! ## Synchronous Client
//!
//! To use the blocking `reqwest` client, first enable the `blocking` feature in `Cargo.toml`:
//! ```toml
#![doc = concat!("oauth2-reqwest = { version = \"", env!("CARGO_PKG_VERSION"), "\", features = [\"blocking\"] }")]
//! ```
//!
//! Then, simply wrap the `reqwest` blocking [`Client`](reqwest::blocking::Client) with
//! this crate's [`ReqwestBlockingClient`] and pass the `ReqwestBlockingClient` to the desired
//! `request` method:
//!
//! ```rust,no_run
//! # #[cfg(feature = "blocking")]
//! use oauth2_reqwest::ReqwestBlockingClient;
//!
//! # #[cfg(feature = "blocking")]
//! # fn err_wrapper() -> Result<(), anyhow::Error> {
//! # let client = oauth2::basic::BasicClient::new(oauth2::ClientId::new("client_id".to_string()))
//! #     .set_token_uri(oauth2::TokenUrl::new("http://token".to_string())?);
//! let reqwest_client = reqwest::blocking::ClientBuilder::new()
//!     // Following redirects opens the client up to SSRF vulnerabilities.
//!     .redirect(reqwest::redirect::Policy::none())
//!     .build()
//!     .expect("Client should build");
//! let http_client = ReqwestBlockingClient::from(reqwest_client);
//!
//! # let code = oauth2::AuthorizationCode::new("code".to_string());
//! // This code assumes `client` is a previously constructed `oauth2::Client` and `code` is an
//! // `oauth2::AuthorizationCode`.
//! let token_result = client
//!     .exchange_code(code)
//!     .request(&http_client)?;
//!
//! # Ok(())
//! # }
//! ```
use oauth2::{http, AsyncHttpClient, HttpClientError, HttpRequest, HttpResponse};
use std::future::Future;
use std::pin::Pin;

/// Asynchronous `reqwest` [`Client`](reqwest::Client) wrapper.
///
/// See the [crate-level documentation](crate) for usage instructions.
///
/// On non-WebAssembly targets, [`Default`] disables redirects to prevent replaying OAuth2
/// credentials to redirect targets. On WebAssembly, redirects are controlled by the browser's
/// Fetch API; `reqwest` does not expose a redirect policy there.
///
/// Converting a [`reqwest::Client`] with [`From`] preserves its configuration, including its
/// redirect policy. Callers supplying a client must disable redirects themselves.
#[derive(Clone, Debug)]
pub struct ReqwestClient(reqwest::Client);

impl Default for ReqwestClient {
    fn default() -> Self {
        let builder = reqwest::Client::builder();
        #[cfg(not(target_arch = "wasm32"))]
        let builder = builder.redirect(reqwest::redirect::Policy::none());
        Self(builder.build().expect("OAuth2 HTTP client should build"))
    }
}

impl From<reqwest::Client> for ReqwestClient {
    fn from(inner: reqwest::Client) -> Self {
        Self(inner)
    }
}

impl<'c> AsyncHttpClient<'c> for ReqwestClient {
    type Error = HttpClientError<reqwest::Error>;

    #[cfg(target_arch = "wasm32")]
    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + 'c>>;
    #[cfg(not(target_arch = "wasm32"))]
    type Future =
        Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + Send + Sync + 'c>>;

    fn call(&'c self, request: HttpRequest) -> Self::Future {
        Box::pin(async move {
            let response = self
                .0
                .execute(request.try_into().map_err(Box::new)?)
                .await
                .map_err(Box::new)?;

            let mut builder = http::Response::builder().status(response.status());

            #[cfg(not(target_arch = "wasm32"))]
            {
                builder = builder.version(response.version());
            }

            for (name, value) in response.headers().iter() {
                builder = builder.header(name, value);
            }

            builder
                .body(response.bytes().await.map_err(Box::new)?.to_vec())
                .map_err(HttpClientError::Http)
        })
    }
}

#[cfg(all(feature = "blocking", not(target_arch = "wasm32")))]
pub use blocking::ReqwestBlockingClient;

#[cfg(all(feature = "blocking", not(target_arch = "wasm32")))]
mod blocking {
    use oauth2::{http, HttpClientError, HttpRequest, HttpResponse};

    /// Synchronous `reqwest` blocking [`Client`](reqwest::blocking::Client) wrapper.
    ///
    /// See the [crate-level documentation](crate) for usage instructions.
    ///
    /// [`Default`] disables redirects to prevent replaying OAuth2 credentials to redirect targets.
    /// Converting a [`reqwest::blocking::Client`] with [`From`] preserves its configuration,
    /// including its redirect policy. Callers supplying a client must disable redirects themselves.
    #[derive(Clone, Debug)]
    pub struct ReqwestBlockingClient(reqwest::blocking::Client);

    impl Default for ReqwestBlockingClient {
        fn default() -> Self {
            Self(
                reqwest::blocking::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                    .expect("OAuth2 HTTP client should build"),
            )
        }
    }

    impl oauth2::SyncHttpClient for ReqwestBlockingClient {
        type Error = HttpClientError<reqwest::Error>;

        fn call(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
            let mut response = self
                .0
                .execute(request.try_into().map_err(Box::new)?)
                .map_err(Box::new)?;

            let mut builder = http::Response::builder()
                .status(response.status())
                .version(response.version());

            for (name, value) in response.headers().iter() {
                builder = builder.header(name, value);
            }

            let mut body = Vec::new();
            <reqwest::blocking::Response as std::io::Read>::read_to_end(&mut response, &mut body)?;

            builder.body(body).map_err(HttpClientError::Http)
        }
    }

    impl From<reqwest::blocking::Client> for ReqwestBlockingClient {
        fn from(inner: reqwest::blocking::Client) -> Self {
            Self(inner)
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    const CREDENTIALS: &[u8] = b"grant_type=client_credentials&client_secret=do-not-replay";
    const TIMEOUT: Duration = Duration::from_secs(10);

    struct RedirectServer {
        url: String,
        stop: mpsc::Sender<()>,
        worker: thread::JoinHandle<bool>,
    }

    impl RedirectServer {
        fn new(status: http::StatusCode) -> Self {
            let origin = TcpListener::bind("127.0.0.1:0").unwrap();
            let target = TcpListener::bind("127.0.0.1:0").unwrap();
            origin.set_nonblocking(true).unwrap();
            target.set_nonblocking(true).unwrap();
            let url = format!("http://{}/token", origin.local_addr().unwrap());
            let location = format!("http://{}/stolen", target.local_addr().unwrap());
            let (stop, stopped) = mpsc::channel();

            let worker = thread::spawn(move || {
                let deadline = Instant::now() + TIMEOUT;
                let mut origin_stream = loop {
                    match origin.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "no request reached the origin");
                            thread::sleep(Duration::from_millis(1));
                        }
                        Err(error) => panic!("origin accept failed: {error}"),
                    }
                };
                let headers = read_request(&mut origin_stream);
                assert!(headers.starts_with("POST /token HTTP/1.1\r\n"));
                assert!(headers.lines().any(|line| {
                    line.split_once(':').is_some_and(|(name, value)| {
                        name.eq_ignore_ascii_case("authorization")
                            && value.trim() == "Basic Y2xpZW50OnNlY3JldA=="
                    })
                }));
                write!(
                    origin_stream,
                    "HTTP/1.1 {} Redirect\r\nLocation: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    status.as_u16(),
                    location
                )
                .unwrap();
                drop(origin_stream);

                let mut reached_target = false;
                loop {
                    // Check the listener before the stop signal so a queued connection cannot
                    // escape the assertion when the client has just completed its request.
                    match target.accept() {
                        Ok((mut stream, _)) => {
                            reached_target = true;
                            read_request(&mut stream);
                            stream
                                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                                .unwrap();
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            if stopped.try_recv() != Err(mpsc::TryRecvError::Empty) {
                                break;
                            }
                            assert!(Instant::now() < deadline, "HTTP client did not finish");
                            thread::sleep(Duration::from_millis(1));
                        }
                        Err(error) => panic!("redirect target accept failed: {error}"),
                    }
                }
                reached_target
            });
            Self { url, stop, worker }
        }

        fn request(&self) -> HttpRequest {
            http::Request::builder()
                .method(http::Method::POST)
                .uri(&self.url)
                .header(http::header::AUTHORIZATION, "Basic Y2xpZW50OnNlY3JldA==")
                .header(
                    http::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(CREDENTIALS.to_vec())
                .unwrap()
        }

        fn assert_redirected(self, expected: bool) {
            self.stop.send(()).unwrap();
            assert_eq!(
                self.worker.join().unwrap(),
                expected,
                "unexpected request to redirect target"
            );
        }
    }

    fn read_request(stream: &mut TcpStream) -> String {
        stream.set_read_timeout(Some(TIMEOUT)).unwrap();
        stream.set_write_timeout(Some(TIMEOUT)).unwrap();
        let mut reader = BufReader::new(stream);
        let mut headers = String::new();
        loop {
            let start = headers.len();
            assert!(reader.read_line(&mut headers).unwrap() > 0);
            assert!(headers.len() < 16 * 1024, "request headers are too large");
            if &headers[start..] == "\r\n" {
                break;
            }
        }
        let mut body = vec![0; CREDENTIALS.len()];
        reader.read_exact(&mut body).unwrap();
        assert_eq!(body, CREDENTIALS);
        headers
    }

    #[test]
    fn async_default_does_not_follow_credential_redirects() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            for status in [
                http::StatusCode::TEMPORARY_REDIRECT,
                http::StatusCode::PERMANENT_REDIRECT,
            ] {
                let server = RedirectServer::new(status);
                let client = ReqwestClient::default();
                let response = tokio::time::timeout(TIMEOUT, client.call(server.request())).await;
                server.assert_redirected(false);
                assert_eq!(response.unwrap().unwrap().status(), status);
            }
        });
    }

    #[cfg(feature = "blocking")]
    #[test]
    fn blocking_default_does_not_follow_credential_redirects() {
        use oauth2::SyncHttpClient;

        for status in [
            http::StatusCode::TEMPORARY_REDIRECT,
            http::StatusCode::PERMANENT_REDIRECT,
        ] {
            let server = RedirectServer::new(status);
            let response = ReqwestBlockingClient::default().call(server.request());
            server.assert_redirected(false);
            assert_eq!(response.unwrap().status(), status);
        }
    }

    #[test]
    fn async_from_preserves_redirect_policy() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let server = RedirectServer::new(http::StatusCode::TEMPORARY_REDIRECT);
            let client = ReqwestClient::from(
                reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::limited(1))
                    .build()
                    .unwrap(),
            );
            let response = tokio::time::timeout(TIMEOUT, client.call(server.request())).await;
            server.assert_redirected(true);
            assert_eq!(response.unwrap().unwrap().status(), http::StatusCode::OK);
        });
    }

    #[cfg(feature = "blocking")]
    #[test]
    fn blocking_from_preserves_redirect_policy() {
        use oauth2::SyncHttpClient;

        let server = RedirectServer::new(http::StatusCode::TEMPORARY_REDIRECT);
        let client = ReqwestBlockingClient::from(
            reqwest::blocking::Client::builder()
                .redirect(reqwest::redirect::Policy::limited(1))
                .build()
                .unwrap(),
        );
        let response = client.call(server.request());
        server.assert_redirected(true);
        assert_eq!(response.unwrap().status(), http::StatusCode::OK);
    }
}
