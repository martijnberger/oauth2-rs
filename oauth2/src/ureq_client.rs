use crate::{HttpClientError, HttpRequest, HttpResponse};

use http::{header::CONTENT_TYPE, method::Method};

impl crate::SyncHttpClient for ureq::Agent {
    type Error = HttpClientError<ureq::Error>;

    fn call(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
        let uri = request.uri().to_string();

        let response = if *request.method() == Method::POST {
            // OAuth error responses must be parsed by the caller, not discarded by ureq.
            let mut req = self.post(&uri).config().http_status_as_error(false).build();
            for (name, value) in request.headers() {
                req = req.header(name, value);
            }
            req.send(request.body())
        } else {
            debug_assert_eq!(*request.method(), Method::GET);
            let mut req = self.get(&uri).config().http_status_as_error(false).build();
            for (name, value) in request.headers() {
                req = req.header(name, value);
            }
            req.call()
        }
        .map_err(Box::new)?;

        let (parts, mut body_reader) = response.into_parts();
        let mut builder = http::Response::builder().status(parts.status);

        if let Some(content_type) = parts.headers.get(CONTENT_TYPE) {
            builder = builder.header(CONTENT_TYPE, content_type);
        }

        let body = body_reader.read_to_vec().map_err(Box::new)?;

        builder.body(body).map_err(HttpClientError::Http)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use crate::basic::{BasicClient, BasicErrorResponseType};
    use crate::{AuthorizationCode, ClientId, RequestTokenError, TokenUrl};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn oauth_error_response_is_not_a_transport_error() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut reader = BufReader::new(&stream);
            let mut length = 0;
            loop {
                let mut line = String::new();
                assert_ne!(reader.read_line(&mut line).unwrap(), 0);
                if line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse::<usize>().unwrap();
                }
            }
            reader.read_exact(&mut vec![0; length]).unwrap();
            let body = r#"{"error":"invalid_grant"}"#;
            write!(
                stream,
                "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .max_redirects(0)
            .timeout_global(Some(Duration::from_secs(5)))
            .build()
            .into();
        let result = BasicClient::new(ClientId::new("client".to_string()))
            .set_token_uri(TokenUrl::new(format!("http://{address}/token")).unwrap())
            .exchange_code(AuthorizationCode::new("code".to_string()))
            .request(&agent);
        server.join().unwrap();
        match result {
            Err(RequestTokenError::ServerResponse(error)) => {
                assert_eq!(error.error(), &BasicErrorResponseType::InvalidGrant);
            }
            other => panic!("expected an OAuth server error, got {other:?}"),
        }
    }
}
