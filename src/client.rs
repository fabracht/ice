use hyper::client::HttpConnector;
use hyper::Client;
use std::sync::Arc;

struct ClientConnector {
    connector: Arc<Client<HttpConnector>>,
}

impl ClientConnector {
    pub fn new() -> Self {
        let connector = Arc::new(Client::new());
        ClientConnector { connector }
    }
}
