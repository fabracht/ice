use crate::{Method, Request, Response, StatusCode, REMOTE_AUTH_CHANNEL, REMOTE_CAND_CHANNEL};
use hyper::Body;

// HTTP Listener to get ICE Credentials/Candidate from remote Peer
pub async fn remote_handler(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    //println!("received {:?}", req);
    match (req.method(), req.uri().path()) {
        (&Method::POST, "/remoteAuth") => {
            let full_body =
                match std::str::from_utf8(&hyper::body::to_bytes(req.into_body()).await?) {
                    Ok(s) => s.to_owned(),
                    Err(err) => panic!("{}", err),
                };
            let tx = REMOTE_AUTH_CHANNEL.0.lock().await;
            //println!("body: {:?}", full_body);
            let _ = tx.send(full_body).await;

            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::OK;
            Ok(response)
        }

        (&Method::POST, "/remoteCandidate") => {
            let full_body =
                match std::str::from_utf8(&hyper::body::to_bytes(req.into_body()).await?) {
                    Ok(s) => s.to_owned(),
                    Err(err) => panic!("{}", err),
                };
            let tx = REMOTE_CAND_CHANNEL.0.lock().await;
            //println!("body: {:?}", full_body);
            let _ = tx.send(full_body).await;

            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::OK;
            Ok(response)
        }

        // Return the 404 Not Found for other routes.
        _ => {
            let mut not_found = Response::default();
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}
