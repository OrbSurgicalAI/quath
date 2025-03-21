use http::Request;
use http_body_util::Full;
use hyper::body::Bytes;


pub enum Message {
    Request(Request<Full<Bytes>>)
}