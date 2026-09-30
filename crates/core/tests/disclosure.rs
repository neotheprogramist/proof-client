#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "public disclosure workflow"
)]
use futures::FutureExt;
use proof_client_core::tls::disclosure::{Disclosure, receive};
use proptest::prelude::*;

proptest! {
    #[test]
    fn receive_and_resolve_preserve_wire_bytes(chunk in 1usize..64, amount in 0u32..1_000_000) {
        let body = format!(r#"{{"balance":{amount}.1200,"id":"demo-id","number":"demo-number"}}"#);
        let mut wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n".to_vec();
        for part in body.as_bytes().chunks(chunk) {
            wire.extend(format!("{:x}\r\n", part.len()).as_bytes());
            wire.extend(part);
            wire.extend(b"\r\n");
        }
        wire.extend(b"0\r\n\r\n");
        // EOF remains pending: framed HTTP must finish without waiting for close.
        let stream = futures::stream::iter(wire.iter().map(|b| Ok::<_, std::io::Error>(vec![*b])))
            .chain(futures::stream::pending());
        use futures::{StreamExt, TryStreamExt};
        let message = receive(&mut stream.into_async_read(), &http::Method::GET, wire.len())
            .now_or_never().unwrap().unwrap();
        let policy = Disclosure::parse(br#"{
            "reveal":{"received":[{"json":"/balance"},{"json_key":"/id"}]},
            "commit":{"received":[{"json_value":"/id"},{"json_value":"/number"}]}
        }"#).unwrap();
        let (revealed, committed, _) = message.resolve(&policy.reveal.received, &policy.commit.received).unwrap().into_parts();
        let bytes = |ranges: &tlsn::rangeset::set::RangeSet<usize>| ranges.iter().flat_map(|r| wire[r].to_vec()).collect::<Vec<_>>();
        prop_assert_eq!(bytes(&revealed), format!(r#""balance":{amount}.1200"id""#).into_bytes());
        prop_assert_eq!(committed.len(), 2);
        prop_assert_eq!(bytes(&committed[0]), br#""demo-id""#);
        prop_assert_eq!(bytes(&committed[1]), br#""demo-number""#);
        prop_assert_eq!(message.into_body(), body.as_bytes());
    }
}
