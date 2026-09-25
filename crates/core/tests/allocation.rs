#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "isolated allocation witness"
)]
use proof_client_core::tls::disclosure::{Direction, Disclosure, select};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};
thread_local! { static ALLOCATED: Cell<Option<usize>> = const { Cell::new(None) }; }
struct Counted;
fn account(bytes: usize) {
    ALLOCATED.with(|count| count.set(count.get().map(|n| n + bytes)));
}
// PROOF: the wrapper forwards each allocation with its original layout and pointer to System.
unsafe impl GlobalAlloc for Counted {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        account(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        account(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        account(size);
        unsafe { System.realloc(ptr, layout, size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Counted = Counted;
fn measured<T>(run: impl FnOnce() -> T) -> (T, usize) {
    ALLOCATED.with(|count| count.set(Some(0)));
    let result = run();
    (result, ALLOCATED.with(|count| count.replace(None).unwrap()))
}
#[test]
fn unused_ancestor_allocation_scales_with_input_not_descendant_paths() {
    let policy = Disclosure::parse(br#"{"sent":[],"received":[{"json":"/balance"}]}"#).unwrap();
    let input = |key: usize| {
        let body = format!(
            r#"{{"{}":[{}],"balance":42.1200}}"#,
            "x".repeat(key),
            vec!["0"; 8001].join(",")
        );
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    };
    let small = input(1);
    let large = input(24_000);
    let select_bytes = |raw: &[u8]| {
        let ranges = select(
            raw,
            Direction::Response(&http::Method::GET),
            &policy.received,
        )
        .unwrap();
        ranges
            .iter()
            .flat_map(|range| raw[range].to_vec())
            .collect::<Vec<_>>()
    };
    let (a, baseline) = measured(|| select_bytes(&small));
    let (b, allocation) = measured(|| select_bytes(&large));
    assert_eq!(a, br#""balance":42.1200"#);
    assert_eq!(a, b);
    // Policy: allow twice the measured input growth for allocator/parser capacity boundaries.
    let within = |bytes: usize| {
        (bytes as u128) * (small.len() as u128) <= 2 * (baseline as u128) * (large.len() as u128)
    };
    let (_, linear) = measured(|| std::hint::black_box(large.clone()));
    let (_, quadratic) = measured(|| {
        for _ in 0..8001 {
            std::hint::black_box("x".repeat(24_000));
        }
    });
    assert!(within(linear), "positive allocation reference must pass");
    assert!(
        !within(quadratic),
        "path duplication control must fail the witness"
    );
    assert!(
        within(allocation),
        "allocation {allocation}, baseline {baseline}"
    );
}

#[test]
fn fragmented_chunks_allocate_linearly() {
    use futures::{AsyncRead, executor::block_on};
    use proof_client_core::tls::disclosure::receive;
    struct Bytes<'a>(&'a [u8]);
    impl AsyncRead for Bytes<'_> {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            out: &mut [u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            let n = usize::from(!self.0.is_empty()).min(out.len());
            out[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            std::task::Poll::Ready(Ok(n))
        }
    }
    let input = |chunks| {
        format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{}0\r\n\r\n",
            "1\r\nx\r\n".repeat(chunks)
        )
        .into_bytes()
    };
    let small = input(128);
    let large = input(512);
    let run = |raw: &[u8]| {
        block_on(receive(&mut Bytes(raw), &http::Method::GET, raw.len()))
            .unwrap()
            .into_body()
    };
    let (a, baseline) = measured(|| run(&small));
    let (b, allocation) = measured(|| run(&large));
    assert_eq!(a, vec![b'x'; 128]);
    assert_eq!(b, vec![b'x'; 512]);
    // Policy: allow twice proportional input growth for allocation capacity boundaries.
    let within = |bytes: usize| {
        (bytes as u128) * (small.len() as u128) <= 2 * (baseline as u128) * (large.len() as u128)
    };
    let (_, linear) = measured(|| std::hint::black_box(large.clone()));
    let (_, quadratic) = measured(|| {
        for end in 0..large.len() {
            std::hint::black_box(large[..end].to_vec());
        }
    });
    assert!(within(linear));
    assert!(!within(quadratic));
    assert!(
        within(allocation),
        "allocation {allocation}, baseline {baseline}"
    );
}
