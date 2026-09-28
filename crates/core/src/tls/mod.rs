pub mod attest;
pub mod disclosure;
pub mod quic;

pub mod evidence;

// Policy: cap independent hash computations per TLS session.
pub const MAX_COMMITMENTS: usize = 32;
