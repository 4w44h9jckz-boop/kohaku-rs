//! Find, and pin, an element of GF(2^192)^* whose powers carry a whole coefficient sum.
use primitives::field::F192;

fn pow(mut b: F192, mut e: u128) -> F192 {
    let mut r = F192::ONE;
    while e > 0 {
        if e & 1 == 1 {
            r = r * b;
        }
        b = b * b;
        e >>= 1;
    }
    r
}

/// 2^192 - 1 = 3^2 · 5 · 7 · 13 · 17 · 97 · 193 · 241 · 257 · 641 · 673 · 65537 · 6700417
/// · 22253377 · 18446744069414584321. An element is primitive when h^(N/p) != 1 for each p.
const PRIMES: [u128; 15] = [3, 5, 7, 13, 17, 97, 193, 241, 257, 641, 673, 65537, 6700417, 22253377, 18446744069414584321];

fn is_primitive(h: F192) -> bool {
    // N/p as a 192-bit exponent: h^(N/p) = (h^(N/p mod 2^128 part)) handled by splitting N/p.
    PRIMES.iter().all(|&p| {
        let n = num(p);
        pow_big(h, &n) != F192::ONE
    })
}

/// N / p as little-endian u64 limbs.
fn num(p: u128) -> [u64; 3] {
    // long division of 2^192 - 1 by p
    let mut rem: u128 = 0;
    let mut out = [0u64; 3];
    for i in (0..3).rev() {
        let cur = (rem << 64) | u128::from(u64::MAX);
        out[i] = (cur / p) as u64;
        rem = cur % p;
    }
    out
}

fn pow_big(h: F192, e: &[u64; 3]) -> F192 {
    let mut r = F192::ONE;
    for &limb in e.iter().rev() {
        r = pow(r, 1u128 << 64);
        r = r * pow(h, u128::from(limb));
    }
    r
}

#[test]
fn h_is_primitive() {
    let h = kohaku_fhe_input_pq::H;
    assert!(is_primitive(h));
}

#[test]
#[ignore = "search, run once"]
fn search() {
    for c in 1..20u64 {
        for (a, b) in [(c, 1), (1, c), (c, c + 1)] {
            let h = F192::new(a, b, 0);
            if is_primitive(h) {
                println!("primitive: F192::new({a}, {b}, 0)");
                return;
            }
        }
    }
}
