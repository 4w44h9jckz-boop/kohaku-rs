//! circomlib's Poseidon over two inputs (`t = 3`), as circomlibjs's reference implementation
//! computes it: 8 full rounds and 57 partial ones, with the round constants and MDS matrix of
//! `poseidon_constants.json` (circomlibjs 0.1.7), copied into `poseidon_t3.json`. It is the hash
//! of Privacy Pools' association-set tree (a `LeanIMT`).

use std::sync::LazyLock;

use alloy::primitives::U256;
use ark_bn254::Fr;
use ark_ff::{BigInt, Field, PrimeField, Zero};

const T: usize = 3;
const FULL: usize = 8;
const PARTIAL: usize = 57;

struct Constants {
    c: Vec<Fr>,
    m: [[Fr; T]; T],
}

static CONSTANTS: LazyLock<Constants> = LazyLock::new(|| {
    #[derive(serde::Deserialize)]
    struct Json {
        #[serde(rename = "C")]
        c: Vec<String>,
        #[serde(rename = "M")]
        m: Vec<Vec<String>>,
    }
    let j: Json =
        serde_json::from_str(include_str!("poseidon_t3.json")).expect("embedded constants");
    let fr = |s: &String| {
        let x = U256::from_str_radix(s.trim_start_matches("0x"), 16).expect("hex constant");
        Fr::from_bigint(BigInt(x.into_limbs())).expect("a field element")
    };
    assert_eq!(j.c.len(), (FULL + PARTIAL) * T);
    let mut m = [[Fr::zero(); T]; T];
    for (i, row) in j.m.iter().enumerate() {
        for (k, x) in row.iter().enumerate() {
            m[i][k] = fr(x);
        }
    }
    Constants {
        c: j.c.iter().map(fr).collect(),
        m,
    }
});

fn pow5(a: Fr) -> Fr {
    a.square().square() * a
}

/// `Poseidon(a, b)`, circomlib's.
#[must_use]
pub fn poseidon2(a: Fr, b: Fr) -> Fr {
    let k = &*CONSTANTS;
    let mut s = [Fr::zero(), a, b];
    for r in 0..FULL + PARTIAL {
        for (i, x) in s.iter_mut().enumerate() {
            *x += k.c[r * T + i];
        }
        // Partial rounds in the middle: the S-box on the first element only.
        if (FULL / 2..FULL / 2 + PARTIAL).contains(&r) {
            s[0] = pow5(s[0]);
        } else {
            s = s.map(pow5);
        }
        s = std::array::from_fn(|i| (0..T).map(|j| k.m[i][j] * s[j]).sum());
    }
    s[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_circomlib() {
        // circomlibjs 0.1.7: poseidon([1, 2]).
        let expected = U256::from_str_radix(
            "7853200120776062878684798364095072458815029376092732009249414926327459813530",
            10,
        )
        .unwrap();
        let got = U256::from_limbs(poseidon2(Fr::from(1u64), Fr::from(2u64)).into_bigint().0);
        assert_eq!(got, expected);
    }
}
