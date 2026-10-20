//! Values `exp-frames` experiment 39's TypeScript third party computes the same way, pinned.

use kohaku_ticket_read::pir;

/// `A` for seed `0x07..07`: `rand_chacha`'s ChaCha20 keystream, word by word, as the third party's
/// `chacha20` yields it.
#[test]
fn the_public_matrix_is_the_chacha20_keystream() {
    let a = pir::public_matrix([7; 32], 1);
    assert_eq!(
        [a[0], a[1], a[15], a[16], a[39]],
        [2_022_834_420, 1_106_684_503, 1_809_837_684, 204_047_415, 934_711_965]
    );
}
