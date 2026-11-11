// BlindAccount: ETH held for blind tickets, one count per key chi = keccak256(D || epoch), the two
// as 32-byte words. Payouts under a key never exceed the purchases under it.
//
// Version 2 (experiment 59's amendment 2): the value owed is kept, and a ticket can be rolled over
// into the next epoch's key.
//
// Storage: burned[chi] at keccak256(chi || 0), minted[chi] at keccak256(chi || 1),
// owed[recipient] at keccak256(recipient || 2), what a payout could not send, and outstanding at
// keccak256(0 || 3), the value owed: D per unspent ticket, and every credit not yet claimed.
//
// buy(uint64 epoch)                           0x215adc4a  D = msg.value > 0: burned[chi] += 1
// claim()                                     0x4e71d92d  sends owed[caller]
// (no calldata)                                           accepts ETH: the surplus
// payout(uint256 D, uint64 e, address to, n)  0x423b21cd  only from itself, in a SENDER frame:
//   minted[chi] += n (reverting past burned[chi]); sends n * D - maxCost to `to` holding back
//   60,000 gas, and credits owed[to] if the send fails.
// rollover(uint256 D, uint64 e, 0, n)         0x0799081a  only from itself, in a SENDER frame:
//   minted[(D, e)] += n (reverting past burned), burned[(D, e + 1)] += n, logging Bought for the
//   binder of the VERIFY frame. No ETH moves.
//
// VERIFY (frame 0, scope 3): the frame's data is
//
//   D (32) || epoch (8) || binder (20) || n (1) || serial (32) * n || sigma (128, EIP-2537's G1)
//
// and each ticket's message, under the namespace BLIND_ACCOUNT_V1 (blind BLS, MinSig), is
//
//   chain_id (32) || account (20) || D (32) || epoch (8) || serial (32) || binder (20)   144 bytes
//
// It checks: exactly two frames, the second a SENDER frame to this account with no value, an
// execution budget of at least 100,000 and the data payout(D, epoch, to, n); 1 <= n <= 16 serials,
// non-zero and strictly increasing, which are the transaction's nonce keys (TXPARAM 0x0f, the keys'
// hash) at sequence 0 (TXPARAM 0x01); the maximum cost (TXPARAM 0x06) below D; minted + n <= burned;
// a SECP256K1 signature entry by binder over the signature hash; and the pairing
// e(sigma, -g2) e(sum_i H(m_i), PK) = 1, with sigma the sum of the tickets' signatures.
//
// initcode = <this object> || PK (256, EIP-2537's encoding of a G2 point)
object "BlindAccount" {
    code {
        let size := datasize("runtime")
        datacopy(0, dataoffset("runtime"), size)
        codecopy(size, sub(codesize(), 256), 256)
        return(0, add(size, 256))
    }
    object "runtime" {
        code {
            if eq(caller(), 0xaa) {
                let frame := txparam(0x0a)
                if eq(frameparam(0x02, frame), 1) { validate(frame) }
                stop()
            }
            // A plain transfer adds to the surplus, which pays a rollover's fee.
            if iszero(calldatasize()) { stop() }
            let sel := shr(224, calldataload(0))
            if eq(caller(), address()) {
                if eq(sel, 0x423b21cd) { payout() }
                if eq(sel, 0x0799081a) { rollover() }
            }
            switch sel
            case 0x215adc4a { buy() }
            case 0x4e71d92d { claim() }
            default { revert(0, 0) }

            function chiOf(d, epoch) -> chi {
                mstore(0, d)
                mstore(0x20, epoch)
                chi := keccak256(0, 0x40)
            }
            function slotOf(k, i) -> s {
                mstore(0, k)
                mstore(0x20, i)
                s := keccak256(0, 0x40)
            }

            function buy() {
                let d := callvalue()
                if iszero(d) { revert(0, 0) }
                let epoch := calldataload(4)
                if gt(epoch, 0xffffffffffffffff) { revert(0, 0) }
                let chi := chiOf(d, epoch)
                let s := slotOf(chi, 0)
                let index := sload(s)
                sstore(s, add(index, 1))
                let os := slotOf(0, 3)
                sstore(os, add(sload(os), d))
                mstore(0, index)
                // Bought(bytes32 indexed chi, address indexed buyer, uint256 index)
                log3(0, 0x20, 0xffa101c6ca2880d2c4f3240ea96a0cdbac504f2ee13706c9cf67c1b27219df94, chi, caller())
                stop()
            }

            function claim() {
                let s := slotOf(caller(), 2)
                let amount := sload(s)
                sstore(s, 0)
                let os := slotOf(0, 3)
                sstore(os, sub(sload(os), amount))
                if iszero(call(gas(), caller(), amount, 0, 0, 0, 0)) { revert(0, 0) }
                stop()
            }

            function payout() {
                let d := calldataload(4)
                let epoch := calldataload(36)
                let to := calldataload(68)
                let n := calldataload(100)
                let chi := chiOf(d, epoch)
                let ms := slotOf(chi, 1)
                let minted := add(sload(ms), n)
                if gt(minted, sload(slotOf(chi, 0))) { revert(0, 0) }
                sstore(ms, minted)
                let amount := sub(mul(n, d), txparam(0x06))
                let out := slotOf(0, 3)
                let left := sub(sload(out), mul(n, d))
                let sent := call(sub(gas(), 60000), to, amount, 0, 0, 0, 0)
                if iszero(sent) {
                    let os := slotOf(to, 2)
                    sstore(os, add(sload(os), amount))
                    left := add(left, amount)
                }
                sstore(out, left)
                mstore(0, amount)
                mstore(0x20, sent)
                // Paid(bytes32 indexed chi, address indexed to, uint256 amount, bool sent)
                log3(0, 0x40, 0x408247e89d39871c0cb4768c90199873315688a638cb09e6f8eeb7a32a5cf1eb, chi, to)
                stop()
            }

            function rollover() {
                let d := calldataload(4)
                let epoch := calldataload(36)
                let n := calldataload(100)
                let ms := slotOf(chiOf(d, epoch), 1)
                let minted := add(sload(ms), n)
                if gt(minted, sload(slotOf(chiOf(d, epoch), 0))) { revert(0, 0) }
                sstore(ms, minted)
                let next := chiOf(d, add(epoch, 1))
                let bs := slotOf(next, 0)
                let index := sload(bs)
                sstore(bs, add(index, n))
                let binder := shr(96, framedataload(40, 0))
                for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                    mstore(0, add(index, i))
                    log3(0, 0x20, 0xffa101c6ca2880d2c4f3240ea96a0cdbac504f2ee13706c9cf67c1b27219df94, next, binder)
                }
                stop()
            }

            function validate(me) {
                if me { fail1() }
                if iszero(eq(frameparam(0x06, me), 3)) { fail1() }       // scope EXECUTION_AND_PAYMENT
                if iszero(eq(txparam(0x09), 2)) { fail1() }              // exactly two frames
                let d := calldataload(0)
                let epoch := shr(192, calldataload(32))
                let binder := shr(96, calldataload(40))
                let n := shr(248, calldataload(60))
                if or(iszero(n), gt(n, 16)) { fail1() }
                if iszero(eq(calldatasize(), add(189, shl(5, n)))) { fail1() }
                if iszero(binder) { fail1() }
                if iszero(lt(txparam(0x06), d)) { fail1() }               // maximum cost below D

                // The second frame: SENDER to this account, no value, payout(D, epoch, to, n).
                if iszero(eq(frameparam(0x02, 1), 2)) { fail1() }
                if iszero(eq(frameparam(0x00, 1), address())) { fail1() }
                if frameparam(0x08, 1) { fail1() }
                if lt(frameparam(0x01, 1), 100000) { fail1() }
                if iszero(eq(frameparam(0x04, 1), 132)) { fail1() }
                let call1 := shr(224, framedataload(0, 1))
                switch call1
                case 0x423b21cd {}
                case 0x0799081a {
                    // A rollover: no recipient, and a surplus that pays its fee.
                    if framedataload(68, 1) { fail1() }
                    if lt(selfbalance(), add(sload(slotOf(0, 3)), txparam(0x06))) { fail1() }
                }
                default { fail1() }
                if iszero(eq(framedataload(4, 1), d)) { fail1() }
                if iszero(eq(framedataload(36, 1), epoch)) { fail1() }
                if iszero(eq(framedataload(100, 1), n)) { fail1() }

                // The serials are the nonce keys, at sequence 0: keccak256(n || serials) is the
                // keys' hash. Strictly increasing and non-zero, as EIP-8250 requires of keys.
                if txparam(0x01) { fail2() }
                mstore(0x1000, n)
                let prev := 0
                for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                    let s := calldataload(add(61, shl(5, i)))
                    if iszero(gt(s, prev)) { fail2() }
                    prev := s
                    mstore(add(0x1020, shl(5, i)), s)
                }
                if iszero(eq(keccak256(0x1000, add(32, shl(5, n))), txparam(0x0f))) { fail2() }

                // The count, read at admission and again at inclusion.
                let chi := chiOf(d, epoch)
                if gt(add(sload(slotOf(chi, 1)), n), sload(slotOf(chi, 0))) { fail3() }

                // The binding: an entry the protocol verified over the sig hash, by the binder.
                let bound := 0
                let entries := txparam(0x0b)
                for { let i := 0 } lt(i, entries) { i := add(i, 1) } {
                    if eq(sigparam(0x01, i), 1) {
                        if iszero(sigparam(0x02, i)) {
                            if eq(sigparam(0x00, i), binder) { bound := 1 }
                        }
                    }
                }
                if iszero(bound) { fail4() }

                // sum_i H(m_i) at 0xc00, each H(m_i) through 0xc80.
                for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                    hashToG1(d, epoch, calldataload(add(61, shl(5, i))), binder)
                    switch i
                    case 0 { mcopy(0xc00, 0xc80, 128) }
                    default { if iszero(staticcall(gas(), 0x0b, 0xc00, 256, 0xc00, 128)) { fail5() } }
                }

                // e(sigma, -g2) e(sum Q, PK) = 1
                calldatacopy(0x900, add(61, shl(5, n)), 128)
                datacopy(0x980, dataoffset("negG2"), 256)
                mcopy(0xa80, 0xc00, 128)
                codecopy(0xb00, sub(codesize(), 256), 256)
                if iszero(staticcall(gas(), 0x0f, 0x900, 0x300, 0x00, 0x20)) { fail5() }
                if iszero(eq(mload(0x00), 1)) { fail5() }
                approve(3)
            }

            // H(m) for one ticket's message, hashed to G1 as experiment 36's tickets are, at 0xc80.
            function hashToG1(d, epoch, serial, binder) {
                // msg_prime = Z_pad (64) || varint(16) || NAMESPACE (16) || message (144)
                //             || I2OSP(128, 2) || I2OSP(0, 1) || DST_prime (44), at 0x200: 272 bytes.
                mstore(0x200, 0)
                mstore(0x220, 0)
                mstore(0x240, shl(248, 16))
                mstore(0x241, NAMESPACE())
                mstore(0x251, chainid())
                mstore(0x271, shl(96, address()))
                mstore(0x285, d)
                mstore(0x2a5, shl(192, epoch))
                mstore(0x2ad, serial)
                mstore(0x2cd, shl(96, binder))
                mstore(0x2e1, shl(240, 0x0080))
                mstore8(0x2e3, 0)
                mstore(0x2e4, DST1())
                mstore(0x304, DST2())
                sha256(0x200, 0x110, 0x100)                              // b_0
                let b0 := mload(0x100)
                mstore(0x161, DST1())
                mstore(0x181, DST2())
                let prev := 0
                for { let i := 1 } lt(i, 5) { i := add(i, 1) } {
                    mstore(0x140, xor(b0, prev))
                    mstore8(0x160, i)
                    let out := add(0x400, shl(5, sub(i, 1)))
                    sha256(0x140, 77, out)
                    prev := mload(out)
                }
                toField(0x400, 0x600)
                toField(0x440, 0x640)
                if iszero(staticcall(gas(), 0x10, 0x600, 64, 0x700, 128)) { fail() }
                if iszero(staticcall(gas(), 0x10, 0x640, 64, 0x780, 128)) { fail() }
                if iszero(staticcall(gas(), 0x0b, 0x700, 256, 0xc80, 128)) { fail() }
            }

            function sha256(from, len, to) {
                if iszero(staticcall(gas(), 0x02, from, len, to, 32)) { fail() }
            }

            // 64 bytes at `from`, reduced mod p by MODEXP, written at `to` as a 64-byte field element.
            function toField(from, to) {
                mstore(0x500, 64)
                mstore(0x520, 1)
                mstore(0x540, 48)
                mstore(0x560, mload(from))
                mstore(0x580, mload(add(from, 32)))
                mstore8(0x5a0, 1)
                mstore(0x5a1, P1())
                mstore(0x5c1, P2())
                mstore(to, 0)
                if iszero(staticcall(gas(), 0x05, 0x500, 209, add(to, 16), 48)) { fail() }
            }

            function fail() { revert(0, 0) }
            // One per group of VERIFY's checks: the shape, the nonce keys, the count, the binding,
            // the pairing. Each reverts.
            function fail1() { revert(0, 0) }
            function fail2() { revert(0, 0) }
            function fail3() { revert(0, 0) }
            function fail4() { revert(0, 0) }
            function fail5() { revert(0, 0) }
            // "BLIND_ACCOUNT_V1", left-aligned.
            function NAMESPACE() -> v { v := 0x424c494e445f4143434f554e545f563100000000000000000000000000000000 }
            // "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_" || I2OSP(43, 1), left-aligned.
            function DST1() -> v { v := 0x424c535f5349475f424c53313233383147315f584d443a5348412d3235365f53 }
            function DST2() -> v { v := 0x5357555f524f5f504f505f2b0000000000000000000000000000000000000000 }
            function P1() -> v { v := 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f624 }
            function P2() -> v { v := 0x1eabfffeb153ffffb9feffffffffaaab00000000000000000000000000000000 }
            function approve(scope) { verbatim_3i_0o(hex"aa", 0, 0, scope) }
            function txparam(param) -> v { v := verbatim_1i_1o(hex"b0", param) }
            function frameparam(param, frame) -> v { v := verbatim_2i_1o(hex"b3", frame, param) }
            function framedataload(offset, frame) -> v { v := verbatim_2i_1o(hex"b1", offset, frame) }
            function sigparam(param, index) -> v { v := verbatim_2i_1o(hex"b4", index, param) }
        }
        // -g2, the negated generator of G2, in EIP-2537's encoding (experiment 36's).
        data "negG2" hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e000000000000000000000000000000000d1b3cc2c7027888be51d9ef691d77bcb679afda66c73f17f9ee3837a55024f78c71363275a75d75d86bab79f74782aa0000000000000000000000000000000013fa4d4a0ad8b1ce186ed5061789213d993923066dddaf1040bc3ff59f825c78df74f2d75467e25e0f55f8a00fa030ed"
    }
}
