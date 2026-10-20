// TicketPaymaster: pays the gas of any frame transaction that carries a blind ticket, a BLS
// signature by a committee of off-chain issuers on the transaction's own slot.
//
// Buying: any call with value buys value / DENOMINATION tickets (a multiple, or it reverts) and
// logs Bought(buyer, count). The issuers watch the log and answer that many blinded requests from
// the buyer. There is no withdrawal: the float leaves only as gas this contract approves.
//
// Paying: in a VERIFY frame with scope PAYMENT, the frame's data is
//
//   epoch (8) || salt (32) || sigma (128, EIP-2537's encoding of a G1 point)          168 bytes
//
// and the ticket message is built from the transaction itself, so a ticket pays for exactly one
// slot and the nonce is its spent mark: the protocol consumes it once.
//
//   message = chain_id (32) || sender (20) || nonce_keys_hash (32) || nonce_seq (8)
//             || epoch (8) || salt (32)                                            132 bytes
//
// sigma must be the issuers' signature on it, as Commonware's `ops::verify_message::<MinSig>`
// checks one: H = hash_to_curve(union_unique(NAMESPACE, message)) in G1, RFC 9380's
// BLS12381G1_XMD:SHA-256_SSWU_RO_ suite under the DST below, and e(sigma, -g2) e(H, PK) = 1.
// It also requires the transaction's max cost (TXPARAM 0x06) to be at most DENOMINATION.
//
// It reads no storage and no balance, calls only precompiles, and forwards gas only as GAS
// immediately before STATICCALL, so it can run in a public-mempool VERIFY frame.
//
// initcode = <this object> || PK (256, EIP-2537's encoding of a G2 point) || DENOMINATION (32)
object "TicketPaymaster" {
    code {
        let size := datasize("runtime")
        datacopy(0, dataoffset("runtime"), size)
        codecopy(size, sub(codesize(), 288), 288)
        return(0, add(size, 288))
    }
    object "runtime" {
        code {
            // ENTRY_POINT (0xaa) calls in DEFAULT and VERIFY frames. Only VERIFY does anything.
            if eq(caller(), 0xaa) {
                let frame := txparam(0x0a)
                if eq(frameparam(0x02, frame), 1) { validate(frame) }
                stop()
            }
            buy()

            function buy() {
                let d := denomination()
                if iszero(callvalue()) { revert(0, 0) }
                if mod(callvalue(), d) { revert(0, 0) }
                mstore(0, div(callvalue(), d))
                // Bought(address indexed buyer, uint256 count)
                log2(0, 0x20, 0xc55650ccda1011e1cdc769b1fbf546ebb8c97800b6072b49e06cd560305b1d67, caller())
                stop()
            }

            function validate(me) {
                if iszero(eq(frameparam(0x06, me), 1)) { fail() }      // scope PAYMENT only
                if iszero(eq(calldatasize(), 168)) { fail() }
                if gt(txparam(0x06), denomination()) { fail() }

                // msg_prime = Z_pad (64) || union_unique(NAMESPACE, message) (149)
                //             || I2OSP(128, 2) || I2OSP(0, 1) || DST_prime (44), at 0x200.
                calldatacopy(0x200, calldatasize(), 64)                 // Z_pad: zeros
                mstore(0x240, shl(248, 16))                             // varint(len(NAMESPACE))
                mstore(0x241, NAMESPACE())
                mstore(0x251, chainid())
                mstore(0x271, shl(96, txparam(0x02)))                   // sender
                mstore(0x285, txparam(0x0f))                            // nonce_keys_hash
                mstore(0x2a5, shl(192, txparam(0x01)))                  // nonce_seq
                calldatacopy(0x2ad, 0, 40)                              // epoch, salt
                mstore(0x2d5, shl(240, 0x0080))                         // len_in_bytes = 128
                mstore8(0x2d7, 0)
                mstore(0x2d8, DST1())
                mstore(0x2f8, DST2())
                sha256(0x200, 0x104, 0x100)                             // b_0
                let b0 := mload(0x100)

                // b_i = H(strxor(b_0, b_{i-1}) || I2OSP(i, 1) || DST_prime), uniform at 0x400.
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

                // u_j = OS2IP(uniform[64j .. 64j+64]) mod p, then Q_j = map_to_curve(u_j).
                toField(0x400, 0x600)
                toField(0x440, 0x640)
                if iszero(staticcall(gas(), 0x10, 0x600, 64, 0x700, 128)) { fail() }
                if iszero(staticcall(gas(), 0x10, 0x640, 64, 0x780, 128)) { fail() }

                // e(sigma, -g2) e(Q_0 + Q_1, PK) = 1
                calldatacopy(0x900, 40, 128)
                datacopy(0x980, dataoffset("negG2"), 256)
                if iszero(staticcall(gas(), 0x0b, 0x700, 256, 0xa80, 128)) { fail() }
                codecopy(0xb00, sub(codesize(), 288), 256)
                if iszero(staticcall(gas(), 0x0f, 0x900, 0x300, 0x00, 0x20)) { fail() }
                if iszero(eq(mload(0x00), 1)) { fail() }
                approvePayment()
            }

            function sha256(from, len, to) {
                if iszero(staticcall(gas(), 0x02, from, len, to, 32)) { fail() }
            }

            // 64 bytes at `from`, reduced mod p by MODEXP (exponent 1), written at `to` as
            // EIP-2537's 64-byte field element.
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

            function denomination() -> d {
                codecopy(0, sub(codesize(), 32), 32)
                d := mload(0)
            }
            function fail() { revert(0, 0) }
            // "kohaku-ticket-v1", left-aligned.
            function NAMESPACE() -> v { v := 0x6b6f68616b752d7469636b65742d763100000000000000000000000000000000 }
            // "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_" || I2OSP(43, 1), left-aligned.
            function DST1() -> v { v := 0x424c535f5349475f424c53313233383147315f584d443a5348412d3235365f53 }
            function DST2() -> v { v := 0x5357555f524f5f504f505f2b0000000000000000000000000000000000000000 }
            // The base field's modulus p, 48 bytes, left-aligned over two words.
            function P1() -> v { v := 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f624 }
            function P2() -> v { v := 0x1eabfffeb153ffffb9feffffffffaaab00000000000000000000000000000000 }
            // PUSH1 1, PUSH0, PUSH0, APPROVE: APPROVE(offset 0, length 0, scope PAYMENT).
            function approvePayment() { verbatim_0i_0o(hex"60015f5faa") }
            function txparam(param) -> v { v := verbatim_1i_1o(hex"b0", param) }
            function frameparam(param, frame) -> v { v := verbatim_2i_1o(hex"b3", frame, param) }
        }
        // -g2, the negated generator of G2, in EIP-2537's encoding.
        data "negG2" hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e000000000000000000000000000000000d1b3cc2c7027888be51d9ef691d77bcb679afda66c73f17f9ee3837a55024f78c71363275a75d75d86bab79f74782aa0000000000000000000000000000000013fa4d4a0ad8b1ce186ed5061789213d993923066dddaf1040bc3ff59f825c78df74f2d75467e25e0f55f8a00fa030ed"
    }
}
