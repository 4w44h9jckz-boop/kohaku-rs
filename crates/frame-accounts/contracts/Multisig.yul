// Multisig: a k-of-n smart account whose owners can be secp256k1 keys or P256 (passkey) keys.
//
// No signature is checked in the EVM. Before any frame runs, the protocol has validated every
// SECP256K1 and P256 entry in tx.signatures (an invalid one makes the whole transaction invalid).
// The account only counts, with SIGPARAM, the distinct owners among the entries that sign the
// canonical sig hash (empty msg). That hash commits to every frame, so the approval cannot be
// replayed with other frames. Entries for other schemes, other signers or explicit digests are
// ignored, so the account can share the list with a paymaster's signature.
//
// The VERIFY path reads only this account's own code: no storage, no ecrecover, no P256VERIFY.
// Execution needs no `execute` function either: SENDER frames call their targets as the account.
//
// initcode = <this object> ‖ owner_0 ‖ … ‖ owner_{n-1} ‖ n ‖ k (32-byte words)
// Every word after the runtime is appended to the deployed code.
object "Multisig" {
    code {
        codecopy(0, sub(codesize(), 64), 64)
        let n := mload(0)
        let k := mload(32)
        if or(or(iszero(k), gt(k, n)), gt(n, 256)) { revert(0, 0) }
        let size := datasize("runtime")
        let config := mul(add(n, 2), 32)
        datacopy(0, dataoffset("runtime"), size)
        codecopy(size, sub(codesize(), config), config)
        return(0, add(size, config))
    }
    object "runtime" {
        code {
            // ENTRY_POINT (0xaa) is the caller only in DEFAULT and VERIFY frames. Anything else,
            // such as a plain ETH transfer, is a no-op.
            if eq(caller(), 0xaa) {
                let frame := txparam(0x0a)
                if eq(frameparam(0x02, frame), 1) { validate(frame) } // mode == VERIFY
            }
            stop()

            function validate(frame) {
                let k := word(32)
                let n := word(64)
                // Owners into memory at 0x80, once.
                codecopy(0x80, sub(codesize(), mul(add(n, 2), 32)), mul(n, 32))
                let seen := 0
                let count := 0
                let sigs := txparam(0x0b)
                for { let i := 0 } lt(i, sigs) { i := add(i, 1) } {
                    let scheme := sigparam(0x01, i)
                    // SECP256K1 or P256 (resolved signer is defined), signing the sig hash (msg empty).
                    if and(or(eq(scheme, 1), eq(scheme, 2)), iszero(sigparam(0x02, i))) {
                        let signer := sigparam(0x00, i)
                        for { let j := 0 } lt(j, n) { j := add(j, 1) } {
                            if eq(mload(add(0x80, shl(5, j))), signer) {
                                let bit := shl(j, 1)
                                if iszero(and(seen, bit)) {
                                    seen := or(seen, bit)
                                    count := add(count, 1)
                                }
                                break
                            }
                        }
                    }
                }
                if lt(count, k) { revert(0, 0) }
                approve(frameparam(0x06, frame)) // whatever scope the frame allows
            }

            // A word counted from the end of the code: k at 32, n at 64.
            function word(fromEnd) -> v {
                codecopy(0, sub(codesize(), fromEnd), 32)
                v := mload(0)
            }

            // EIP-8141 opcodes. verbatim puts its first argument on top of the stack.
            function txparam(param) -> v { v := verbatim_1i_1o(hex"b0", param) }
            function frameparam(param, frame) -> v { v := verbatim_2i_1o(hex"b3", frame, param) }
            function sigparam(param, index) -> v { v := verbatim_2i_1o(hex"b4", index, param) }
            function approve(scope) { verbatim_3i_0o(hex"aa", 0, 0, scope) }
        }
    }
}
