// SimpleAccount: the smallest smart account that can validate an EIP-8141 frame transaction.
//
// Authentication reuses the protocol's signature list instead of running ecrecover in the EVM:
// before any frame runs, the protocol has already checked every SECP256K1 entry in
// tx.signatures. The account only has to confirm (via SIGPARAM) that entry 0 is a secp256k1
// signature by its owner over the canonical signature hash. That hash commits to every frame,
// so the approval cannot be reused with different frames.
//
// The owner is appended to the runtime code at deployment and read back with CODECOPY, so the
// VERIFY path touches no storage at all.
//
// initcode = <this object> ‖ abi.encode(owner)
object "SimpleAccount" {
    code {
        let n := datasize("runtime")
        datacopy(0, dataoffset("runtime"), n)
        codecopy(n, sub(codesize(), 32), 32)
        return(0, add(n, 32))
    }
    object "runtime" {
        code {
            // ENTRY_POINT (0xaa) is the caller only in DEFAULT and VERIFY frames of a frame tx.
            if eq(caller(), 0xaa) {
                let frame := txparam(0x0a) // index of the executing frame
                if eq(frameparam(0x02, frame), 1) { validate(frame) } // mode == VERIFY
            }
            // Any other call (e.g. receiving ETH) is a no-op.
            stop()

            function validate(frame) {
                if iszero(txparam(0x0b)) { revert(0, 0) }                  // len(signatures) > 0
                if iszero(eq(sigparam(0x01, 0), 1)) { revert(0, 0) }       // scheme == SECP256K1
                if iszero(eq(sigparam(0x00, 0), owner())) { revert(0, 0) } // resolved signer == owner
                if sigparam(0x02, 0) { revert(0, 0) }                      // msg empty: signs the sig hash
                approve(frameparam(0x06, frame))                           // whatever scope the frame allows
            }

            function owner() -> o {
                codecopy(0, sub(codesize(), 32), 32)
                o := mload(0)
            }

            // EIP-8141 opcodes. verbatim puts its first argument on top of the stack.
            function txparam(param) -> v { v := verbatim_1i_1o(hex"b0", param) }
            function frameparam(param, frame) -> v { v := verbatim_2i_1o(hex"b3", frame, param) }
            function sigparam(param, index) -> v { v := verbatim_2i_1o(hex"b4", index, param) }
            function approve(scope) { verbatim_3i_0o(hex"aa", 0, 0, scope) }
        }
    }
}
