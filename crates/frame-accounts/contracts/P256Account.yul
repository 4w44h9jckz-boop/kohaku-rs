// P256Account: experiment 02's SimpleAccount with a P256 owner instead of a secp256k1 one.
//
// The protocol validates P256 entries (scheme 0x2: r || s || qx || qy, low s, signer =
// keccak256(qx || qy)[12:]) before any frame runs, exactly as it does secp256k1 ones. The account
// only confirms with SIGPARAM that entry 0 is a P256 signature by its owner over the canonical
// sig hash. No P256VERIFY in the EVM, no storage.
//
// It exists because the default code accepts SECP256K1 only: an address derived from a P256 key
// cannot send a frame transaction on its own until something is deployed there.
//
// initcode = <this object> ‖ abi.encode(owner)   where owner = keccak256(qx || qy)[12:]
object "P256Account" {
    code {
        let n := datasize("runtime")
        datacopy(0, dataoffset("runtime"), n)
        codecopy(n, sub(codesize(), 32), 32)
        return(0, add(n, 32))
    }
    object "runtime" {
        code {
            if eq(caller(), 0xaa) {
                let frame := txparam(0x0a)
                if eq(frameparam(0x02, frame), 1) { validate(frame) } // mode == VERIFY
            }
            stop()

            function validate(frame) {
                if iszero(txparam(0x0b)) { revert(0, 0) }                  // len(signatures) > 0
                if iszero(eq(sigparam(0x01, 0), 2)) { revert(0, 0) }       // scheme == P256
                if iszero(eq(sigparam(0x00, 0), owner())) { revert(0, 0) } // resolved signer == owner
                if sigparam(0x02, 0) { revert(0, 0) }                      // msg empty: signs the sig hash
                approve(frameparam(0x06, frame))
            }

            function owner() -> o {
                codecopy(0, sub(codesize(), 32), 32)
                o := mload(0)
            }

            function txparam(param) -> v { v := verbatim_1i_1o(hex"b0", param) }
            function frameparam(param, frame) -> v { v := verbatim_2i_1o(hex"b3", frame, param) }
            function sigparam(param, index) -> v { v := verbatim_2i_1o(hex"b4", index, param) }
            function approve(scope) { verbatim_3i_0o(hex"aa", 0, 0, scope) }
        }
    }
}
