// SphincsSender: a one-key leanSPHINCS account small enough to deploy itself in its own first
// transaction (EIP-8141's Example 1b), whose state gas the validation prefix caps at 500,000, so
// at 206 bytes of code (exp-frames experiment 49). Its key is in its code, so it writes no slot.
//
// VERIFY approves, with its frame's scope, when the transaction declares the leanSPHINCS
// dependency 0x10 (32) || 0 (32) || KEY (32), the zero data hash standing for the signature hash:
//   MODELLED = 0   in a dependency frame (mode 4);
//   MODELLED = 1   in this VERIFY frame's own data (a chain without EIP-8288; checked off chain).
// Calls go out as SENDER frames, which run as the account; the code does nothing else.
//
// initcode = <this object> || MODELLED (1) || KEY (32)
object "SphincsSender" {
    code {
        let n := datasize("runtime")
        datacopy(0, dataoffset("runtime"), n)
        codecopy(n, sub(codesize(), 33), 33)
        return(0, add(n, 33))
    }
    object "runtime" {
        code {
            if iszero(eq(caller(), 0xaa)) { stop() }
            let me := verbatim_1i_1o(hex"b0", 0x0a)
            if iszero(eq(param(0x02, me), 1)) { revert(0, 0) }
            codecopy(0, sub(codesize(), 33), 33)
            let key := mload(1)
            let first := 0
            let last := verbatim_1i_1o(hex"b0", 0x09)
            if byte(0, mload(0)) {
                first := me
                last := add(me, 1)
            }
            for { let i := first } lt(i, last) { i := add(i, 1) } {
                if or(eq(param(0x02, i), 4), byte(0, mload(0))) {
                    let len := param(0x04, i)
                    for { let o := 0 } lt(o, len) { o := add(o, 96) } {
                        if and(
                            and(eq(load(i, o), 0x10), iszero(load(i, add(o, 32)))),
                            eq(load(i, add(o, 64)), key)
                        ) {
                            verbatim_3i_0o(hex"aa", 0, 0, param(0x06, me))
                            stop()
                        }
                    }
                }
            }
            revert(0, 0)

            function param(p, f) -> v { v := verbatim_2i_1o(hex"b3", f, p) }
            function load(f, o) -> v { v := verbatim_2i_1o(hex"b1", o, f) }
        }
    }
}
