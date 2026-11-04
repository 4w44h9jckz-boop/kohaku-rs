// SphincsAccount: DeviceRecoveryAccount (exp-frames experiment 46) with every key a 32-byte
// leanSPHINCS public key and every signature an EIP-8288 dependency (exp-frames experiment 49).
// An owner key that m of n recovery keys can replace, after a delay the current owner can use to
// cancel. The account stores only keccak256(salt || m || n || keys) of the recovery keys,
// revealed in the VERIFY frame's data when they act.
//
// A key K authorises the transaction when the transaction declares the leanSPHINCS dependency
//   0x10 (32) || 0 (32) || K (32)
// whose zero data hash EIP-8288 reads as the transaction's signature hash. Where is the triple?
//   MODELLED = 0   in a dependency frame (mode 4), anywhere in the transaction; the block's
//                  proof checks the signature. A triple anywhere else counts for nothing.
//   MODELLED = 1   in this VERIFY frame's own data, after its body, for a chain without EIP-8288;
//                  nothing on chain checks the signature (the experiment checks it off chain).
//
// Storage: 0 owner key, 1 recovery commitment, 2 pending owner key (1 when none), 3 unlock time.
//
// VERIFY data = kind (1) || body || [MODELLED: triples]
//   0x00 owner          body empty; the owner's dependency; anything
//   0x01 recovery keys  body = salt (32) || m (1) || n (1) || keys (32 each), matching slot 1;
//                       m distinct keys of them, in ascending order, each declared; the
//                       transaction is [this VERIFY, dependency frames, SENDER -> self 0x01 || key]
//   0x02 pending owner  body empty; the pending owner's dependency;
//                       [this VERIFY, dependency frames, SENDER -> self 0x02]
//
// Operations, as SENDER frames the account sends to itself:
//   0x01 || key (32)         start a recovery: pending = key, unlock = now + DELAY
//   0x02                     finish it, if now >= unlock
//   0x03                     cancel it
//   0x04 || commitment (32)  replace the recovery commitment
//
// LOWER_BOUND as in DeviceRecoveryAccount: 1 refuses an early finish at admission on ethrex.
//
// initcode = <this object> || owner (32) || commitment (32) || DELAY (32) || LOWER_BOUND (32)
//            || MODELLED (32)
object "SphincsAccount" {
    code {
        let args := sub(codesize(), 160)
        codecopy(0, args, 160)
        sstore(0, mload(0))
        sstore(1, mload(32))
        sstore(2, 1)
        let n := datasize("runtime")
        datacopy(0, dataoffset("runtime"), n)
        codecopy(n, add(args, 64), 96)
        return(0, add(n, 96))
    }
    object "runtime" {
        code {
            if eq(caller(), 0xaa) {
                let frame := txparam(0x0a)
                if eq(frameparam(0x02, frame), 1) { validate(frame) } // mode == VERIFY
                stop()
            }
            if eq(caller(), address()) { operate() }
            stop()

            function validate(frame) {
                let len := frameparam(0x04, frame)
                if iszero(len) { fail() }
                let kind := shr(248, framedataload(frame, 0))
                let scope := frameparam(0x06, frame)
                switch kind
                case 0 {
                    if iszero(declared(sload(0), frame, 1)) { fail() }
                    approve(scope)
                }
                case 1 { recoveryKeys(frame, len, scope) }
                case 2 {
                    let pending := sload(2)
                    if eq(pending, 1) { fail() }
                    if iszero(declared(pending, frame, 1)) { fail() }
                    onlySelfCall(frame, 2, 1)
                    if lowerBound() { notBefore(sload(3)) }
                    approve(scope)
                }
                default { fail() }
            }

            function recoveryKeys(frame, len, scope) {
                if lt(len, 67) { fail() }
                let n := byte(0, framedataload(frame, 34))
                let body := add(34, mul(n, 32))
                if gt(add(1, body), len) { fail() }
                framedatacopy(0, 1, body, frame)
                if iszero(eq(keccak256(0, body), sload(1))) { fail() }
                let m := byte(0, mload(32))
                if or(iszero(m), gt(m, n)) { fail() }
                // The committed keys are strictly ascending, so distinct; m of them must be
                // declared.
                let prev := 0
                let count := 0
                for { let j := 0 } lt(j, n) { j := add(j, 1) } {
                    let key := mload(add(34, mul(j, 32)))
                    if iszero(gt(key, prev)) { fail() }
                    prev := key
                    if declared(key, frame, add(1, body)) { count := add(count, 1) }
                }
                if lt(count, m) { fail() }
                onlySelfCall(frame, 1, 33)
                let next := framedataload(sub(txparam(0x09), 1), 1)
                if or(iszero(next), eq(next, 1)) { fail() }
                approve(scope)
            }

            // Whether the triple 0x10 || 0 || key is declared: in a dependency frame, or, when
            // MODELLED, in this frame's own data from `start`.
            function declared(key, frame, start) -> ok {
                if modelled() {
                    let len := frameparam(0x04, frame)
                    for { let o := start } iszero(gt(add(o, 96), len)) { o := add(o, 96) } {
                        if matches(frame, o, key) {
                            ok := 1
                            leave
                        }
                    }
                    leave
                }
                let count := txparam(0x09)
                for { let i := 0 } lt(i, count) { i := add(i, 1) } {
                    if eq(frameparam(0x02, i), 4) {
                        let len := frameparam(0x04, i)
                        for { let o := 0 } lt(o, len) { o := add(o, 96) } {
                            if matches(i, o, key) {
                                ok := 1
                                leave
                            }
                        }
                    }
                }
            }
            function matches(f, o, key) -> r {
                r := and(
                    and(eq(framedataload(f, o), 0x10), iszero(framedataload(f, add(o, 32)))),
                    eq(framedataload(f, add(o, 64)), key)
                )
            }

            // The expiry verifier refuses once block.timestamp > deadline. Called with unlock - 1,
            // it refuses exactly when block.timestamp >= unlock, which is when this may pass.
            function notBefore(unlock) {
                mstore(0, shl(192, sub(unlock, 1)))
                if staticcall(30000, 0x8141, 0, 8, 0, 0) { fail() }
            }

            // The transaction is [frame 0: this VERIFY, dependency frames, last: SENDER -> self,
            // op, len bytes].
            function onlySelfCall(frame, op, len) {
                if frame { fail() }
                let last := sub(txparam(0x09), 1)
                if lt(last, 1) { fail() }
                for { let i := 1 } lt(i, last) { i := add(i, 1) } {
                    if iszero(eq(frameparam(0x02, i), 4)) { fail() }
                }
                if iszero(eq(frameparam(0x02, last), 2)) { fail() }
                if iszero(eq(frameparam(0x00, last), address())) { fail() }
                if frameparam(0x08, last) { fail() }
                if iszero(eq(frameparam(0x04, last), len)) { fail() }
                if iszero(eq(shr(248, framedataload(last, 0)), op)) { fail() }
            }

            function operate() {
                switch shr(248, calldataload(0))
                case 1 {
                    if iszero(eq(calldatasize(), 33)) { fail() }
                    let next := calldataload(1)
                    if or(iszero(next), eq(next, 1)) { fail() }
                    sstore(2, next)
                    sstore(3, add(timestamp(), delay()))
                }
                case 2 {
                    if iszero(eq(calldatasize(), 1)) { fail() }
                    let next := sload(2)
                    if eq(next, 1) { fail() }
                    if lt(timestamp(), sload(3)) { fail() }
                    sstore(0, next)
                    sstore(2, 1)
                }
                case 3 {
                    if iszero(eq(calldatasize(), 1)) { fail() }
                    sstore(2, 1)
                }
                case 4 {
                    if iszero(eq(calldatasize(), 33)) { fail() }
                    sstore(1, calldataload(1))
                }
                default { fail() }
            }

            function immutable(fromEnd) -> v {
                codecopy(0, sub(codesize(), fromEnd), 32)
                v := mload(0)
            }
            function delay() -> d { d := immutable(96) }
            function lowerBound() -> b { b := immutable(64) }
            function modelled() -> b { b := immutable(32) }
            function fail() { revert(0, 0) }

            function txparam(param) -> v { v := verbatim_1i_1o(hex"b0", param) }
            function framedataload(frame, offset) -> v { v := verbatim_2i_1o(hex"b1", offset, frame) }
            function framedatacopy(memOffset, dataOffset, length, frame) {
                verbatim_4i_0o(hex"b2", memOffset, dataOffset, length, frame)
            }
            function frameparam(param, frame) -> v { v := verbatim_2i_1o(hex"b3", frame, param) }
            function approve(scope) { verbatim_3i_0o(hex"aa", 0, 0, scope) }
        }
    }
}
