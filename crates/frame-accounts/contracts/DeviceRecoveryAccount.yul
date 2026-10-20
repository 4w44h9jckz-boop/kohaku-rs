// DeviceRecoveryAccount: experiment 13's RecoveryAccount (v2) with the guardians replaced by the
// owner's own devices. An owner key that m of the owner's n devices can replace, after a delay
// the current owner can use to cancel. Nobody but the owner holds anything: the devices are the
// owner's, and the account stores only keccak256(salt || m || devices), revealed in the VERIFY
// frame's data when the devices act.
//
// Storage: 0 owner, 1 device commitment, 2 recovery = pending owner (20) || unlock time (12), or
// 1 when none is pending. Slot 2 never returns to zero (experiment 13, observation 2).
//
// VERIFY accepts three kinds of transaction:
//   owner          entry 0 signed by the owner (sload(0)); anything
//   devices        this frame's data = salt (32) || m (1) || devices (20 each), matching slot 1;
//                  entries 0..m-1 signed by distinct devices in ascending order; the
//                  transaction is exactly [this VERIFY, SENDER -> self 0x01 || newOwner]
//   pending owner  entry 0 signed by the pending owner; exactly [this VERIFY, SENDER -> self 0x02]
//
// Operations, as SENDER frames the account sends to itself:
//   0x01 || newOwner (20)   start a recovery: pending = newOwner, unlock = now + DELAY
//   0x02                    finish it, if now >= unlock
//   0x03                    cancel it
//   0x04 || commitment (32) replace the device commitment
//
// When is a finish too early? Two rules, chosen at deployment by LOWER_BOUND:
//   0  the EIP's: TIMESTAMP is banned in VERIFY and the expiry frame bounds time from above only,
//      so the delay is enforced by 0x02 in execution. An early finish is admitted, included, and
//      reverts in its finish frame.
//   1  ethrex's: ethrex allows TIMESTAMP wherever the expiry verifier's code runs, at any call
//      depth (experiment 19, probe 30). The pending owner's VERIFY calls 0x8141 with unlock - 1
//      and requires it to revert, so an early finish is refused at admission. 0x02 still checks
//      in execution. A client that follows the EIP's wording halts this VERIFY, so such an
//      account can be recovered only on ethrex.
//
// initcode = <this object> || owner (32) || commitment (32) || DELAY (32) || LOWER_BOUND (32)
object "DeviceRecoveryAccount" {
    code {
        let args := sub(codesize(), 128)
        codecopy(0, args, 128)
        sstore(0, mload(0))
        sstore(1, mload(32))
        sstore(2, 1)
        let n := datasize("runtime")
        datacopy(0, dataoffset("runtime"), n)
        codecopy(n, add(args, 64), 64)
        return(0, add(n, 64))
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
                if frameparam(0x04, frame) { devices(frame) }
                if iszero(txparam(0x0b)) { fail() }
                if iszero(sigparam(0x01, 0)) { fail() }       // a protocol scheme
                if sigparam(0x02, 0) { fail() }               // msg empty
                let signer := sigparam(0x00, 0)
                let scope := frameparam(0x06, frame)
                if eq(signer, sload(0)) { approve(scope) }
                let pending := shr(96, sload(2))
                if iszero(pending) { fail() }
                if iszero(eq(signer, pending)) { fail() }
                onlySelfCall(frame, 2, 1)
                if lowerBound() { notBefore(and(sload(2), 0xffffffffffffffffffffffff)) }
                approve(scope)
            }

            // The expiry verifier refuses once block.timestamp > deadline. Called with unlock - 1,
            // it refuses exactly when block.timestamp >= unlock, which is when this may pass.
            function notBefore(unlock) {
                mstore(0, shl(192, sub(unlock, 1)))
                if staticcall(30000, 0x8141, 0, 8, 0, 0) { fail() }
            }

            function devices(frame) {
                let len := frameparam(0x04, frame)
                if lt(len, 53) { fail() }
                if mod(sub(len, 33), 20) { fail() }
                framedatacopy(0, 0, len, frame)
                if iszero(eq(keccak256(0, len), sload(1))) { fail() }
                let m := byte(0, mload(32))
                let count := div(sub(len, 33), 20)
                if or(iszero(m), gt(m, count)) { fail() }
                if lt(txparam(0x0b), m) { fail() }
                let prev := 0
                for { let i := 0 } lt(i, m) { i := add(i, 1) } {
                    if iszero(sigparam(0x01, i)) { fail() }
                    if sigparam(0x02, i) { fail() }
                    let signer := sigparam(0x00, i)
                    if iszero(gt(signer, prev)) { fail() }    // distinct, ascending
                    prev := signer
                    let found := 0
                    for { let j := 0 } lt(j, count) { j := add(j, 1) } {
                        if eq(shr(96, mload(add(33, mul(j, 20)))), signer) { found := 1 }
                    }
                    if iszero(found) { fail() }
                }
                onlySelfCall(frame, 1, 21)
                if iszero(shr(96, framedataload(1, 1))) { fail() }
                approve(frameparam(0x06, frame))
            }

            // The transaction is [frame 0: this VERIFY, frame 1: SENDER -> self, op, len bytes].
            function onlySelfCall(frame, op, len) {
                if frame { fail() }
                if iszero(eq(txparam(0x09), 2)) { fail() }
                if iszero(eq(frameparam(0x02, 1), 2)) { fail() }
                if iszero(eq(frameparam(0x00, 1), address())) { fail() }
                if frameparam(0x08, 1) { fail() }
                if iszero(eq(frameparam(0x04, 1), len)) { fail() }
                if iszero(eq(shr(248, framedataload(1, 0)), op)) { fail() }
            }

            function operate() {
                switch shr(248, calldataload(0))
                case 1 {
                    if iszero(eq(calldatasize(), 21)) { fail() }
                    let next := shr(96, calldataload(1))
                    if iszero(next) { fail() }
                    sstore(2, or(shl(96, next), add(timestamp(), delay())))
                }
                case 2 {
                    if iszero(eq(calldatasize(), 1)) { fail() }
                    let recovery := sload(2)
                    let next := shr(96, recovery)
                    if iszero(next) { fail() }
                    if lt(timestamp(), and(recovery, 0xffffffffffffffffffffffff)) { fail() }
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

            function delay() -> d {
                codecopy(0, sub(codesize(), 64), 32)
                d := mload(0)
            }
            function lowerBound() -> b {
                codecopy(0, sub(codesize(), 32), 32)
                b := mload(0)
            }
            function fail() { revert(0, 0) }

            function txparam(param) -> v { v := verbatim_1i_1o(hex"b0", param) }
            function framedataload(frame, offset) -> v { v := verbatim_2i_1o(hex"b1", offset, frame) }
            function framedatacopy(memOffset, dataOffset, length, frame) {
                verbatim_4i_0o(hex"b2", memOffset, dataOffset, length, frame)
            }
            function frameparam(param, frame) -> v { v := verbatim_2i_1o(hex"b3", frame, param) }
            function sigparam(param, index) -> v { v := verbatim_2i_1o(hex"b4", index, param) }
            function approve(scope) { verbatim_3i_0o(hex"aa", 0, 0, scope) }
        }
    }
}
