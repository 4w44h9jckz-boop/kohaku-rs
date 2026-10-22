// SessionAccount: one owner key with full control, plus session keys the owner grants. A session
// key may sign transactions that only call one target with one selector, until a deadline, within
// a budget that counts the value sent and the transaction's maximum fee.
//
// A session transaction has exactly this shape, and VERIFY checks every frame of it:
//
//   0  VERIFY  -> EXPIRY_VERIFIER (0x8141)  deadline <= session.validUntil
//   1  VERIFY  -> sender                    this frame; entry 0 signed by the session key
//   2  SENDER  -> sender                    0x03 ‖ key (20) ‖ amount (32), no flags, no value,
//                                           >= 30,000 execution gas
//   3+ SENDER  -> session.target            data empty if selector = 0, else starting with it
//
// amount must be at least TXPARAM(0x06) (the maximum cost) plus the value of frames 3+, and
// spent + amount must stay within budget. "At least" rather than "equal": the maximum cost
// includes the calldata cost of the signature, which is not known until the amount is signed. VERIFY runs static, so it cannot record the spend
// itself; frame 2 does, and VERIFY makes sure frame 2 cannot fail. TIMESTAMP is banned in VERIFY,
// so the session's expiry is enforced by requiring the expiry frame and bounding its deadline.
//
// Storage, per session key k at base = keccak256(k):
//   base     target (20) ‖ selector (4) ‖ validUntil (8)
//   base + 1 budget, in wei
//   base + 2 1 + spent, in wei (starts at 1 so that a spend never writes a fresh slot)
//
// Owner operations are SENDER frames the account sends to itself (caller == address()):
//   0x01 ‖ key (20) ‖ target (20) ‖ selector (4) ‖ validUntil (8) ‖ budget (16)   add a session
//   0x02 ‖ key (20)                                                            revoke it
//   0x03 ‖ key (20) ‖ amount (32)                                              record a spend
//
// initcode = <this object> ‖ owner (32)
object "SessionAccount" {
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
                stop()
            }
            if eq(caller(), address()) { operate() }
            stop()

            function validate(frame) {
                if iszero(txparam(0x0b)) { fail() }
                if iszero(sigparam(0x01, 0)) { fail() }   // a protocol scheme, not ARBITRARY
                if sigparam(0x02, 0) { fail() }           // msg empty: signs the sig hash
                let signer := sigparam(0x00, 0)
                let scope := frameparam(0x06, frame)
                if eq(signer, owner()) { approve(scope) }

                let base := slotOf(signer)
                let policy := sload(base)
                if iszero(policy) { fail() }
                let target := shr(96, policy)
                let selector := and(shr(64, policy), 0xffffffff)

                // frame 0: the expiry frame, with a deadline inside the session
                if iszero(eq(frame, 1)) { fail() }
                if iszero(eq(frameparam(0x00, 0), 0x8141)) { fail() }
                if iszero(eq(frameparam(0x02, 0), 1)) { fail() }
                if iszero(eq(frameparam(0x04, 0), 8)) { fail() }
                if gt(shr(192, framedataload(0, 0)), and(policy, 0xffffffffffffffff)) { fail() }

                // frame 2: the spend record, which must not be able to fail
                let n := txparam(0x09)
                if lt(n, 4) { fail() }
                if iszero(eq(frameparam(0x02, 2), 2)) { fail() }
                if iszero(eq(frameparam(0x00, 2), address())) { fail() }
                if frameparam(0x03, 2) { fail() }
                if frameparam(0x08, 2) { fail() }
                if lt(frameparam(0x01, 2), 30000) { fail() }
                if iszero(eq(frameparam(0x04, 2), 53)) { fail() }
                if iszero(eq(shr(248, framedataload(2, 0)), 3)) { fail() }
                if iszero(eq(shr(96, framedataload(2, 1)), signer)) { fail() }

                // frames 3..n-1: calls the session allows; total = max cost + value sent
                let total := txparam(0x06)
                for { let i := 3 } lt(i, n) { i := add(i, 1) } {
                    if iszero(eq(frameparam(0x02, i), 2)) { fail() }
                    if iszero(eq(frameparam(0x00, i), target)) { fail() }
                    let len := frameparam(0x04, i)
                    switch selector
                    case 0 { if len { fail() } }
                    default {
                        if lt(len, 4) { fail() }
                        if iszero(eq(shr(224, framedataload(i, 0)), selector)) { fail() }
                    }
                    let v := frameparam(0x08, i)
                    total := add(total, v)
                    if lt(total, v) { fail() }
                }
                let amount := framedataload(2, 21)
                if lt(amount, total) { fail() }
                let spent := add(sload(add(base, 2)), amount)
                if lt(spent, amount) { fail() }
                if gt(spent, add(sload(add(base, 1)), 1)) { fail() }
                approve(scope)
            }

            function operate() {
                let op := shr(248, calldataload(0))
                let base := slotOf(shr(96, calldataload(1)))
                switch op
                case 1 {
                    if iszero(eq(calldatasize(), 69)) { fail() }
                    let policy := calldataload(21)
                    let target := shr(96, policy)
                    if or(iszero(target), eq(target, address())) { fail() }
                    sstore(base, policy)
                    sstore(add(base, 1), shr(128, calldataload(53)))
                    sstore(add(base, 2), 1)
                }
                case 2 {
                    if iszero(eq(calldatasize(), 21)) { fail() }
                    sstore(base, 0)
                    sstore(add(base, 1), 0)
                    sstore(add(base, 2), 0)
                }
                case 3 {
                    if iszero(eq(calldatasize(), 53)) { fail() }
                    let amount := calldataload(21)
                    let spent := add(sload(add(base, 2)), amount)
                    if lt(spent, amount) { fail() }
                    if gt(spent, add(sload(add(base, 1)), 1)) { fail() }
                    sstore(add(base, 2), spent)
                }
                default { fail() }
            }

            function owner() -> o {
                codecopy(0, sub(codesize(), 32), 32)
                o := mload(0)
            }
            function slotOf(key) -> s {
                mstore(0, key)
                s := keccak256(0, 32)
            }
            function fail() { revert(0, 0) }

            function txparam(param) -> v { v := verbatim_1i_1o(hex"b0", param) }
            function framedataload(frame, offset) -> v { v := verbatim_2i_1o(hex"b1", offset, frame) }
            function frameparam(param, frame) -> v { v := verbatim_2i_1o(hex"b3", frame, param) }
            function sigparam(param, index) -> v { v := verbatim_2i_1o(hex"b4", index, param) }
            function approve(scope) { verbatim_3i_0o(hex"aa", 0, 0, scope) }
        }
    }
}
