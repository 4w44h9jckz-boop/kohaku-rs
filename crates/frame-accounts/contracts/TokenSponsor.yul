// TokenSponsor: pays gas in ETH for anyone who pays it in one ERC-20 token (EIP-8141 Example 3).
//
// VERIFY (pay frame, flags = APPROVE_PAYMENT): the frame right after this one must be a stand-alone
// SENDER frame calling token.transfer(this, amount) with amount >= max_cost * RATE. The check
// reads only the transaction (TXPARAM, FRAMEPARAM, FRAMEDATALOAD) and this contract's own code,
// never the token's storage, as the public mempool requires of a pay frame. So the sponsor cannot
// know the sender holds the tokens: a sender who empties its balance first still gets its gas
// paid (the risk the EIP's note on Example 3 describes).
//
// DEFAULT (post-op, last frame only): if this contract paid and the fee transfer succeeded,
// refund the tokens for the gas the earlier frames left unused, priced at max_fee_per_gas. The
// sponsor keeps the post-op frame's own unused gas and the gap between max fee and the
// effective price. In a transaction that settles at the calldata floor, unused execution gas
// is not returned to the payer in full, so this refund can exceed what the sponsor got back by
// up to ~60 gas per byte of transaction data. A production sponsor would price that in.
//
// Owner, no value, any data: sweep the sponsor's tokens and ETH to the owner.
//
// initcode = <this object> ‖ abi.encode(token, rate, owner)
// rate = token base units per wei.
object "TokenSponsor" {
    code {
        let n := datasize("runtime")
        datacopy(0, dataoffset("runtime"), n)
        codecopy(n, sub(codesize(), 96), 96)
        return(0, add(n, 96))
    }
    object "runtime" {
        code {
            if eq(caller(), 0xaa) {
                let frame := txparam(0x0a)
                switch frameparam(0x02, frame)
                case 1 { validate(frame) } // VERIFY
                case 0 { postOp(frame) }   // DEFAULT
            }
            if and(eq(caller(), owner()), iszero(callvalue())) { sweep() }
            stop()

            function validate(frame) {
                if iszero(eq(frameparam(0x06, frame), 1)) { revert(0, 0) }   // flags allow exactly PAYMENT
                let fee := add(frame, 1)
                if iszero(lt(fee, txparam(0x09))) { revert(0, 0) }          // a next frame exists
                if iszero(eq(frameparam(0x02, fee), 2)) { revert(0, 0) }     // SENDER
                if iszero(eq(frameparam(0x00, fee), token())) { revert(0, 0) }
                if frameparam(0x07, fee) { revert(0, 0) }                    // not in an atomic batch
                if iszero(eq(frameparam(0x04, fee), 68)) { revert(0, 0) }
                if iszero(eq(shr(224, framedataload(fee, 0)), 0xa9059cbb)) { revert(0, 0) } // transfer(address,uint256)
                if iszero(eq(framedataload(fee, 4), address())) { revert(0, 0) }
                if lt(framedataload(fee, 36), price(txparam(0x06))) { revert(0, 0) }        // amount >= max_cost * rate
                approve(1)
            }

            function postOp(frame) {
                let frames := txparam(0x09)
                if iszero(eq(add(frame, 1), frames)) { revert(0, 0) }       // last frame: refunds at most once
                let pay := payFrame(frame)
                let fee := add(pay, 1)
                if iszero(eq(frameparam(0x05, fee), 1)) { revert(0, 0) }    // the fee transfer succeeded
                let unused := 0
                for { let j := 0 } lt(j, frame) { j := add(j, 1) } {
                    unused := add(unused, sub(
                        add(frameparam(0x01, j), frameparam(0x09, j)),       // limits.execution + limits.state
                        add(frameparam(0x0a, j), frameparam(0x0b, j))        // gas_used.execution + gas_used.state
                    ))
                }
                let paid := framedataload(fee, 36)
                let kept := price(sub(txparam(0x06), mul(unused, txparam(0x04))))
                if gt(paid, kept) { transfer(txparam(0x02), sub(paid, kept)) }
            }

            // The VERIFY frame that made this contract the payer. VERIFY frames cannot fail without
            // invalidating the transaction, so if it is there, it approved.
            function payFrame(frame) -> pay {
                pay := frame
                for { let j := 0 } lt(j, frame) { j := add(j, 1) } {
                    if and(eq(frameparam(0x02, j), 1), and(eq(frameparam(0x00, j), address()), eq(frameparam(0x06, j), 1))) {
                        pay := j
                        break
                    }
                }
                if eq(pay, frame) { revert(0, 0) }
            }

            function price(wei) -> amount {
                amount := mul(wei, rate())
                if iszero(eq(div(amount, rate()), wei)) { revert(0, 0) }
            }

            function transfer(to, amount) {
                mstore(0, shl(224, 0xa9059cbb))
                mstore(4, to)
                mstore(36, amount)
                if iszero(call(gas(), token(), 0, 0, 68, 0, 32)) { revert(0, 0) }
            }

            function sweep() {
                mstore(0, shl(224, 0x70a08231)) // balanceOf(address)
                mstore(4, address())
                if iszero(staticcall(gas(), token(), 0, 36, 0, 32)) { revert(0, 0) }
                let held := mload(0)
                if held { transfer(owner(), held) }
                if iszero(call(gas(), owner(), selfbalance(), 0, 0, 0, 0)) { revert(0, 0) }
            }

            function token() -> t { t := arg(96) }
            function rate() -> r { r := arg(64) }
            function owner() -> o { o := arg(32) }
            // The three constructor arguments sit at the end of the code. Read them through their
            // own scratch word: transfer() builds calldata at 0..100 and only then evaluates token().
            function arg(fromEnd) -> v {
                codecopy(0x80, sub(codesize(), fromEnd), 32)
                v := mload(0x80)
            }

            // EIP-8141 opcodes. verbatim puts its first argument on top of the stack.
            function txparam(param) -> v { v := verbatim_1i_1o(hex"b0", param) }
            function framedataload(frame, offset) -> v { v := verbatim_2i_1o(hex"b1", offset, frame) }
            function frameparam(param, frame) -> v { v := verbatim_2i_1o(hex"b3", frame, param) }
            function approve(scope) { verbatim_3i_0o(hex"aa", 0, 0, scope) }
        }
    }
}
