// Vault: one application's custody. It holds the ether deposited for the application and pays
// only that application's withdrawals, from its own balance, when the registry calls it.
//
// Its rules are experiment 32's applications', answered from its code alone, so the registry's
// VERIFY may call them:
//
//   kind 0, FixedPool: a deposit of exactly `amount`, spent whole, no change note;
//   kind 1, Balance:   a deposit of any amount below 2^64, at most `amount` out per withdrawal.
//
// params() is SHA-256(0x90 || kind || amount): what the registry hashes into the vault's scope,
// beside the chain's identifier and the vault's address.
//
// Ether arrives only through fund(), from the registry, in the same call as the note's
// insertion; it leaves only through pay(), on the registry's call. A payee that cannot receive is
// credited here, and claim() pays it later. So the vault's balance is what its depositors paid
// in, less what it paid out, plus what it owes.
//
// initcode = <this object> || registry (32) || kind (32) || amount (32)
object "Vault" {
    code {
        let size := datasize("runtime")
        datacopy(0, dataoffset("runtime"), size)
        codecopy(size, sub(codesize(), 96), 96)
        return(0, add(size, 96))
    }
    object "runtime" {
        code {
            let kind := word(64)
            let amount := word(32)
            switch shr(224, calldataload(0))
            case 0xce5ce723 { // accepts(uint256)
                let value := calldataload(4)
                switch kind
                case 0 { ret(eq(value, amount)) }
                default { ret(and(gt(value, 0), iszero(shr(64, value)))) }
            }
            case 0x396faf6a { // allows(uint256,bool)
                let withdrawn := calldataload(4)
                let change := calldataload(0x24)
                switch kind
                case 0 { ret(and(eq(withdrawn, amount), iszero(change))) }
                default { ret(and(gt(withdrawn, 0), iszero(gt(withdrawn, amount)))) }
            }
            case 0xcff0ab96 { // params()
                mstore8(0, 0x90)
                mstore(1, kind)
                mstore(0x21, amount)
                if iszero(staticcall(gas(), 0x02, 0, 0x41, 0, 0x20)) { revert(0, 0) }
                return(0, 0x20)
            }
            case 0xb60d4288 { // fund()
                if iszero(eq(caller(), word(96))) { revert(0, 0) }
                stop()
            }
            case 0xc4076876 { // pay(address,uint256)
                if iszero(eq(caller(), word(96))) { revert(0, 0) }
                let to := calldataload(4)
                let value := calldataload(0x24)
                if gt(value, selfbalance()) { revert(0, 0) }
                if iszero(call(PAYOUT_STIPEND(), to, value, 0, 0, 0, 0)) {
                    let s := owedSlot(to)
                    sstore(s, add(sload(s), value))
                }
                mstore(0, value)
                log2(0, 0x20, 0x737c69225d647e5994eab1a6c301bf6d9232beb2759ae1e27a8966b4732bc489, to)
                stop()
            }
            case 0x1e83409a { // claim(address)
                let who := calldataload(4)
                let s := owedSlot(who)
                let value := sload(s)
                sstore(s, 0)
                if iszero(call(gas(), who, value, 0, 0, 0, 0)) { revert(0, 0) }
                stop()
            }
            case 0xdf18e047 { ret(sload(owedSlot(calldataload(4)))) } // owed(address)
            case 0x7b103999 { ret(word(96)) }                          // registry()
            default { revert(0, 0) }

            // A payee gets a fixed stipend, so it cannot starve the registry's update frame.
            function PAYOUT_STIPEND() -> g { g := 50000 }

            function owedSlot(who) -> s {
                mstore(0, who)
                mstore(0x20, 1)
                s := keccak256(0, 0x40)
            }

            // A constructor word, counted from the end of the code. Uses scratch at 0x60.
            function word(fromEnd) -> v {
                codecopy(0x60, sub(codesize(), fromEnd), 32)
                v := mload(0x60)
            }

            function ret(v) {
                mstore(0, v)
                return(0, 0x20)
            }
        }
    }
}
