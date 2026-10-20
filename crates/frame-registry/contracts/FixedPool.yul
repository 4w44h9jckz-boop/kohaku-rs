// FixedPool: the first application of the registry, experiment 06's pool as a rule. A note
// holds exactly DENOMINATION wei, and an update spends all of it, leaving no change note.
//
// An application is the registry's tag and nothing else: the registry holds the notes and the
// ether, and asks the application only whether a deposit or an update follows its rules. Both
// answers read nothing but this code, so the registry may ask from VERIFY.
//
//   accepts(uint256 value) -> bool                  a deposit of `value`
//   allows(uint256 withdrawn, bool change) -> bool  an update taking `withdrawn` out
//
// initcode = <this object> || DENOMINATION (32)
object "FixedPool" {
    code {
        let size := datasize("runtime")
        datacopy(0, dataoffset("runtime"), size)
        codecopy(size, sub(codesize(), 32), 32)
        return(0, add(size, 32))
    }
    object "runtime" {
        code {
            codecopy(0, sub(codesize(), 32), 32)
            let denomination := mload(0)
            switch shr(224, calldataload(0))
            case 0xce5ce723 { ret(eq(calldataload(4), denomination)) }
            case 0x396faf6a { ret(and(eq(calldataload(4), denomination), iszero(calldataload(0x24)))) }
            default { revert(0, 0) }

            function ret(v) {
                mstore(0, v)
                return(0, 0x20)
            }
        }
    }
}
