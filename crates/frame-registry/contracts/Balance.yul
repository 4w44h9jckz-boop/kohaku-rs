// Balance: the second application of the registry. A note is a balance of any size, and an
// update takes any part of it, at most CAP wei, and leaves the rest in a change note.
//
// Same interface as FixedPool: both answers read nothing but this code.
//
//   accepts(uint256 value) -> bool                  any deposit above zero
//   allows(uint256 withdrawn, bool change) -> bool  withdrawn <= CAP, with or without change
//
// initcode = <this object> || CAP (32)
object "Balance" {
    code {
        let size := datasize("runtime")
        datacopy(0, dataoffset("runtime"), size)
        codecopy(size, sub(codesize(), 32), 32)
        return(0, add(size, 32))
    }
    object "runtime" {
        code {
            codecopy(0, sub(codesize(), 32), 32)
            let cap := mload(0)
            switch shr(224, calldataload(0))
            case 0xce5ce723 { ret(gt(calldataload(4), 0)) }
            case 0x396faf6a { ret(iszero(gt(calldataload(4), cap))) }
            default { revert(0, 0) }

            function ret(v) {
                mstore(0, v)
                return(0, 0x20)
            }
        }
    }
}
