// StoredRule: the control. An application whose update rule reads its own storage, as an
// application with a balance in its own contract would. The registry asks it from VERIFY, so
// the read is of storage outside the sender, which the frame pool's trace rules refuse.
//
//   accepts(uint256 value) -> bool                  any deposit above zero
//   allows(uint256 withdrawn, bool change) -> bool  withdrawn <= the cap in slot 0
//
// initcode = <this object> || cap (32), stored in slot 0
object "StoredRule" {
    code {
        codecopy(0, sub(codesize(), 32), 32)
        sstore(0, mload(0))
        let size := datasize("runtime")
        datacopy(0, dataoffset("runtime"), size)
        return(0, size)
    }
    object "runtime" {
        code {
            switch shr(224, calldataload(0))
            case 0xce5ce723 { ret(gt(calldataload(4), 0)) }
            case 0x396faf6a { ret(iszero(gt(calldataload(4), sload(0)))) }
            default { revert(0, 0) }

            function ret(v) {
                mstore(0, v)
                return(0, 0x20)
            }
        }
    }
}
