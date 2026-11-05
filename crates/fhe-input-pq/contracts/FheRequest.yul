// FheRequest: accepts one TFHE input per transaction when the transaction declares the leanSTARK
// dependency that proves the input well formed (exp-frames experiment 41, the post-quantum run).
// The contract is the transaction's sender and pays its own gas:
//
//   [0] VERIFY -> self       data: MODELLED: the triple (96); otherwise empty
//   [1] DEP_VERIFY (mode 4)  data: the triple (96)                    (EIP-8288 chains only)
//   [n-1] SENDER -> self     data: requester (32) || ciphertext (CTLEN)
//
// The triple is 0x11 (32) || D (32) || VK (32), VK the program's key, and
//   D  = keccak256(keccak256(HPK || keccak256(ciphertext)) || mu)
//   mu = keccak256(DOMAIN || chain id || this || request number || requester)
// with HPK keccak256 of the TFHE key's bytes and the request number this account's nonce. A
// proof made for one request fits no other: another ciphertext, number, requester, chain or
// contract changes D. VERIFY checks only that the triple is declared: on a chain that runs
// EIP-8288 (extended to leanSTARK) the block is valid only if its proof verifies; on the test
// network (MODELLED = 1) nothing on chain checks it, and the experiment checks it off chain.
//
// The request frame records keccak256(ciphertext) at keccak256(request number) and logs it.
//
// initcode = <this object> || HPK (32) || VK (32) || CTLEN (32) || MODELLED (32)
object "FheRequest" {
    code {
        let n := datasize("runtime")
        datacopy(0, dataoffset("runtime"), n)
        codecopy(n, sub(codesize(), 128), 128)
        return(0, add(n, 128))
    }
    object "runtime" {
        code {
            if eq(caller(), 0xaa) {
                let frame := txparam(0x0a)
                if eq(frameparam(0x02, frame), 1) { validate(frame) }
                stop()
            }
            if eq(caller(), address()) { request() }
            stop()

            function validate(me) {
                if me { fail() }
                let n := txparam(0x09)
                let w := sub(n, 1)
                // [VERIFY, W] or [VERIFY, DEP, W]
                let dep := eq(n, 3)
                if iszero(or(eq(n, 2), dep)) { fail() }
                if dep { if iszero(eq(frameparam(0x02, 1), 4)) { fail() } }
                if iszero(eq(frameparam(0x02, w), 2)) { fail() }
                if iszero(eq(frameparam(0x00, w), address())) { fail() }
                if frameparam(0x08, w) { fail() }
                if frameparam(0x03, w) { fail() }
                let len := ctlen()
                if iszero(eq(frameparam(0x04, w), add(32, len))) { fail() }
                // One nonce key, key 0 (EIP-8250's keccak256(1 || 0)).
                if iszero(eq(txparam(0x0e), 1)) { fail() }
                mstore(0, 1)
                mstore(32, 0)
                if iszero(eq(keccak256(0, 64), txparam(0x0f))) { fail() }

                let requester := framedataload(0, w)
                if shr(160, requester) { fail() }
                framedatacopy(0x200, 32, len, w)
                let hct := keccak256(0x200, len)
                mstore(0x100, hpk())
                mstore(0x120, hct)
                let inner := keccak256(0x100, 64)
                mstore(0x100, DOMAIN())
                mstore(0x120, chainid())
                mstore(0x140, address())
                mstore(0x160, txparam(0x01))
                mstore(0x180, requester)
                let mu := keccak256(0x100, 0xa0)
                mstore(0x100, inner)
                mstore(0x120, mu)
                let d := keccak256(0x100, 64)

                // The triple: the dependency frame's data, or, modelled, this frame's own.
                switch modelled()
                case 0 {
                    if iszero(dep) { fail() }
                    if iszero(eq(frameparam(0x04, 1), 96)) { fail() }
                    if frameparam(0x04, me) { fail() }
                    triple(1, d)
                }
                default {
                    if dep { fail() }
                    if iszero(eq(frameparam(0x04, me), 96)) { fail() }
                    triple(me, d)
                }
                approve(3)
            }
            function triple(f, d) {
                if iszero(eq(framedataload(0, f), 0x11)) { fail() }
                if iszero(eq(framedataload(32, f), d)) { fail() }
                if iszero(eq(framedataload(64, f), vk())) { fail() }
            }

            function request() {
                let len := ctlen()
                if iszero(eq(calldatasize(), add(32, len))) { fail() }
                calldatacopy(0x200, 32, len)
                let hct := keccak256(0x200, len)
                // The request number: the nonce this transaction used.
                let num := txparam(0x01)
                mstore(0, num)
                sstore(keccak256(0, 32), hct)
                mstore(0, num)
                mstore(32, hct)
                // Request(address indexed requester, uint256 number, bytes32 ciphertextHash)
                log2(0, 64, 0xd4467e2d69b2759959412d2c02689a2d453543dc07b07c99339222fd08a70080, calldataload(0))
                stop()
            }

            function word(fromEnd) -> v {
                codecopy(0, sub(codesize(), fromEnd), 32)
                v := mload(0)
            }
            function hpk() -> v { v := word(128) }
            function vk() -> v { v := word(96) }
            function ctlen() -> v { v := word(64) }
            function modelled() -> v { v := word(32) }
            // keccak256("exp-frames/41/fhe-request")
            function DOMAIN() -> v { v := 0x5afdea4a76df0aacc9b2ece5c97651c4dabacc3289d313ea887e6611dee94613 }
            function fail() { revert(0, 0) }
            function txparam(param) -> v { v := verbatim_1i_1o(hex"b0", param) }
            function frameparam(param, frame) -> v { v := verbatim_2i_1o(hex"b3", frame, param) }
            function framedataload(offset, frame) -> v { v := verbatim_2i_1o(hex"b1", offset, frame) }
            function framedatacopy(memOffset, dataOffset, length, frame) {
                verbatim_4i_0o(hex"b2", memOffset, dataOffset, length, frame)
            }
            function approve(scope) { verbatim_3i_0o(hex"aa", 0, 0, scope) }
        }
    }
}
