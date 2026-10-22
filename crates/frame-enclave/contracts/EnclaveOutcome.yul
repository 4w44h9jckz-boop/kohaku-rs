// EnclaveOutcome: the chain's end of experiment 51's simulated remote enclave. It is its own
// frame-transaction sender and payer, and records an output of the enclave's sealed comparison
// once it has checked, in VERIFY, either the attestation signature or the zero-knowledge proof.
//
// One output per transaction, exactly:
//
//   frame 0  VERIFY  this contract, scope 3: checks the evidence, approves and pays
//   frame 1  SENDER  this contract -> itself, record(uint256 route, bytes32 measurement,
//                    uint256[9] statement, uint256[8] evidence)
//
// statement = pk.x pk.y Ea.x Ea.y ca Eb.x Eb.y cb out: the enclave's Baby Jubjub key, the two
// ciphertexts and the output bit.
//
//   route 1, attestation: evidence = r s, then zeros. P256VERIFY at 0x100 must accept (r, s)
//     under the attestation key fixed in this code, over
//       keccak256("exp-frames/51/attest" || measurement || pk.x || pk.y || inputs || out)
//     where inputs = keccak256(Ea.x || Ea.y || ca || Eb.x || Eb.y || cb); s <= n/2.
//   route 2, proof: measurement = 0; evidence = a Groth16 proof (A.x A.y B.x1 B.x0 B.y1 B.y0
//     C.x C.y) the verifier accepts for the nine statement words.
//
// The transaction's only EIP-8250 nonce key is keccak256(route || pk.x || pk.y || inputs), at
// sequence 0: one output per route for one enclave key and one pair of ciphertexts.
//
// VERIFY reads no storage.
//
// initcode = <this object> || verifier (32) || attestation qx (32) || qy (32)
object "EnclaveOutcome" {
    code {
        let size := datasize("runtime")
        datacopy(0, dataoffset("runtime"), size)
        codecopy(size, sub(codesize(), 96), 96)
        return(0, add(size, 96))
    }
    object "runtime" {
        code {
            if eq(caller(), 0xaa) {
                let frame := txparam(0x0a)
                if eq(frameparam(0x02, frame), 1) { validate(frame) }
                stop()
            }
            switch shr(224, calldataload(0))
            case 0xa44c853c { record() }   // record(uint256,bytes32,uint256[9],uint256[8])
            default {
                // Plain ether funds it.
                if calldatasize() { revert(0, 0) }
                stop()
            }

            function validate(me) {
                if me { revert(0, 0) }
                if iszero(eq(txparam(0x09), 2)) { revert(0, 0) }
                if iszero(eq(frameparam(0x06, me), 3)) { revert(0, 0) }

                // Frame 1: SENDER, to this contract, no value, no flags, record(...) exactly.
                if iszero(eq(frameparam(0x02, 1), 2)) { revert(0, 0) }
                if iszero(eq(frameparam(0x00, 1), address())) { revert(0, 0) }
                if frameparam(0x08, 1) { revert(0, 0) }
                if frameparam(0x03, 1) { revert(0, 0) }
                if iszero(eq(frameparam(0x04, 1), 612)) { revert(0, 0) }
                if iszero(eq(shr(224, framedataload(0, 1)), 0xa44c853c)) { revert(0, 0) }

                // The statement at 0x200: route, measurement, then the nine words.
                framedatacopy(0x200, 4, 608, 1)
                let route := mload(0x200)
                let out := mload(0x340)
                if gt(out, 1) { revert(0, 0) }
                for { let i := 0 } lt(i, 9) { i := add(i, 1) } {
                    if iszero(lt(mload(add(0x240, shl(5, i))), FIELD())) { revert(0, 0) }
                }
                let inputs := keccak256(0x280, 192)        // Ea.x Ea.y ca Eb.x Eb.y cb

                // One output per route, enclave key and ciphertexts: the nonce key.
                mstore(0, route)
                mstore(0x20, mload(0x240))
                mstore(0x40, mload(0x260))
                mstore(0x60, inputs)
                let key := keccak256(0, 0x80)
                if iszero(eq(txparam(0x0e), 1)) { revert(0, 0) }
                if txparam(0x01) { revert(0, 0) }
                mstore(0, 1)
                mstore(0x20, key)
                if iszero(eq(keccak256(0, 0x40), txparam(0x0f))) { revert(0, 0) }

                // A bound on what one output can cost this contract.
                if gt(txparam(0x06), MAX_COST()) { revert(0, 0) }

                switch route
                case 1 { attested(inputs, out) }
                case 2 { proved() }
                default { revert(0, 0) }

                approve(3)
            }

            // P256VERIFY(digest, r, s, qx, qy) over the attestation message.
            function attested(inputs, out) {
                // "exp-frames/51/attest" (20 bytes) || measurement || pk.x || pk.y || inputs || out
                // Built at 0x700, past the evidence (0x360..0x460) and the call below.
                mstore(0x700, shl(96, 0x6578702d6672616d65732f35312f617474657374))
                mstore(0x714, mload(0x220))
                mstore(0x734, mload(0x240))
                mstore(0x754, mload(0x260))
                mstore(0x774, inputs)
                mstore(0x794, out)
                let digest := keccak256(0x700, 180)
                let s := mload(0x380)
                if gt(s, 0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8) { revert(0, 0) }
                for { let i := 2 } lt(i, 8) { i := add(i, 1) } {
                    if mload(add(0x360, shl(5, i))) { revert(0, 0) }
                }
                mstore(0x500, digest)
                mstore(0x520, mload(0x360))
                mstore(0x540, s)
                mstore(0x560, word(64))
                mstore(0x580, word(32))
                mstore(0, 0)
                if iszero(staticcall(gas(), 0x100, 0x500, 160, 0, 32)) { revert(0, 0) }
                if iszero(eq(mload(0), 1)) { revert(0, 0) }
            }

            // The verifier, on proof || statement. `gas()` is evaluated last, so GAS sits
            // immediately before STATICCALL.
            function proved() {
                if mload(0x220) { revert(0, 0) }
                // proof (8 words at 0x360) then the statement (9 words at 0x240), at 0x500
                mcopy(0x500, 0x360, 256)
                mcopy(0x600, 0x240, 288)
                if iszero(staticcall(gas(), word(96), 0x500, 544, 0, 0x20)) { revert(0, 0) }
                if iszero(and(eq(returndatasize(), 0x20), eq(mload(0), 1))) { revert(0, 0) }
            }

            // SENDER: Outcome(uint256 indexed route, uint256 out, bytes32 inputs, uint256 pkx, uint256 pky)
            function record() {
                if iszero(eq(caller(), address())) { revert(0, 0) }
                calldatacopy(0x200, 4, 608)
                mstore(0, mload(0x340))
                mstore(0x20, keccak256(0x280, 192))
                mstore(0x40, mload(0x240))
                mstore(0x60, mload(0x260))
                log2(0, 0x80, 0x64e89c47d8c69906878bdb1fdf78fbb3b2a0647ed89ffef8c77a3afb7ed30f6c, mload(0x200))
                stop()
            }

            function MAX_COST() -> c { c := 10000000000000000 } // 0.01 ETH
            function FIELD() -> f { f := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001 }

            // A constructor word, counted from the end of the code: qy 32, qx 64, verifier 96.
            // Uses scratch at 0x60.
            function word(fromEnd) -> v {
                codecopy(0x60, sub(codesize(), fromEnd), 32)
                v := mload(0x60)
            }

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
