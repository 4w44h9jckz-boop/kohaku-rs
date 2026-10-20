// Groth16Verifier: a BN254 Groth16 verifier for a snarkjs verifying key, which is appended to
// its code. It reads no storage, and forwards gas to the precompiles only as GAS immediately
// before STATICCALL, so it can run in a public-mempool VERIFY frame. snarkjs's own Solidity
// verifier forwards `sub(gas(), 2000)`, which the validation trace rules ban (experiment 06).
//
// calldata = A.x A.y B.x1 B.x0 B.y1 B.y0 C.x C.y || input_1 .. input_n   (32-byte words; a G2
//            coordinate x = x0 + x1 * i is written x1 first, as EIP-197 reads it)
// returns  one word, 1 if the proof is valid and 0 if not. Reverts on a malformed call: a wrong
//          length, an input outside the scalar field, or a point the precompiles refuse.
//
// initcode = <this object> || alpha (2 words) || beta (4) || gamma (4) || delta (4)
//            || IC_0 .. IC_n (2 each) || n (1)
object "Groth16Verifier" {
    code {
        let runtime := datasize("runtime")
        let key := sub(codesize(), add(dataoffset("runtime"), runtime))
        datacopy(0, dataoffset("runtime"), runtime)
        codecopy(runtime, sub(codesize(), key), key)
        return(0, add(runtime, key))
    }
    object "runtime" {
        code {
            let n := word(32)
            if iszero(eq(calldatasize(), shl(5, add(8, n)))) { revert(0, 0) }

            // The key, counted from the end of the code.
            let ic := sub(codesize(), add(32, shl(6, add(n, 1))))
            let delta := sub(ic, 128)
            let gamma := sub(delta, 128)
            let beta := sub(gamma, 128)
            let alpha := sub(beta, 64)

            // vk_x = IC_0 + sum input_i * IC_i, accumulated at 0x00.
            codecopy(0x00, ic, 64)
            for { let i := 1 } iszero(gt(i, n)) { i := add(i, 1) } {
                let x := calldataload(shl(5, add(7, i)))
                if iszero(lt(x, R())) { revert(0, 0) }
                codecopy(0x80, add(ic, shl(6, i)), 64)
                mstore(0xc0, x)
                if iszero(staticcall(gas(), 0x07, 0x80, 0x60, 0x40, 0x40)) { revert(0, 0) }
                if iszero(staticcall(gas(), 0x06, 0x00, 0x80, 0x00, 0x40)) { revert(0, 0) }
            }

            // e(-A, B) e(alpha, beta) e(vk_x, gamma) e(C, delta) = 1
            let p := 0x100
            let ay := calldataload(0x20)
            if iszero(lt(ay, Q())) { revert(0, 0) }
            mstore(p, calldataload(0))
            mstore(add(p, 0x20), mod(sub(Q(), ay), Q()))
            calldatacopy(add(p, 0x40), 0x40, 0x80)
            codecopy(add(p, 0xc0), alpha, 64)
            codecopy(add(p, 0x100), beta, 128)
            mstore(add(p, 0x180), mload(0x00))
            mstore(add(p, 0x1a0), mload(0x20))
            codecopy(add(p, 0x1c0), gamma, 128)
            calldatacopy(add(p, 0x240), 0xc0, 0x40)
            codecopy(add(p, 0x280), delta, 128)
            if iszero(staticcall(gas(), 0x08, p, 0x300, 0x00, 0x20)) { revert(0, 0) }
            mstore(0x00, eq(mload(0x00), 1))
            return(0x00, 0x20)

            // BN254's base field and scalar field.
            function Q() -> q { q := 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47 }
            function R() -> r { r := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001 }

            function word(fromEnd) -> v {
                codecopy(0x60, sub(codesize(), fromEnd), 32)
                v := mload(0x60)
            }
        }
    }
}
