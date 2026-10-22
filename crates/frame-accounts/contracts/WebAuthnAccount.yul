// WebAuthnAccount: a smart account owned by a browser passkey.
//
// A WebAuthn authenticator never signs a raw digest. It signs
//     sha256(authenticatorData || sha256(clientDataJSON))
// where clientDataJSON embeds the challenge, base64url-encoded. The protocol's P256 scheme
// verifies a signature over the sig hash itself, so it cannot carry a WebAuthn assertion, and
// an explicit-digest P256 entry cannot either: its digest would have to commit to the sig hash,
// which commits to the entry. So the assertion travels in an ARBITRARY entry, whose bytes the sig
// hash elides, and this account checks it in the EVM:
//
//   1. entry 0 is ARBITRARY with an empty msg;
//   2. its bytes are  authLen (2) || challengeIndex (2) || typeIndex (2)
//                     || authenticatorData || clientDataJSON || r (32) || s (32);
//   3. authenticatorData has the user-presence flag (bit 0 of byte 32);
//   4. clientDataJSON has "type":"webauthn.get" at typeIndex and
//      "challenge":"<base64url(sig hash)>" at challengeIndex;
//   5. s <= n/2. ARBITRARY bytes are elided from the sig hash, so a verifier that accepted both s
//      and n - s would let anyone change the transaction hash in flight (EIP-8141, "Arbitrary
//      Signature Malleability");
//   6. P256VERIFY (precompile 0x100) accepts (sha256(authData || sha256(clientDataJSON)), r, s, qx, qy).
//
// The public key is appended to the runtime. The VERIFY path reads no storage.
//
// initcode = <this object> ‖ qx ‖ qy
object "WebAuthnAccount" {
    code {
        let n := datasize("runtime")
        datacopy(0, dataoffset("runtime"), n)
        codecopy(n, sub(codesize(), 64), 64)
        return(0, add(n, 64))
    }
    object "runtime" {
        code {
            if eq(caller(), 0xaa) {
                let frame := txparam(0x0a)
                if eq(frameparam(0x02, frame), 1) { validate(frame) } // mode == VERIFY
            }
            stop()

            function validate(frame) {
                if iszero(txparam(0x0b)) { fail() }
                if sigparam(0x01, 0) { fail() } // scheme == ARBITRARY
                if sigparam(0x02, 0) { fail() } // msg empty
                let len := sigparam(0x03, 0)

                sigdatacopy(0, 0, 6, 0)
                let head := mload(0)
                let authLen := shr(240, head)
                let challengeIndex := and(shr(224, head), 0xffff)
                let typeIndex := and(shr(208, head), 0xffff)
                if lt(authLen, 37) { fail() }
                if lt(len, add(authLen, 70)) { fail() }
                let clientLen := sub(len, add(authLen, 70))

                // authenticatorData || clientDataJSON at 0x100, r and s at 0x80 and 0xa0.
                let auth := 0x100
                let client := add(auth, authLen)
                sigdatacopy(auth, 6, add(authLen, clientLen), 0)
                sigdatacopy(0x80, add(6, add(authLen, clientLen)), 64, 0)
                if gt(mload(0xa0), 0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8) { fail() }
                if iszero(and(byte(0, mload(add(auth, 32))), 0x01)) { fail() }

                // "type":"webauthn.get" (21 bytes)
                if gt(add(typeIndex, 21), clientLen) { fail() }
                if iszero(eq(shr(88, mload(add(client, typeIndex))), shr(88, "\"type\":\"webauthn.get\""))) { fail() }

                // "challenge":" (13 bytes), 43 base64url characters, then a closing quote
                if gt(add(challengeIndex, 57), clientLen) { fail() }
                let c := add(client, challengeIndex)
                if iszero(eq(shr(152, mload(c)), shr(152, "\"challenge\":\""))) { fail() }
                let encoded := 0x40
                base64url(txparam(0x08), encoded)
                if iszero(eq(mload(add(c, 13)), mload(encoded))) { fail() }
                if iszero(eq(shr(168, mload(add(c, 45))), shr(168, mload(add(encoded, 32))))) { fail() }
                if iszero(eq(byte(0, mload(add(c, 56))), 0x22)) { fail() }

                // message = sha256(authData || sha256(clientDataJSON))
                if iszero(staticcall(gas(), 0x02, client, clientLen, 0, 32)) { fail() }
                mstore(client, mload(0))
                if iszero(staticcall(gas(), 0x02, auth, add(authLen, 32), 0, 32)) { fail() }

                // P256VERIFY(message, r, s, qx, qy): 32 bytes of 1 on success, nothing otherwise
                let p := add(client, 32)
                mstore(p, mload(0))
                mstore(add(p, 32), mload(0x80))
                mstore(add(p, 64), mload(0xa0))
                codecopy(add(p, 96), sub(codesize(), 64), 64)
                mstore(0, 0)
                if iszero(staticcall(gas(), 0x100, p, 160, 0, 32)) { fail() }
                if iszero(eq(mload(0), 1)) { fail() }

                approve(frameparam(0x06, frame))
            }

            // 32 bytes as 43 base64url characters, no padding, written at `out`.
            function base64url(value, out) {
                let lo := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
                let hi := "ghijklmnopqrstuvwxyz0123456789-_"
                for { let i := 0 } lt(i, 42) { i := add(i, 1) } {
                    mstore8(add(out, i), char(and(shr(sub(250, mul(6, i)), value), 63), lo, hi))
                }
                mstore8(add(out, 42), char(and(shl(2, value), 63), lo, hi))
            }

            function char(index, lo, hi) -> c {
                switch lt(index, 32)
                case 1 { c := byte(index, lo) }
                default { c := byte(sub(index, 32), hi) }
            }

            function fail() { revert(0, 0) }

            function txparam(param) -> v { v := verbatim_1i_1o(hex"b0", param) }
            function frameparam(param, frame) -> v { v := verbatim_2i_1o(hex"b3", frame, param) }
            function sigparam(param, index) -> v { v := verbatim_2i_1o(hex"b4", index, param) }
            function sigdatacopy(memOffset, dataOffset, length, index) {
                verbatim_4i_0o(hex"b5", memOffset, dataOffset, length, index)
            }
            function approve(scope) { verbatim_3i_0o(hex"aa", 0, 0, scope) }
        }
    }
}
