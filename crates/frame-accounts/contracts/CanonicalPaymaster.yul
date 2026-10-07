// Deploys an instance of the EIP-8141 canonical paymaster (ethereum/EIPs#12041, the version
// ethrex pins: 355-byte runtime, keccak256 0xda42f0d11838c4c0c3129b8b8e93e9718127ad6b315e517e1088125707c4d45c).
//
// The runtime is the PR's bytes, verbatim; nothing here is compiled into it. Recognition is on the
// runtime code hash, so every instance shares these bytes and differs only in slot 0, the signer,
// which this initcode writes ("the standard constructor-writes-storage pattern").
//
// Runtime behaviour, from the PR: a pay frame (empty calldata, no value) requires signature entry 1
// to be a protocol-verified (non-ARBITRARY) signature over the sig hash by the stored signer, then
// calls APPROVE(APPROVE_PAYMENT). Plain value transfers are deposits. Admin calls are
// op (1 byte) || argument (32 bytes): 0x01 initiate withdrawal, 0x02 initiate signer rotation,
// 0x03 cancel, 0x04 finalize after DELAY = 86400 s.
//
// initcode = <this object> ‖ abi.encode(signer)
object "CanonicalPaymaster" {
    code {
        codecopy(0, sub(codesize(), 32), 32)
        sstore(0, mload(0))
        let n := datasize("runtime")
        datacopy(0, dataoffset("runtime"), n)
        return(0, n)
    }
    data "runtime" hex"3461002e57366100355760016001b41561005a575f6001b45f54141561005a5760026001b461005a5760015f5faa5b3661005a57005b5f3560f81c8060011461005e57806002146100a557806003146100ec57600414610123575b5f5ffd5b50335f54146100875760016001b41561005a575f6001b45f54141561005a5760026001b461005a575b60025461005a57600135801561005a57600155426201518001600255005b50335f54146100ce5760016001b41561005a575f6001b45f54141561005a5760026001b461005a575b60025461005a57600135801561005a57600355426201518001600255005b50335f54146101155760016001b41561005a575f6001b45f54141561005a5760026001b461005a575b5f6001555f6002555f600355005b600254801561005a57421061005a576001548015610153575f6001555f6002555f5f5f5f845f545af11561005a57005b506003545f555f6003555f60025500"
}
