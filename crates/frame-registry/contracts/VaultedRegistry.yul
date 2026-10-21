// VaultedRegistry: experiment 32's registry, with each application's value in a vault of its
// own, the vault bound into what a withdrawal proves, and the withdrawal bound to whom it pays
// and on what fee terms.
//
// A note is a leaf H(scope, inner, state) of Tornado Cash's height-20 MiMC tree, as in experiment
// 32 with `scope` where the application's address was:
//
//   scope = SHA-256(0x91 || vault.params() || uint64be(chain id) || vault) mod p
//
// The registry computes the scope itself, from the vault's address, so no two vaults share one,
// and it computes every leaf, at deposit, from the scope and the ether that came in, which it
// passes to the vault in the same call. Spending reveals the nullifier H(scope, nullifierSecret).
//
// An update is an EIP-8141 frame transaction with `tx.sender` = this registry and no signature,
// laid out as experiment 32's, for one note:
//
//   frame 0  VERIFY  0x8272, (source_id || slot || root): the EIP-8272 verifier frame
//   frame 1  VERIFY  this registry, scope 3: it approves execution and pays
//   frame 2  SENDER  this registry -> itself, update(bytes32 root, uint256[15][1] updates)
//
//   update words: 0 nullifier  1 newCommitment  2 vault  3 withdrawn  4 recipient  5 fee
//                 6 link (0)   7-14 proof
//
// The proof's public inputs are experiment 32's kernel's: root, nullifier, newCommitment, the
// scope in the tag's place, withdrawn, and
//
//   binding = SHA-256(0x61 || recipient || fee || max_priority_fee_per_gas || max_fee_per_gas) >> 8
//
// with the two fees read from this transaction by TXPARAM. A registry update carries no
// signature, so without them anyone holding a pending update could send it again with a higher
// priority fee, and the block's producer would be paid the fee's surplus.
//
// VERIFY reads no storage. The scope and the rule come from calls that read only the vault's
// code; the root from frame 0; spentness from the nonce keys; the fees from TXPARAM.
//
// Frame 2 pays `withdrawn - fee` to the recipient and `fee` to this registry, both from the
// vault, so a withdrawal is paid from its own application's value and the registry's gas from
// its own application's fee.
//
// initcode = <this object> || hasher (32) || verifier (32) || salt (32)
object "VaultedRegistry" {
    code {
        let size := datasize("runtime")
        datacopy(0, dataoffset("runtime"), size)
        codecopy(size, sub(codesize(), 96), 96)
        return(0, add(size, 96))
    }
    object "runtime" {
        code {
            // ENTRY_POINT (0xaa) calls in DEFAULT and VERIFY frames. Only VERIFY does anything.
            if eq(caller(), 0xaa) {
                let frame := txparam(0x0a)
                if eq(frameparam(0x02, frame), 1) { validate(frame) }
                stop()
            }
            // A vault paying this registry its fee.
            if iszero(calldatasize()) { stop() }

            switch shr(224, calldataload(0))
            case 0xb9e1aa03 { deposit(calldataload(4), calldataload(0x24)) } // deposit(address,bytes32)
            case 0x7f81305f { update() }                      // update(bytes32,uint256[15][])
            case 0x8bb852fe { republish() }                   // republish()
            case 0xba70f757 { ret(sload(2)) }                 // getLastRoot()
            case 0xfc7e9c6f { ret(sload(0)) }                 // nextIndex()
            case 0xd069aab9 { ret(sourceId()) }               // sourceId()
            case 0xaab86bea { ret(scopeOf(calldataload(4))) } // scopeOf(address)
            default { revert(0, 0) }

            // ---- VERIFY ----

            function validate(me) {
                // [8272 verifier, this VERIFY scope 3, SENDER update].
                if iszero(eq(me, 1)) { revert(0, 0) }
                if iszero(eq(txparam(0x09), 3)) { revert(0, 0) }
                if iszero(eq(frameparam(0x06, me), 3)) { revert(0, 0) }

                // Frame 2: SENDER, to this registry, no value, no flags, one update.
                if iszero(eq(frameparam(0x02, 2), 2)) { revert(0, 0) }
                if iszero(eq(frameparam(0x00, 2), address())) { revert(0, 0) }
                if frameparam(0x08, 2) { revert(0, 0) }
                if frameparam(0x03, 2) { revert(0, 0) }
                if iszero(eq(shr(224, framedataload(0, 2)), 0x7f81305f)) { revert(0, 0) }
                if iszero(eq(framedataload(0x24, 2), 0x40)) { revert(0, 0) }
                if iszero(eq(framedataload(0x44, 2), 1)) { revert(0, 0) }
                if iszero(eq(frameparam(0x04, 2), add(0x64, 480))) { revert(0, 0) }
                let root := framedataload(0x04, 2)

                // Frame 0 is the EIP-8272 verifier frame.
                if iszero(eq(frameparam(0x00, 0), 0x8272)) { revert(0, 0) }
                if iszero(eq(frameparam(0x02, 0), 1)) { revert(0, 0) }
                if frameparam(0x03, 0) { revert(0, 0) }
                if iszero(eq(frameparam(0x04, 0), 72)) { revert(0, 0) }
                if iszero(eq(framedataload(0, 0), sourceId())) { revert(0, 0) }
                if iszero(eq(framedataload(40, 0), root)) { revert(0, 0) }

                // The nullifier is the one nonce key, at sequence 0.
                if iszero(eq(txparam(0x0e), 1)) { revert(0, 0) }
                if txparam(0x01) { revert(0, 0) }
                let at := 0x64
                let nullifier := field(2, 0)
                mstore(0x400, 1)
                mstore(0x420, nullifier)
                if iszero(eq(keccak256(0x400, 0x40), txparam(0x0f))) { revert(0, 0) }

                let newCommitment := field(2, 32)
                let vault := framedataload(add(at, 64), 2)
                let withdrawn := framedataload(add(at, 96), 2)
                let recipient := framedataload(add(at, 128), 2)
                let fee := framedataload(add(at, 160), 2)
                if or(shr(160, vault), shr(160, recipient)) { revert(0, 0) }
                if shr(64, withdrawn) { revert(0, 0) }
                if gt(fee, withdrawn) { revert(0, 0) }
                if framedataload(add(at, 192), 2) { revert(0, 0) }   // no pairs here

                allows(vault, withdrawn, newCommitment)
                verifyProof(at, root, scopeOf(vault), contextOf(recipient, fee))

                // The fee is the registry's, from the vault, and covers the worst case.
                if lt(fee, txparam(0x06)) { revert(0, 0) }

                // Nobody can make frame 2 fail after approval by starving it.
                let inserts := iszero(iszero(newCommitment))
                let payout := gt(withdrawn, fee)
                if lt(frameparam(0x01, 2), add(UPDATE_EXECUTION(), mul(inserts, INSERT_EXECUTION()))) { revert(0, 0) }
                if lt(frameparam(0x09, 2), add(mul(payout, 183600), mul(inserts, INSERT_STATE()))) { revert(0, 0) }

                approve(3)
            }

            // The application's rule, answered from the vault's code alone.
            function allows(vault, withdrawn, newCommitment) {
                mstore(0, shl(224, 0x396faf6a))
                mstore(0x04, withdrawn)
                mstore(0x24, iszero(iszero(newCommitment)))
                if iszero(staticcall(gas(), vault, 0, 0x44, 0, 0x20)) { revert(0, 0) }
                if iszero(and(eq(returndatasize(), 0x20), eq(mload(0), 1))) { revert(0, 0) }
            }

            // SHA-256(0x91 || vault.params() || uint64be(chainid) || vault) mod p, built at 0x300.
            function scopeOf(vault) -> s {
                if shr(160, vault) { revert(0, 0) }
                mstore(0, shl(224, 0xcff0ab96))
                if iszero(staticcall(gas(), vault, 0, 0x04, 0, 0x20)) { revert(0, 0) }
                if iszero(eq(returndatasize(), 0x20)) { revert(0, 0) }
                mstore8(0x300, 0x91)
                mstore(0x301, mload(0))
                mstore(0x321, shl(192, chainid()))
                mstore(0x329, shl(96, vault))
                if iszero(staticcall(gas(), 0x02, 0x300, 0x3d, 0x300, 0x20)) { revert(0, 0) }
                s := mod(mload(0x300), FIELD())
            }

            // SHA-256(0x61 || recipient || fee || max_priority_fee_per_gas || max_fee_per_gas) >> 8.
            function contextOf(recipient, fee) -> c {
                mstore8(0x300, 0x61)
                mstore(0x301, recipient)
                mstore(0x321, fee)
                mstore(0x341, txparam(0x03))
                mstore(0x361, txparam(0x04))
                if iszero(staticcall(gas(), 0x02, 0x300, 0x81, 0x300, 0x20)) { revert(0, 0) }
                c := shr(8, mload(0x300))
            }

            // The kernel proof, copied out of frame 2, against its six public inputs.
            // `gas()` is evaluated last, so GAS sits immediately before STATICCALL.
            function verifyProof(at, root, scope, context) {
                let p := 0x80
                framedatacopy(p, add(at, 224), 256, 2)
                mstore(add(p, 0x100), root)
                framedatacopy(add(p, 0x120), at, 128, 2)       // nullifier, newCommitment, -, withdrawn
                mstore(add(p, 0x160), scope)
                mstore(add(p, 0x1a0), context)
                if iszero(staticcall(gas(), word(64), p, 0x1c0, 0, 0x20)) { revert(0, 0) }
                if iszero(and(eq(returndatasize(), 0x20), eq(mload(0), 1))) { revert(0, 0) }
            }

            // A field element of frame `frame`'s update data, at `offset` past the updates' start.
            function field(frame, offset) -> v {
                v := framedataload(add(0x64, offset), frame)
                if iszero(lt(v, FIELD())) { revert(0, 0) }
            }

            // ---- SENDER: the update frame ----

            function update() {
                // Only a SENDER frame of a transaction this registry approved has it as caller.
                if iszero(eq(caller(), address())) { revert(0, 0) }
                let at := 0x64
                let nullifier := calldataload(at)
                let newCommitment := calldataload(add(at, 32))
                let vault := calldataload(add(at, 64))
                let withdrawn := calldataload(add(at, 96))
                let recipient := calldataload(add(at, 128))
                let fee := calldataload(add(at, 160))
                if newCommitment { insert(vault, newCommitment) }
                // Both payments come from the vault. A payee that cannot receive is credited
                // there, so neither call reverts while the vault holds the note's value.
                let amount := sub(withdrawn, fee)
                if amount { pay(vault, recipient, amount) }
                if fee { pay(vault, address(), fee) }
                mstore(0, nullifier)
                mstore(0x20, recipient)
                mstore(0x40, withdrawn)
                mstore(0x60, fee)
                log2(0, 0x80, 0xfb15c1793eb288efe330f5c4867944badf5c105ad045a32b19a289fdefd0f7ca, vault)
                if newCommitment { recordRoot(sload(2)) }
                stop()
            }

            function pay(vault, to, value) {
                mstore(0, shl(224, 0xc4076876))
                mstore(0x04, to)
                mstore(0x24, value)
                if iszero(call(gas(), vault, 0, 0, 0x44, 0, 0)) { revert(0, 0) }
            }

            // ---- deposits and the tree ----

            function deposit(vault, inner) {
                let value := callvalue()
                if shr(64, value) { revert(0, 0) }
                if iszero(lt(inner, FIELD())) { revert(0, 0) }
                mstore(0, shl(224, 0xce5ce723))   // accepts(uint256)
                mstore(0x04, value)
                if iszero(staticcall(gas(), vault, 0, 0x24, 0, 0x20)) { revert(0, 0) }
                if iszero(and(eq(returndatasize(), 0x20), eq(mload(0), 1))) { revert(0, 0) }
                let leaf := hash3(scopeOf(vault), inner, value)
                // The value goes to the vault in the same call as the leaf goes in.
                mstore(0, shl(224, 0xb60d4288))   // fund()
                if iszero(call(gas(), vault, value, 0, 0x04, 0, 0)) { revert(0, 0) }
                insert(vault, leaf)
                recordRoot(sload(2))
                stop()
            }

            // Tornado's MerkleTreeWithHistory._insert, as in experiment 32.
            function insert(vault, leaf) {
                let index := sload(0)
                if iszero(lt(index, shl(20, 1))) { revert(0, 0) }
                let node := leaf
                let i := index
                for { let level := 0 } lt(level, 20) { level := add(level, 1) } {
                    switch and(i, 1)
                    case 0 {
                        sstore(add(0x100, level), node)
                        node := hashLeftRight(node, zero(level))
                    }
                    default {
                        node := hashLeftRight(sload(add(0x100, level)), node)
                    }
                    i := shr(1, i)
                }
                sstore(0, add(index, 1))
                sstore(2, node)
                mstore(0, leaf)
                mstore(0x20, index)
                log2(0, 0x40, 0x78f38fdf0de0782fafd17050a6a02eca83b65c29cc3b0a032c89ed0a6cfe9487, vault)
            }

            // One MiMC permutation of the deployed hasher: (xL, xR) -> (xL, xR) at 0 and 0x20.
            function permute(xL, xR) {
                mstore(0, shl(224, 0xf47d33b5))   // MiMCSponge(uint256,uint256)
                mstore(0x04, xL)
                mstore(0x24, xR)
                if iszero(staticcall(gas(), word(96), 0, 0x44, 0, 0x40)) { revert(0, 0) }
            }

            function hashLeftRight(left, right) -> r {
                permute(left, 0)
                permute(addmod(mload(0), right, FIELD()), mload(0x20))
                r := mload(0)
            }

            // circomlib's MiMCSponge(3, 220, 1), key 0.
            function hash3(a, b, c) -> r {
                permute(a, 0)
                permute(addmod(mload(0), b, FIELD()), mload(0x20))
                permute(addmod(mload(0), c, FIELD()), mload(0x20))
                r := mload(0)
            }

            // EIP-8272 write: calldata salt || root, source_id = keccak256(registry || salt).
            function recordRoot(root) {
                mstore(0, word(32))
                mstore(0x20, root)
                if iszero(call(gas(), 0x8272, 0, 0, 0x40, 0, 0)) { revert(0, 0) }
                mstore(0, root)
                mstore(0x20, slotnum())
                log1(0, 0x40, 0x2fd31368794d8179a2869e743a7fb1d8819c4b52d4154ba95ddbba7cf39a8552)
            }

            function republish() {
                let root := sload(2)
                if iszero(root) { revert(0, 0) }
                recordRoot(root)
                stop()
            }

            function sourceId() -> id {
                mstore(0, address())
                mstore(0x20, word(32))
                id := keccak256(12, 52)
            }

            // ---- helpers ----

            // What frame 2 must be given: two vault payments and the event; per change note,
            // its insertion and the root's publication.
            function UPDATE_EXECUTION() -> g { g := 150000 }
            function INSERT_EXECUTION() -> g { g := 1200000 }
            function INSERT_STATE() -> g { g := 195840 }

            function FIELD() -> f { f := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001 }

            function zero(level) -> z {
                datacopy(0x60, add(dataoffset("zeros"), shl(5, level)), 32)
                z := mload(0x60)
            }

            // A constructor word, counted from the end of the code: salt 32, verifier 64,
            // hasher 96. Uses scratch at 0x60.
            function word(fromEnd) -> v {
                codecopy(0x60, sub(codesize(), fromEnd), 32)
                v := mload(0x60)
            }

            function ret(v) {
                mstore(0, v)
                return(0, 0x20)
            }

            // EIP-8141 opcodes, and EIP-7843 SLOTNUM. verbatim puts its first argument on top.
            function txparam(param) -> v { v := verbatim_1i_1o(hex"b0", param) }
            function frameparam(param, frame) -> v { v := verbatim_2i_1o(hex"b3", frame, param) }
            function framedataload(offset, frame) -> v { v := verbatim_2i_1o(hex"b1", offset, frame) }
            function framedatacopy(memOffset, dataOffset, length, frame) {
                verbatim_4i_0o(hex"b2", memOffset, dataOffset, length, frame)
            }
            function approve(scope) { verbatim_3i_0o(hex"aa", 0, 0, scope) }
            function slotnum() -> v { v := verbatim_0i_1o(hex"4b") }
        }
        // zeros(0) .. zeros(20) of Tornado's tree, as tornado-core hard-codes them.
        data "zeros" hex"2fe54c60d3acabf3343a35b6eba15db4821b340f76e741e2249685ed4899af6c256a6135777eee2fd26f54b8b7037a25439d5235caee224154186d2b8a52e31d1151949895e82ab19924de92c40a3d6f7bcb60d92b00504b8199613683f0c20020121ee811489ff8d61f09fb89e313f14959a0f28bb428a20dba6b0b068b3bdb0a89ca6ffa14cc462cfedb842c30ed221a50a3d6bf022a6a57dc82ab24c157c924ca05c2b5cd42e890d6be94c68d0689f4f21c9cec9c0f13fe41d566dfb549591ccb97c932565a92c60156bdba2d08f3bf1377464e025cee765679e604a7315c19156fbd7d1a8bf5cba8909367de1b624534ebab4f0f79e003bccdd1b182bdb4261af8c1f0912e465744641409f622d466c3920ac6e5ff37e36604cb11dfff800058459724ff6ca5a1652fcbc3e82b93895cf08e975b19beab3f54c217d1c0071f04ef20dee48d39984d8eabe768a70eafa6310ad20849d4573c3c40c2ad1e301bea3dec5dab51567ce7e200a30f7ba6d4276aeaa53e2686f962a46c66d511e50ee0f941e2da4b9e31c3ca97a40d8fa9ce68d97c084177071b3cb46cd3372f0f1ca9503e8935884501bbaf20be14eb4c46b89772c97b96e3b2ebf3a36a948bbd133a80e30697cd55d8f7d4b0965b7be24057ba5dc3da898ee2187232446cb10813e6d8fc88839ed76e182c2a779af5b2c0da9dd18c90427a644f7e148a6253b61eb16b057a477f4bc8f572ea6bee39561098f78f15bfb3699dcbb7bd8db618540da2cb16a1ceaabf1c16b838f7a9e3f2a3a3088d9e0a6debaa748114620696ea24a3b3d822420b14b5d8cb6c28a574f01e98ea9e940551d2ebd75cee12649f9d198622acbd783d1b0d9064105b1fc8e4d8889de95c4c519b3f635809fe6afc0529d7ed391256ccc3ea596c86e933b89ff339d25ea8ddced975ae2fe30b5296d4"
    }
}
