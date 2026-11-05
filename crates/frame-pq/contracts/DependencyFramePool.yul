// DependencyFramePool: exp-frames experiment 06's FramePool.yul with one change, for exp-frames
// experiment 49. Experiment 06's pool accepts its frame layouts exactly, so a withdrawal that
// carries an EIP-8288 dependency frame (a leanSPHINCS-bound ticket's binder, declared) is refused
// by the pool's own VERIFY. This one also accepts dependency frames, mode 4, between the last
// VERIFY and W. Nothing else differs.
//
// FramePool: a Tornado Cash ETH pool that is its own frame-transaction sender.
//
// Deposits are ordinary calls: `deposit(bytes32 commitment)` with exactly `denomination` wei,
// inserted into Tornado's height-20 MiMC Merkle tree. The circuit, notes and proofs are Tornado
// Cash's, unchanged.
//
// A withdrawal is an EIP-8141 frame transaction with `tx.sender` = this pool and no signature at
// all: the proof is the authorisation. The pool's VERIFY frame reads the withdrawal frame's
// calldata, checks the root, the nullifier and the Groth16 proof, and approves. The withdrawal
// frame (SENDER, pool -> pool) then pays out; the pool trusts it because only a transaction it
// approved can make the pool call itself.
//
// Two ways to track roots and nullifiers, chosen at deployment:
//
//   mode 0 ("storage"): roots and nullifiers live in the pool's storage and VERIFY reads them,
//     as in "Frame transactions and the three gates to privacy" (Nero_eth, 2026-04-16).
//     `history` = 0 keeps every root (append-only); `history` = H keeps the last H in a ring,
//     as Tornado's MerkleTreeWithHistory does with H = 30.
//   mode 1 ("keyed"): VERIFY reads no storage. The nullifier hash is the transaction's only
//     EIP-8250 nonce key, at sequence 0, so the protocol refuses a second spend. Each deposit
//     publishes the new root to the EIP-8272 recent-root predeploy, and the withdrawal proves it
//     against a root named in an EIP-8272 verifier frame (frame 0).
//
// Frame layouts VERIFY accepts (P = this pool, W = SENDER frame calling P.withdraw, last):
//
//   mode 0, pool pays:      [P VERIFY scope 3, W]
//   mode 0, sponsor pays:   [P VERIFY scope 2, sponsor VERIFY, W]
//   mode 1, pool pays:      [8272 verifier, P VERIFY scope 3, W]
//   mode 1, sponsor pays:   [8272 verifier, P VERIFY scope 2, sponsor VERIFY, W]
//
// When the pool pays, the note's `relayer` must be the pool and its `fee` must cover the
// transaction's maximum cost: the fee stays in the pool and reimburses the gas.
//
// initcode = <this object> || verifier || hasher || denomination || mode || history || salt
// (32-byte words, appended to the deployed code and read back from its end).
object "FramePool" {
    code {
        let size := datasize("runtime")
        datacopy(0, dataoffset("runtime"), size)
        codecopy(size, sub(codesize(), 192), 192)
        let mode := mload(add(size, 96))
        let history := mload(add(size, 128))
        if or(gt(mode, 1), gt(history, 64)) { revert(0, 0) }
        if and(eq(mode, 1), gt(history, 0)) { revert(0, 0) }
        return(0, add(size, 192))
    }
    object "runtime" {
        code {
            // ENTRY_POINT (0xaa) calls in DEFAULT and VERIFY frames. Only VERIFY does anything.
            if eq(caller(), 0xaa) {
                let frame := txparam(0x0a)
                if eq(frameparam(0x02, frame), 1) { validate(frame) }
                stop()
            }

            switch shr(224, calldataload(0))
            case 0xb214faa5 { deposit(calldataload(4)) }      // deposit(bytes32)
            case 0x21a0adb6 { withdraw() }                    // withdraw(bytes,bytes32,bytes32,address,address,uint256,uint256)
            case 0x1e83409a { claim(calldataload(4)) }        // claim(address)
            case 0x8bb852fe { republish() }                   // republish()
            case 0xba70f757 { ret(sload(2)) }                 // getLastRoot()
            case 0xfc7e9c6f { ret(sload(0)) }                 // nextIndex()
            case 0x6d9833e3 { ret(isKnownRoot(calldataload(4))) } // isKnownRoot(bytes32)
            case 0xe5285dcc { ret(sload(mapslot(calldataload(4), 4))) } // isSpent(bytes32), mode 0
            case 0xdf18e047 { ret(sload(mapslot(calldataload(4), 6))) } // owed(address)
            case 0xd069aab9 { ret(sourceId()) }               // sourceId(), mode 1
            default { revert(0, 0) }

            // ---- VERIFY ----

            function validate(me) {
                let mode := word(96)
                let n := txparam(0x09)
                let scope := frameparam(0x06, me)
                let w := sub(n, 1)

                // The layout, exactly. Every SENDER frame runs as the pool, so one extra frame
                // could move the whole pool balance. EIP-8288 dependency frames (mode 4) execute
                // nothing and move nothing, so any number of them may stand just before W; they
                // are not counted.
                let deps := 0
                for { let i := sub(w, 1) } and(gt(i, me), eq(frameparam(0x02, i), 4)) { i := sub(i, 1) } {
                    deps := add(deps, 1)
                }
                n := sub(n, deps)
                if iszero(eq(me, mode)) { revert(0, 0) }
                switch scope
                case 3 { if iszero(eq(n, add(mode, 2))) { revert(0, 0) } }
                case 2 {
                    if iszero(eq(n, add(mode, 3))) { revert(0, 0) }
                    if iszero(eq(frameparam(0x02, add(me, 1)), 1)) { revert(0, 0) }
                }
                default { revert(0, 0) }

                // W: SENDER, to this pool, no value, no flags, a canonical withdraw() encoding.
                if iszero(eq(frameparam(0x02, w), 2)) { revert(0, 0) }
                if iszero(eq(frameparam(0x00, w), address())) { revert(0, 0) }
                if frameparam(0x08, w) { revert(0, 0) }
                if frameparam(0x03, w) { revert(0, 0) }
                if iszero(eq(frameparam(0x04, w), 516)) { revert(0, 0) }
                if iszero(eq(shr(224, framedataload(0, w)), 0x21a0adb6)) { revert(0, 0) }
                if iszero(eq(framedataload(0x04, w), 0xe0)) { revert(0, 0) }
                if iszero(eq(framedataload(0xe4, w), 0x100)) { revert(0, 0) }

                let root := framedataload(0x24, w)
                let nullifierHash := framedataload(0x44, w)
                let recipient := framedataload(0x64, w)
                let relayer := framedataload(0x84, w)
                let fee := framedataload(0xa4, w)
                if or(shr(160, recipient), shr(160, relayer)) { revert(0, 0) }
                if framedataload(0xc4, w) { revert(0, 0) }   // refund: ETH pool
                if gt(fee, word(128)) { revert(0, 0) }       // fee <= denomination

                // Nobody can make W fail after approval by starving it: the payout's gas is
                // floored here. In mode 1 a failed W would burn the note, since the nonce key is
                // consumed when payment is approved.
                if lt(frameparam(0x01, w), 100000) { revert(0, 0) }
                if lt(frameparam(0x09, w), withdrawStateFloor(mode, relayer)) { revert(0, 0) }

                // The pool pays: the fee is the pool's and covers the worst case.
                if and(scope, 1) {
                    if iszero(eq(relayer, address())) { revert(0, 0) }
                    if lt(fee, txparam(0x06)) { revert(0, 0) }
                }

                switch mode
                case 0 {
                    if iszero(isKnownRoot(root)) { revert(0, 0) }
                    if sload(mapslot(nullifierHash, 4)) { revert(0, 0) }
                }
                default {
                    // Frame 0 is the EIP-8272 verifier frame; the protocol checks its tuple
                    // (source_id || slot || root) against the predeploy before this runs.
                    if iszero(eq(frameparam(0x00, 0), 0x8272)) { revert(0, 0) }
                    if iszero(eq(frameparam(0x02, 0), 1)) { revert(0, 0) }
                    if frameparam(0x03, 0) { revert(0, 0) }
                    if iszero(eq(frameparam(0x04, 0), 72)) { revert(0, 0) }
                    if iszero(eq(framedataload(0, 0), sourceId())) { revert(0, 0) }
                    if iszero(eq(framedataload(40, 0), root)) { revert(0, 0) }
                    // The nullifier hash is the only nonce key, at sequence 0: the protocol
                    // refuses the transaction once the key has been used.
                    if iszero(eq(txparam(0x0e), 1)) { revert(0, 0) }
                    if iszero(eq(txparam(0x10), nullifierHash)) { revert(0, 0) }
                    if txparam(0x01) { revert(0, 0) }
                }

                verifyProof(w, root, nullifierHash, recipient, relayer, fee)
                approve(scope)
            }

            // Tornado's Verifier.verifyProof(bytes proof, uint256[6] input), the proof copied
            // straight out of W's calldata. `gas()` is evaluated last, so GAS sits immediately
            // before STATICCALL, as the validation trace rules require.
            function verifyProof(w, root, nullifierHash, recipient, relayer, fee) {
                let verifier := word(192)
                let p := 0x80
                mstore(p, shl(224, 0x695ef6f9))
                mstore(add(p, 0x04), 0xe0)
                mstore(add(p, 0x24), root)
                mstore(add(p, 0x44), nullifierHash)
                mstore(add(p, 0x64), recipient)
                mstore(add(p, 0x84), relayer)
                mstore(add(p, 0xa4), fee)
                mstore(add(p, 0xc4), 0)
                mstore(add(p, 0xe4), 0x100)
                framedatacopy(add(p, 0x104), 0x104, 0x100, w)
                if iszero(staticcall(gas(), verifier, p, 0x204, 0, 0x20)) { revert(0, 0) }
                if iszero(and(eq(returndatasize(), 0x20), eq(mload(0), 1))) { revert(0, 0) }
            }

            // State gas W may need: the nullifier slot (mode 0), a new account for the
            // recipient (a failed payout's credit costs less), a credit slot for a relayer.
            function withdrawStateFloor(mode, relayer) -> floor {
                floor := 183600
                if iszero(mode) { floor := add(floor, 97920) }
                if iszero(eq(relayer, address())) { floor := add(floor, 97920) }
            }

            // ---- SENDER: the withdrawal frame ----

            function withdraw() {
                // Only a SENDER frame of a transaction this pool approved has the pool as caller.
                if iszero(eq(caller(), address())) { revert(0, 0) }
                let nullifierHash := calldataload(0x44)
                let recipient := calldataload(0x64)
                let relayer := calldataload(0x84)
                let fee := calldataload(0xa4)
                if iszero(word(96)) {
                    let s := mapslot(nullifierHash, 4)
                    if sload(s) { revert(0, 0) }
                    sstore(s, 1)
                }
                // Nothing below can revert: a reverting recipient is credited instead.
                if iszero(eq(relayer, address())) { if fee { credit(relayer, fee) } }
                let amount := sub(word(128), fee)
                if amount {
                    if iszero(call(sub(gas(), 30000), recipient, amount, 0, 0, 0, 0)) {
                        credit(recipient, amount)
                    }
                }
                mstore(0, recipient)
                mstore(0x20, nullifierHash)
                mstore(0x40, fee)
                log2(0, 0x60, 0xe9e508bad6d4c3227e881ca19068f099da81b5164dd6d62b2eaf1e8bc6c34931, relayer)
                stop()
            }

            function credit(who, amount) {
                let s := mapslot(who, 6)
                sstore(s, add(sload(s), amount))
            }

            function claim(who) {
                let s := mapslot(who, 6)
                let amount := sload(s)
                sstore(s, 0)
                if iszero(call(gas(), who, amount, 0, 0, 0, 0)) { revert(0, 0) }
                stop()
            }

            // ---- deposits and the tree ----

            function deposit(commitment) {
                if iszero(eq(callvalue(), word(128))) { revert(0, 0) }
                if iszero(lt(commitment, FIELD())) { revert(0, 0) }
                let seen := mapslot(commitment, 5)
                if sload(seen) { revert(0, 0) }
                sstore(seen, 1)

                let index := sload(0)
                if iszero(lt(index, shl(20, 1))) { revert(0, 0) }
                let hasher := word(160)
                let node := commitment
                let i := index
                // Tornado's MerkleTreeWithHistory._insert. filledSubtrees[level] is read only
                // where an earlier insertion wrote it, so it needs no initialisation.
                for { let level := 0 } lt(level, 20) { level := add(level, 1) } {
                    switch and(i, 1)
                    case 0 {
                        sstore(add(0x100, level), node)
                        node := hashLeftRight(hasher, node, zero(level))
                    }
                    default {
                        node := hashLeftRight(hasher, sload(add(0x100, level)), node)
                    }
                    i := shr(1, i)
                }
                sstore(0, add(index, 1))
                sstore(2, node)
                recordRoot(node)

                mstore(0, index)
                mstore(0x20, timestamp())
                log2(0, 0x40, 0xa945e51eec50ab98c161376f0db4cf2aeba3ec92755fe2fcd388bdbbb80ff196, commitment)
                stop()
            }

            function hashLeftRight(hasher, left, right) -> r {
                mstore(0, shl(224, 0xf47d33b5))   // MiMCSponge(uint256,uint256)
                mstore(0x04, left)
                mstore(0x24, 0)
                if iszero(staticcall(gas(), hasher, 0, 0x44, 0, 0x40)) { revert(0, 0) }
                // The output overwrote the selector: write all three words again.
                let c := mload(0x20)
                let x := addmod(mload(0), right, FIELD())
                mstore(0, shl(224, 0xf47d33b5))
                mstore(0x04, x)
                mstore(0x24, c)
                if iszero(staticcall(gas(), hasher, 0, 0x44, 0, 0x40)) { revert(0, 0) }
                r := mload(0)
            }

            function recordRoot(root) {
                switch word(96)
                case 0 {
                    let h := word(64)
                    switch h
                    case 0 { sstore(mapslot(root, 3), 1) }
                    default {
                        let i := addmod(sload(1), 1, h)
                        sstore(add(0x200, i), root)
                        sstore(1, i)
                    }
                }
                default {
                    // EIP-8272 write: calldata salt || root, source_id = keccak256(pool || salt).
                    mstore(0, word(32))
                    mstore(0x20, root)
                    if iszero(call(gas(), 0x8272, 0, 0, 0x40, 0, 0)) { revert(0, 0) }
                    mstore(0, root)
                    mstore(0x20, slotnum())
                    log1(0, 0x40, 0x2fd31368794d8179a2869e743a7fb1d8819c4b52d4154ba95ddbba7cf39a8552)
                }
            }

            // Anyone may publish the current root again, so that a pool with no recent deposit
            // still has a root inside the EIP-8272 window (8191 slots).
            function republish() {
                if iszero(word(96)) { revert(0, 0) }
                let root := sload(2)
                if iszero(root) { revert(0, 0) }
                recordRoot(root)
                stop()
            }

            function isKnownRoot(root) -> known {
                if iszero(root) { leave }
                let h := word(64)
                if iszero(h) {
                    known := sload(mapslot(root, 3))
                    leave
                }
                let current := sload(1)
                let i := current
                for {} 1 {} {
                    if eq(sload(add(0x200, i)), root) {
                        known := 1
                        leave
                    }
                    if iszero(i) { i := h }
                    i := sub(i, 1)
                    if eq(i, current) { leave }
                }
            }

            function sourceId() -> id {
                mstore(0, address())
                mstore(0x20, word(32))
                id := keccak256(12, 52)
            }

            // ---- helpers ----

            // BN254 scalar field, Tornado's FIELD_SIZE.
            function FIELD() -> f { f := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001 }

            function zero(level) -> z {
                datacopy(0x60, add(dataoffset("zeros"), shl(5, level)), 32)
                z := mload(0x60)
            }

            // A constructor word, counted from the end of the code: salt 32, history 64,
            // mode 96, denomination 128, hasher 160, verifier 192. Uses scratch at 0x60.
            function word(fromEnd) -> v {
                codecopy(0x60, sub(codesize(), fromEnd), 32)
                v := mload(0x60)
            }

            function mapslot(key, tag) -> s {
                mstore(0, key)
                mstore(0x20, tag)
                s := keccak256(0, 0x40)
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
