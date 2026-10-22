// Board: where wallets that do not know each other leave encrypted messages. post(bytes) logs
// the message as Posted(bytes) and keeps nothing. Who reads a message is whoever can decrypt it;
// who posted it is the transaction's sender, which is public.
object "Board" {
    code {
        let size := datasize("runtime")
        datacopy(0, dataoffset("runtime"), size)
        return(0, size)
    }
    object "runtime" {
        code {
            // post(bytes): the calldata after the selector is the event's ABI-encoded data.
            if iszero(eq(shr(224, calldataload(0)), 0xbaf9b369)) { revert(0, 0) }
            let n := sub(calldatasize(), 4)
            calldatacopy(0, 4, n)
            log1(0, n, 0x17f0ecc22a2a71b5b9f1a2f673a516478429ef631733eef661f75eb5b030793d)
            stop()
        }
    }
}
