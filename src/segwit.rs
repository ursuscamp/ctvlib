use bitcoin::{opcodes::all::OP_NOP4, Address, Network, Script, ScriptBuf};

/// Generate a segwit address for a script.
pub fn locking_address(script: &Script, network: Network) -> Address {
    Address::p2wsh(script, network)
}

/// Given a CTV hash, create a `OP_CTV` locking script.
pub fn locking_script(tmplhash: &[u8]) -> ScriptBuf {
    let bytes = <&[u8; 32]>::try_from(tmplhash).unwrap();
    bitcoin::script::Builder::new()
        .push_slice(bytes)
        .push_opcode(OP_NOP4)
        .into_script()
}
