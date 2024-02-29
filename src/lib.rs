use bitcoin::{
    absolute::LockTime,
    address::NetworkUnchecked,
    script::{PushBytesBuf, PushBytesError},
    transaction::Version,
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Missing sequence")]
    MissingSequence,

    #[error("{0}")]
    BitcoinStackItemSize(#[from] PushBytesError),

    #[error("{0}")]
    BitcoinAddress(#[from] bitcoin::address::Error),
}

/// The main type that handles CTV hashing.
///
/// A couple of things to note here:
/// - `network` is not committed to by CTV but is necessary for generating correct locking
/// addresses.
/// - CTV commits to the input count, but that is implied by the `sequences` item here.
/// - `outputs` are not `TxOut` in this case, but a new data structure here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ctv {
    pub network: Network,
    pub version: Version,
    pub locktime: LockTime,
    pub sequences: Vec<Sequence>,
    pub outputs: Vec<Output>,
    pub input_idx: u32,
}

impl Ctv {
    fn as_tx(&self) -> Result<Transaction, Error> {
        let input = self
            .sequences
            .iter()
            .map(|seq| TxIn {
                sequence: *seq,
                ..Default::default()
            })
            .collect();
        let output: Result<Vec<TxOut>, Error> = self
            .outputs
            .iter()
            .map(|output| output.as_txout(self.network))
            .collect();
        Ok(Transaction {
            version: self.version,
            lock_time: self.locktime,
            input,
            output: output?,
        })
    }

    /// Generate a spending transaction (or series of them) to spend the outputs of the CTV.
    /// In the event that this represents a CTV tree, it will generate a series of transactions
    /// that may be spent in order.
    ///
    /// If this does not have any `Output::Tree` outputs, then it will generate a single
    /// transaction to spend to all of the outputs.
    pub fn spending_tx(&self, txid: Txid, vout: u32) -> Result<Vec<Transaction>, Error> {
        let mut transactions = Vec::new();
        let tx = Transaction {
            version: self.version,
            lock_time: self.locktime,
            input: vec![TxIn {
                previous_output: OutPoint { txid, vout },
                script_sig: Default::default(),
                sequence: *self.sequences.first().ok_or(Error::MissingSequence)?,
                witness: self.witness()?,
            }],
            output: self.txouts()?,
        };
        let current_txid = tx.txid();
        transactions.push(tx);
        if let Some(Output::Tree { tree, amount: _ }) = self.outputs.first() {
            transactions.extend_from_slice(&tree.spending_tx(current_txid, 0)?);
        }
        Ok(transactions)
    }

    fn txouts(&self) -> Result<Vec<TxOut>, Error> {
        self.outputs
            .iter()
            .map(|output| output.as_txout(self.network))
            .collect()
    }

    /// The actual hash that this CTV represents. May be used in locking scripts.
    pub fn ctv(&self) -> Result<Vec<u8>, Error> {
        Ok(util::ctv(&self.as_tx()?, self.input_idx))
    }

    fn witness(&self) -> Result<Witness, Error> {
        let mut witness = Witness::new();
        let script = segwit::locking_script(&self.ctv()?);
        witness.push(&script);
        Ok(witness)
    }
}

/// Outputs committed to by a `Ctv`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Output {
    /// Spend a specific amount to a specific address.
    Address {
        address: Address<NetworkUnchecked>,
        amount: Amount,
    },

    /// Commit to an `OP_RETURN` output.
    Data { data: String },

    /// Commit an `amount` to a nested `Ctv` output. Use this to create a congestion control tree
    /// or another type of covenant tree.
    Tree { tree: Box<Ctv>, amount: Amount },
}

impl Output {
    /// Turn this output into a `TxOut` that may be used in a bitcoin `Transaction` struct.
    pub fn as_txout(&self, network: Network) -> Result<TxOut, Error> {
        Ok(match self {
            Output::Address { address, amount } => TxOut {
                value: *amount,
                script_pubkey: address.clone().require_network(network)?.script_pubkey(),
            },
            Output::Data { data } => {
                let mut pb = PushBytesBuf::new();
                pb.extend_from_slice(data.as_bytes())?;
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: ScriptBuf::new_op_return(&pb),
                }
            }
            Output::Tree { tree, amount } => {
                let tmplhash = tree.ctv()?;
                let locking_script = segwit::locking_script(&tmplhash);
                TxOut {
                    value: *amount,
                    script_pubkey: Address::p2wsh(&locking_script, network).script_pubkey(),
                }
            }
        })
    }
}

mod util {
    use std::io::Cursor;
    use std::io::Write;

    use bitcoin::{consensus::Encodable, Transaction};
    use sha2::{Digest, Sha256};

    pub(super) fn ctv(tx: &Transaction, input: u32) -> Vec<u8> {
        let mut buffer = Cursor::new(Vec::<u8>::new());
        tx.version.consensus_encode(&mut buffer).unwrap();
        tx.lock_time.consensus_encode(&mut buffer).unwrap();
        if let Some(scriptsigs) = scriptsigs(tx) {
            buffer.write_all(&scriptsigs).unwrap();
        }
        (tx.input.len() as u32)
            .consensus_encode(&mut buffer)
            .unwrap();
        buffer.write_all(&sequences(tx)).unwrap();
        (tx.output.len() as u32)
            .consensus_encode(&mut buffer)
            .unwrap();
        buffer.write_all(&outputs(tx)).unwrap();
        input.consensus_encode(&mut buffer).unwrap();
        let buffer = buffer.into_inner();
        sha256(buffer)
    }

    fn scriptsigs(tx: &Transaction) -> Option<Vec<u8>> {
        // If there are no scripts sigs, do nothing
        if tx.input.iter().all(|txin| txin.script_sig.is_empty()) {
            return None;
        }

        let scripts_sigs = tx
            .input
            .iter()
            .fold(Cursor::new(Vec::new()), |mut cursor, txin| {
                txin.script_sig.consensus_encode(&mut cursor).unwrap();
                cursor
            })
            .into_inner();
        Some(sha256(scripts_sigs))
    }

    fn sequences(tx: &Transaction) -> Vec<u8> {
        let sequences = tx
            .input
            .iter()
            .fold(Cursor::new(Vec::new()), |mut cursor, txin| {
                txin.sequence.consensus_encode(&mut cursor).unwrap();
                cursor
            })
            .into_inner();
        sha256(sequences)
    }

    fn outputs(tx: &Transaction) -> Vec<u8> {
        let outputs = tx
            .output
            .iter()
            .fold(Cursor::new(Vec::new()), |mut cursor, txout| {
                txout.consensus_encode(&mut cursor).unwrap();
                cursor
            })
            .into_inner();
        sha256(outputs)
    }

    pub fn sha256(data: Vec<u8>) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
}

/// Utility functions for generating segwit addresses.
pub mod segwit {
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
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use crate::util::ctv;

    use super::*;

    #[test]
    fn test_ctv() {
        let test_data = include_str!("../tests/ctvhash.json");
        let test_data: Vec<Value> = serde_json::from_str(test_data).unwrap();
        for td in test_data {
            if td.is_string() {
                continue;
            }
            let td = td.as_object().unwrap();
            let hex_tx = td["hex_tx"].as_str().unwrap();
            let tx: Transaction =
                bitcoin::consensus::deserialize(&hex::decode(hex_tx).unwrap()).unwrap();
            let spend_index = td["spend_index"]
                .as_array()
                .unwrap()
                .iter()
                .map(|i| i.as_i64().unwrap())
                .collect::<Vec<i64>>();
            let result: Vec<String> = td["result"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_owned())
                .collect();

            for (idx, si) in spend_index.into_iter().enumerate() {
                let hash = hex::encode(ctv(&tx, si as u32));
                assert_eq!(hash, result[idx]);
            }
        }
    }
}
