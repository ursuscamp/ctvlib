use bitcoin::{
    absolute::LockTime, address::NetworkUnchecked, script::PushBytesBuf, transaction::Version,
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};

use serde::{Deserialize, Serialize};

use crate::{segwit, Error, TemplateHash};

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
        self.as_tx()?.template_hash(self.input_idx)
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
