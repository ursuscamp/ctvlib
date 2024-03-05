use bitcoin::{
    absolute::LockTime,
    address::{NetworkChecked, NetworkUnchecked},
    opcodes::all::OP_NOP4,
    script::PushBytesBuf,
    taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo},
    transaction::Version,
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness, XOnlyPublicKey,
};

use secp256k1::SECP256K1;
use serde::{Deserialize, Serialize};

use crate::{Error, TemplateHash};

/// The main interface type for working with CTV.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Context {
    pub network: Network,

    /// Dictates whether CTV lock will a P2WSH or P2TR spend.
    pub tx_type: TxType,

    /// The fields that a CTV hash commits to.
    pub fields: Fields,
}

impl Context {
    pub fn locking_script(&self) -> Result<ScriptBuf, Error> {
        let tmplhash = self.ctv()?;
        let mut pbf = PushBytesBuf::new();
        pbf.extend_from_slice(&tmplhash)?;
        Ok(bitcoin::script::Builder::new()
            .push_slice(pbf)
            .push_opcode(OP_NOP4)
            .into_script())
    }

    pub fn address(&self) -> Result<Address<NetworkChecked>, Error> {
        let locking_script = self.locking_script()?;
        match self.tx_type {
            TxType::Segwit => Ok(Address::p2wsh(&locking_script, self.network)),
            TxType::Taproot { internal_key } => {
                let tsi = self.taproot_spend_info(internal_key)?;
                Ok(Address::p2tr(
                    SECP256K1,
                    internal_key,
                    tsi.merkle_root(),
                    self.network,
                ))
            }
        }
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
            version: self.fields.version,
            lock_time: self.fields.locktime,
            input: vec![TxIn {
                previous_output: OutPoint { txid, vout },
                script_sig: Default::default(),
                sequence: *self
                    .fields
                    .sequences
                    .first()
                    .ok_or(Error::MissingSequence)?,
                witness: self.witness()?,
            }],
            output: self.txouts()?,
        };
        let current_txid = tx.txid();
        transactions.push(tx);
        if let Some(Output::Tree { tree, amount: _ }) = self.fields.outputs.first() {
            transactions.extend_from_slice(&tree.spending_tx(current_txid, 0)?);
        }
        Ok(transactions)
    }

    /// The actual hash that this CTV represents. May be used in locking scripts.
    pub fn ctv(&self) -> Result<Vec<u8>, Error> {
        self.as_tx()?.template_hash(self.fields.input_idx)
    }

    fn taproot_spend_info(&self, internal_key: XOnlyPublicKey) -> Result<TaprootSpendInfo, Error> {
        TaprootBuilder::new()
            .add_leaf(0, self.locking_script()?)?
            .finalize(SECP256K1, internal_key)
            .map_err(|_| Error::UnknownError("Taproot not finalizable".into()))
    }

    fn as_tx(&self) -> Result<Transaction, Error> {
        let input = self
            .fields
            .sequences
            .iter()
            .map(|seq| TxIn {
                sequence: *seq,
                ..Default::default()
            })
            .collect();
        let output: Result<Vec<TxOut>, Error> = self
            .fields
            .outputs
            .iter()
            .map(|output| output.as_txout(self.network))
            .collect();
        Ok(Transaction {
            version: self.fields.version,
            lock_time: self.fields.locktime,
            input,
            output: output?,
        })
    }

    fn txouts(&self) -> Result<Vec<TxOut>, Error> {
        self.fields
            .outputs
            .iter()
            .map(|output| output.as_txout(self.network))
            .collect()
    }

    fn witness(&self) -> Result<Witness, Error> {
        let mut witness = Witness::new();
        let script = self.locking_script()?;
        witness.push(script.clone());
        match self.tx_type {
            TxType::Segwit => {}
            TxType::Taproot { internal_key } => {
                let tsi = self.taproot_spend_info(internal_key)?;
                let cb = tsi
                    .control_block(&(script, LeafVersion::TapScript))
                    .ok_or_else(|| Error::UnknownError("Taproot construction error".into()))?;
                witness.push(cb.serialize());
            }
        }
        Ok(witness)
    }
}

/// The fields to which a CTV hash commits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fields {
    pub version: Version,
    pub locktime: LockTime,
    pub sequences: Vec<Sequence>,
    pub outputs: Vec<Output>,
    pub input_idx: u32,
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
    Tree { tree: Box<Context>, amount: Amount },
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
            Output::Tree { tree, amount } => TxOut {
                value: *amount,
                script_pubkey: tree.address()?.script_pubkey(),
            },
        })
    }

    /// Extract amount of final output.
    pub fn amount(&self) -> Amount {
        match self {
            Output::Address { address: _, amount } => *amount,
            Output::Data { data: _ } => Amount::ZERO,
            Output::Tree { tree: _, amount } => *amount,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub enum TxType {
    #[default]
    Segwit,
    Taproot {
        internal_key: XOnlyPublicKey,
    },
}
