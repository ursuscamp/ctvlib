use bitcoin::Transaction;

pub trait TemplateHash {
    fn template_hash(&self, inp_index: u32) -> Result<Vec<u8>, super::Error>;
}

impl TemplateHash for Transaction {
    /// Calculate an `OP_CTV` template hash, given a particular `inp_index`.
    fn template_hash(&self, inp_index: u32) -> Result<Vec<u8>, super::Error> {
        util::ctv(self, inp_index)
    }
}

mod util {
    use std::io::Cursor;
    use std::io::Write;

    use bitcoin::{consensus::Encodable, Transaction};
    use sha2::{Digest, Sha256};

    use crate::Error;

    pub(super) fn ctv(tx: &Transaction, input: u32) -> Result<Vec<u8>, Error> {
        let mut buffer = Cursor::new(Vec::<u8>::new());
        tx.version.consensus_encode(&mut buffer)?;
        tx.lock_time.consensus_encode(&mut buffer)?;
        if let Some(scriptsigs) = scriptsigs(tx)? {
            buffer.write_all(&scriptsigs)?;
        }
        (tx.input.len() as u32).consensus_encode(&mut buffer)?;
        buffer.write_all(&sequences(tx)?)?;
        (tx.output.len() as u32).consensus_encode(&mut buffer)?;
        buffer.write_all(&outputs(tx)?)?;
        input.consensus_encode(&mut buffer)?;
        let buffer = buffer.into_inner();
        Ok(sha256(buffer))
    }

    fn scriptsigs(tx: &Transaction) -> Result<Option<Vec<u8>>, Error> {
        // If there are no scripts sigs, do nothing
        if tx.input.iter().all(|txin| txin.script_sig.is_empty()) {
            return Ok(None);
        }

        let mut cursor = Cursor::new(Vec::new());
        for txin in &tx.input {
            txin.script_sig.consensus_encode(&mut cursor)?;
        }
        let scripts_sigs = cursor.into_inner();
        Ok(Some(sha256(scripts_sigs)))
    }

    fn sequences(tx: &Transaction) -> Result<Vec<u8>, Error> {
        let mut sequences = Cursor::new(Vec::new());
        for txin in &tx.input {
            txin.sequence.consensus_encode(&mut sequences)?;
        }
        let sequences = sequences.into_inner();
        Ok(sha256(sequences))
    }

    fn outputs(tx: &Transaction) -> Result<Vec<u8>, Error> {
        let mut cursor = Cursor::new(Vec::new());
        for txout in &tx.output {
            txout.consensus_encode(&mut cursor)?;
        }
        let outputs = cursor.into_inner();
        Ok(sha256(outputs))
    }

    pub fn sha256(data: Vec<u8>) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    /// Test the hashing code against the BIP-119 test vectors.
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
                // let hash = hex::encode(ctv(&tx, si as u32));
                let hash = hex::encode(tx.template_hash(si as u32).unwrap());
                assert_eq!(hash, result[idx]);
            }
        }
    }
}
