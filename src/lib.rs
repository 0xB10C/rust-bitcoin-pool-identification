//! # Bitcoin Mining Pool Identification
//! Crate to identify Bitcoin mining pools based on coinbase transaction
//! metadata like, for example, pool set coinbase tags or coinbase output
//! addresses.

use bitcoin::network::constants::Network;
use bitcoin::{Address, Block, Transaction};
use serde::{Deserialize, Serialize};

include!(concat!(env!("OUT_DIR"), "/matching.rs"));

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentificationMethod {
    /// The [Pool] was identified via a known coinbase output address.
    Address,
    /// The [Pool] was identified via a known tag in the coinbase script sig.
    Tag,
}

/// Models a mining pool with a name and optionally a link to the pool website.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pool {
    /// Name of the mining pool.
    pub name: String,
    /// Optional link to the mining pools website.
    pub link: Option<String>,
    /// The method the pool was identified with.
    pub identification_method: IdentificationMethod,
}

/// Trait for Bitcoin mining pool identification based on metadata like coinbase
/// tags or coinbase output addresses.
pub trait PoolIdentification {
    /// Checks both the coinbase output address and coinbase tags against known
    /// values to identify a mining pool. The coinbase output address is
    /// checked first, as it is harder to fake than the coinbase tag. Coinbase
    /// tags are not authenticated and can easily be faked by a malicious party.
    ///
    /// If both methods can't identify the pool, then `None` is returned.
    fn identify_pool(&self) -> Option<Pool>;

    /// Checks coinbase tags from against the UTF-8 encoded coinbase script_sig
    /// to identify mining pools.
    ///
    /// These coinbase tags are not authenticated and can easily be faked by a
    /// malicious party.
    ///
    /// The coinbase tag for the ViaBTC pool is, for example, `/ViaBTC/`. An
    /// UTF-8 encoded coinbase looks, for example, like (line breaks removed):
    /// ```text
    /// l</ViaBTC/Mined by leehoo4444/,��mmA�G��CT�)�טb^��̵�g��,Eܩ(
    /// ```
    fn identify_coinbase_tag(&self) -> Option<Pool>;

    /// Checks the coinbase output address against a list of known pool
    /// addresses and returns a found pool. If no output address matches, then
    /// `None` is returned.
    fn identify_coinbase_output_address(&self) -> Option<Pool>;

    /// Returns the coinbase script encoded as lossy UTF-8 String (any invalid
    /// UTF-8 sequences with U+FFFD REPLACEMENT CHARACTER, which looks like
    /// this: �). Line-breaks are removed as well.
    fn coinbase_script_as_utf8(&self) -> String;

    /// Returns the coinbase output addresses for all output types that can be
    /// represented as addresses. This excludes, for example, P2PK or OP_RETURN
    /// outputs. Addresses are ordered by value (descending).
    fn coinbase_output_addresses(&self) -> Vec<Address>;
}

impl PoolIdentification for Transaction {
    /// Checks both the coinbase output address and coinbase tags against known
    /// values to identify a mining pool. The coinbase output address is
    /// checked first, as it is harder to fake than the coinbase tag. Coinbase
    /// tags are not authenticated and can easily be faked by a malicious party.
    ///
    /// If both methods can't identify the pool, then `None` is returned.
    ///
    /// # Panics
    ///
    /// The caller MUST make sure the transaction is a **coinbase transaction**
    /// This can be done, for example, with [Transaction::is_coin_base()]. This
    /// is asserted and will panic.
    ///
    /// # Examples
    ///
    /// ```
    /// use bitcoin::Transaction;
    /// use bitcoin_pool_identification::{IdentificationMethod, Pool, PoolIdentification};
    ///
    /// // Bitcoin mainnet coinbase transaction of block 670828 mined by ViaBTC:
    /// // 71093a08fe47c9d0c08921049f1a317541d78470376d7029c5e27fda2205361b
    /// let rawtx = hex::decode("010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff5f036c3c0a1c2f5669614254432f4d696e6564206279206c6565686f6f343434342f2cfabe6d6d41f647100ea398435411f0297fd9d798625e1b82c82451f7c6ccb59c0c67ec07100000000000000010d02cfe0845dca9281bb0ee077c090000ffffffff04bdb8892b000000001976a914536ffa992491508dca0354e52f32a3a7a679a53a88ac00000000000000002b6a2952534b424c4f434b3a2f21f07f3619ef6521a90de396c2617f2edc5bda4fd04aba89632f2c002f79bc0000000000000000266a24b9e11b6d2dd1c7233a019c512c5f1e105e185a6ea0a47824b5ae390cc7cec5c01714588b0000000000000000266a24aa21a9ed23418324183dba97076f21aadc97aeeb1782c6859faf8e141c601e5c856c55440120000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();
    /// let tx: Transaction = bitcoin::consensus::deserialize(&rawtx).unwrap();
    /// let pool = tx.identify_pool();
    /// assert_eq!(
    ///     pool,
    ///     Some(Pool {
    ///         name: "ViaBTC".to_string(),
    ///         link: Some("https://viabtc.com/".to_string()),
    ///         identification_method: IdentificationMethod::Tag,
    ///     })
    /// );
    fn identify_pool(&self) -> Option<Pool> {
        if let Some(pool) = self.identify_coinbase_output_address() {
            return Some(pool);
        }
        if let Some(pool) = self.identify_coinbase_tag() {
            return Some(pool);
        }
        return None;
    }

    /// Checks coinbase tags from against the UTF-8 encoded coinbase script_sig
    /// to identify mining pools.
    ///
    /// These coinbase tags are not authenticated and can easily be faked by a
    /// malicious party.
    ///
    /// The coinbase tag for the ViaBTC pool is, for example, `/ViaBTC/`. An
    /// UTF-8 encoded coinbase looks, for example, like (line breaks removed):
    /// ```text
    /// l</ViaBTC/Mined by leehoo4444/,��mmA�G��CT�)�טb^��̵�g��,Eܩ(
    /// ```
    ///
    /// # Panics
    ///
    /// The caller MUST make sure the transaction is a **coinbase transaction**
    /// This can be done, for example, with [Transaction::is_coin_base()]. This
    /// is asserted and will panic.
    ///
    /// # Examples
    ///
    /// ```
    /// use bitcoin::Transaction;
    /// use bitcoin_pool_identification::{Pool, PoolIdentification};
    ///
    /// // Bitcoin mainnet coinbase transaction of block 670828 mined by ViaBTC:
    /// // 71093a08fe47c9d0c08921049f1a317541d78470376d7029c5e27fda2205361b
    /// let rawtx = hex::decode("010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff5f036c3c0a1c2f5669614254432f4d696e6564206279206c6565686f6f343434342f2cfabe6d6d41f647100ea398435411f0297fd9d798625e1b82c82451f7c6ccb59c0c67ec07100000000000000010d02cfe0845dca9281bb0ee077c090000ffffffff04bdb8892b000000001976a914536ffa992491508dca0354e52f32a3a7a679a53a88ac00000000000000002b6a2952534b424c4f434b3a2f21f07f3619ef6521a90de396c2617f2edc5bda4fd04aba89632f2c002f79bc0000000000000000266a24b9e11b6d2dd1c7233a019c512c5f1e105e185a6ea0a47824b5ae390cc7cec5c01714588b0000000000000000266a24aa21a9ed23418324183dba97076f21aadc97aeeb1782c6859faf8e141c601e5c856c55440120000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();
    /// let tx: Transaction = bitcoin::consensus::deserialize(&rawtx).unwrap();
    /// let pool = tx.identify_coinbase_output_address();
    /// assert_eq!(pool, None);
    /// ```
    fn identify_coinbase_tag(&self) -> Option<Pool> {
        assert!(self.is_coin_base());
        return coinbase_tag_matching(self.coinbase_script_as_utf8());
    }

    /// Checks the coinbase output address against a list of known pool
    /// addresses and returns a found pool. If no output address matches, then
    /// `None` is returned.
    ///
    /// # Panics
    ///
    /// The caller MUST make sure the transaction is a **coinbase transaction**
    /// This can be done, for example, with [Transaction::is_coin_base()].
    ///
    /// # Examples
    ///
    /// ```
    /// use bitcoin::Transaction;
    /// use bitcoin_pool_identification::{IdentificationMethod, Pool, PoolIdentification};
    ///
    /// // Bitcoin mainnet coinbase transaction of block 670828 mined by ViaBTC:
    /// // 71093a08fe47c9d0c08921049f1a317541d78470376d7029c5e27fda2205361b
    /// let rawtx = hex::decode("010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff5f036c3c0a1c2f5669614254432f4d696e6564206279206c6565686f6f343434342f2cfabe6d6d41f647100ea398435411f0297fd9d798625e1b82c82451f7c6ccb59c0c67ec07100000000000000010d02cfe0845dca9281bb0ee077c090000ffffffff04bdb8892b000000001976a914536ffa992491508dca0354e52f32a3a7a679a53a88ac00000000000000002b6a2952534b424c4f434b3a2f21f07f3619ef6521a90de396c2617f2edc5bda4fd04aba89632f2c002f79bc0000000000000000266a24b9e11b6d2dd1c7233a019c512c5f1e105e185a6ea0a47824b5ae390cc7cec5c01714588b0000000000000000266a24aa21a9ed23418324183dba97076f21aadc97aeeb1782c6859faf8e141c601e5c856c55440120000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();
    /// let tx: Transaction = bitcoin::consensus::deserialize(&rawtx).unwrap();
    /// let pool = tx.identify_coinbase_tag();
    /// assert_eq!(
    ///     pool,
    ///     Some(Pool {
    ///         name: "ViaBTC".to_string(),
    ///         link: Some("https://viabtc.com/".to_string()),
    ///         identification_method: IdentificationMethod::Tag,
    ///     })
    /// );
    /// ```
    fn identify_coinbase_output_address(&self) -> Option<Pool> {
        for address in self.coinbase_output_addresses() {
            if let Some(pool) = coinbase_address_matching(address.to_string()) {
                return Some(pool);
            }
        }
        return None;
    }

    /// Returns the coinbase script encoded as lossy UTF-8 String (any invalid
    /// UTF-8 sequences with U+FFFD REPLACEMENT CHARACTER, which looks like
    /// this: �). Line-breaks are removed as well.
    ///
    /// # Panics
    ///
    /// The caller MUST make sure the transaction is a **coinbase transaction**
    /// This can be done, for example, with [Transaction::is_coin_base()]. This
    /// is asserted and will panic.
    fn coinbase_script_as_utf8(&self) -> String {
        assert!(self.is_coin_base());
        let in0 = &self.input[0];
        return String::from_utf8_lossy(&in0.script_sig.as_bytes())
            .replace('\n', "")
            .to_string();
    }

    /// Returns the coinbase output addresses for all output types that can be
    /// represented as addresses. This excludes, for example, P2PK or OP_RETURN
    /// outputs. Addresses are ordered by value (descending).
    ///
    /// # Panics
    ///
    /// The caller MUST make sure the transaction is a **coinbase transaction**
    /// This can be done, for example, with [Transaction::is_coin_base()].
    ///
    fn coinbase_output_addresses(&self) -> Vec<Address> {
        assert!(self.is_coin_base());
        let mut outputs = self.output.clone();
        outputs.sort_by_key(|o| o.value);

        let mut addresses = vec![];
        for out in outputs {
            if let Some(address) = Address::from_script(&out.script_pubkey, Network::Bitcoin) {
                addresses.push(address);
            }
        }
        return addresses;
    }
}

impl PoolIdentification for Block {
    /// Checks both the coinbase output address and coinbase tags against known
    /// values to identify a mining pool. The coinbase output address is
    /// checked first, as it is harder to fake than the coinbase tag. Coinbase
    /// tags are not authenticated and can easily be faked by a malicious party.
    ///
    /// If both methods can't identify the pool, then `None` is returned.
    ///
    /// # Examples
    /// ```
    ///
    /// use bitcoin::Block;
    /// use bitcoin_pool_identification::{IdentificationMethod, Pool, PoolIdentification};
    ///
    /// // Bitcoin mainnet block at height 670718 mined by BTC.com:
    /// // 0000000000000000000566438fa7dc31ec2b26e8cfd0a704822238ee8a40922c
    /// // Identified by both its coinbase tag and output address.
    /// let raw_block = hex::decode("00e0ff3f0c85cd07e4c8b446f64d9179ddd7627d4858f9bd07df08000000000000000000b263e9b0077a5f8ea941f8498a0df7b88d6d2077e9be4ef9d5b5f5b8e77906c9c56b2a60b9210d173aa2253a0102000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4c03fe3b0a04c16b2a6065752f4254432e636f6d2ffabe6d6d5793cfdad17c5272fca204a71fb04e88a5955239c018b8e5186ce838e789f7d4020000008e9b20aa04f5d252bb00000000000000ffffffff0340be4025000000001976a91474e878616bd5e5236ecb22667627eeecbff54b9f88ac00000000000000002b6a2952534b424c4f434b3a2dcf611172e7f2605b32915ca21102a7b0139400413995a4df47ea0b002ee6900000000000000000266a24b9e11b6d3974264c2913656ea4ee829e6327179645a5e8b4dc463914680b2003569a36e200000000").unwrap();
    /// let block: Block = bitcoin::consensus::deserialize(&raw_block).unwrap();
    /// let expected_id_addr = Some(Pool {
    ///     name: "BTC.com".to_string(),
    ///     link: Some("https://pool.btc.com".to_string()),
    ///     identification_method: IdentificationMethod::Address,
    /// });
    /// let expected_id_tag = Some(Pool {
    ///     name: "BTC.com".to_string(),
    ///     link: Some("https://pool.btc.com".to_string()),
    ///     identification_method: IdentificationMethod::Tag,
    /// });
    ///
    /// assert_eq!(block.identify_pool(), expected_id_addr);
    /// assert_eq!(block.identify_coinbase_output_address(), expected_id_addr);
    /// assert_eq!(block.identify_coinbase_tag(), expected_id_tag);
    /// ```
    fn identify_pool(&self) -> Option<Pool> {
        if let Some(pool) = self.identify_coinbase_output_address() {
            return Some(pool);
        }
        if let Some(pool) = self.identify_coinbase_tag() {
            return Some(pool);
        }
        return None;
    }

    /// Checks coinbase tags from against the UTF-8 encoded coinbase script_sig
    /// to identify mining pools.
    ///
    /// These coinbase tags are not authenticated and can easily be faked by a
    /// malicious party.
    ///
    /// The coinbase tag for the ViaBTC pool is, for example, `/ViaBTC/`. An
    /// UTF-8 encoded coinbase looks, for example, like (line breaks removed):
    /// ```text
    /// l</ViaBTC/Mined by leehoo4444/,��mmA�G��CT�)�טb^��̵�g��,Eܩ(
    /// ```
    fn identify_coinbase_tag(&self) -> Option<Pool> {
        let coinbase = self.txdata.first().unwrap();
        return coinbase.identify_coinbase_tag();
    }

    /// Checks the coinbase output addresses against a list of known pool
    /// addresses and returns a found pool. If no output address matches, then
    /// `None` is returned.
    fn identify_coinbase_output_address(&self) -> Option<Pool> {
        let coinbase = self.txdata.first().unwrap();
        return coinbase.identify_coinbase_output_address();
    }

    /// Returns the coinbase script encoded as lossy UTF-8 String (any invalid
    /// UTF-8 sequences with U+FFFD REPLACEMENT CHARACTER, which looks like
    /// this: �). Line-breaks are removed as well.
    fn coinbase_script_as_utf8(&self) -> String {
        return self.txdata.first().unwrap().coinbase_script_as_utf8();
    }

    /// Returns the coinbase output addresses for all output types that can be
    /// represented as addresses. This excludes, for example, P2PK or OP_RETURN
    /// outputs. Addresses are ordered by value (descending).
    fn coinbase_output_addresses(&self) -> Vec<Address> {
        return self.txdata.first().unwrap().coinbase_output_addresses();
    }
}

#[cfg(test)]
mod tests {

    use super::{IdentificationMethod, Pool, PoolIdentification};
    use bitcoin::{Block, Transaction};
    use hex;

    #[test]
    fn test_block_10000() {
        // Bitcoin mainnet block at height 10000 likely mined by a solo miner:
        // 0000000099c744455f58e6c6e98b671e1bf7f37346bfd4cf5d0274ad8ee660cb
        let raw_block = hex::decode("01000000a7c3299ed2475e1d6ea5ed18d5bfe243224add249cce99c5c67cc9fb00000000601c73862a0a7238e376f497783c8ecca2cf61a4f002ec8898024230787f399cb575d949ffff001d3a5de07f0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d026f03ffffffff0100f2052a010000004341042f462d3245d2f3a015f7f9505f763ee1080cab36191d07ae9e6509f71bb68818719e6fb41c019bf48ae11c45b024d476e19b6963103ce8647fc15fee513b15c7ac00000000").unwrap();
        let block: Block = bitcoin::consensus::deserialize(&raw_block).unwrap();

        assert_eq!(block.identify_pool(), None);
        assert_eq!(block.identify_coinbase_output_address(), None);
        assert_eq!(block.identify_coinbase_tag(), None);
    }

    #[test]
    fn test_block_btccom() {
        // Bitcoin mainnet block at height 670718 mined by BTC.com:
        // 0000000000000000000566438fa7dc31ec2b26e8cfd0a704822238ee8a40922c
        // Identified by both its coinbase tag and output address.
        let raw_block = hex::decode("00e0ff3f0c85cd07e4c8b446f64d9179ddd7627d4858f9bd07df08000000000000000000b263e9b0077a5f8ea941f8498a0df7b88d6d2077e9be4ef9d5b5f5b8e77906c9c56b2a60b9210d173aa2253a0102000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4c03fe3b0a04c16b2a6065752f4254432e636f6d2ffabe6d6d5793cfdad17c5272fca204a71fb04e88a5955239c018b8e5186ce838e789f7d4020000008e9b20aa04f5d252bb00000000000000ffffffff0340be4025000000001976a91474e878616bd5e5236ecb22667627eeecbff54b9f88ac00000000000000002b6a2952534b424c4f434b3a2dcf611172e7f2605b32915ca21102a7b0139400413995a4df47ea0b002ee6900000000000000000266a24b9e11b6d3974264c2913656ea4ee829e6327179645a5e8b4dc463914680b2003569a36e200000000").unwrap();
        let block: Block = bitcoin::consensus::deserialize(&raw_block).unwrap();
        let expected_id_addr = Some(Pool {
            name: "BTC.com".to_string(),
            link: Some("https://pool.btc.com".to_string()),
            identification_method: IdentificationMethod::Address,
        });

        let expected_id_tag = Some(Pool {
            name: "BTC.com".to_string(),
            link: Some("https://pool.btc.com".to_string()),
            identification_method: IdentificationMethod::Tag,
        });

        assert_eq!(block.identify_pool(), expected_id_addr);
        assert_eq!(block.identify_coinbase_output_address(), expected_id_addr);
        assert_eq!(block.identify_coinbase_tag(), expected_id_tag);
    }

    #[test]
    fn test_coinbase_slushpool() {
        // Bitcoin mainnet coinbase transaction of block 670987 mined by SlushPool:
        // 069dc08e89524fb1f2120ecc383ec54bc3e54b9c63716ba4352147dcdd7240a6
        // Identified by both it's coinbase output address and coinbase tag.
        let rawtx = hex::decode("010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff4b030b3d0afabe6d6d87a2773b0dfb971a762db2fd5a473882417a86aa7e1a2993feec04bfa383f93701000000000000002b6501031eb6e5300303000000000002c54ac6082f736c7573682f0000000003f09e942b000000001976a9147c154ed1dc59609e3d26abb2df2ea3d587cd8c4188ac00000000000000002c6a4c2952534b424c4f434b3ae47c0b11ada150b68f298a42147c6a1817907b6e0b435b0021057134002f87000000000000000000266a24aa21a9eda2fe9c7da3d1b9c033e1caa2064e844e1a1b46cf80c4a10c5d1cc15a34f252450120000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&rawtx).unwrap();
        let expected_id_addr = Some(Pool {
            name: "SlushPool".to_string(),
            link: Some("https://slushpool.com/".to_string()),
            identification_method: IdentificationMethod::Address,
        });
        let expected_id_tag = Some(Pool {
            name: "SlushPool".to_string(),
            link: Some("https://slushpool.com/".to_string()),
            identification_method: IdentificationMethod::Tag,
        });

        assert_eq!(tx.identify_pool(), expected_id_addr);
        assert_eq!(tx.identify_coinbase_output_address(), expected_id_addr);
        assert_eq!(tx.identify_coinbase_tag(), expected_id_tag);
    }

    #[test]
    fn test_coinbase_viabtc() {
        // Bitcoin mainnet coinbase transaction of block 670828 mined by ViaBTC:
        // 71093a08fe47c9d0c08921049f1a317541d78470376d7029c5e27fda2205361b
        // Identified by it's coinbase tag.
        let rawtx = hex::decode("010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff5f036c3c0a1c2f5669614254432f4d696e6564206279206c6565686f6f343434342f2cfabe6d6d41f647100ea398435411f0297fd9d798625e1b82c82451f7c6ccb59c0c67ec07100000000000000010d02cfe0845dca9281bb0ee077c090000ffffffff04bdb8892b000000001976a914536ffa992491508dca0354e52f32a3a7a679a53a88ac00000000000000002b6a2952534b424c4f434b3a2f21f07f3619ef6521a90de396c2617f2edc5bda4fd04aba89632f2c002f79bc0000000000000000266a24b9e11b6d2dd1c7233a019c512c5f1e105e185a6ea0a47824b5ae390cc7cec5c01714588b0000000000000000266a24aa21a9ed23418324183dba97076f21aadc97aeeb1782c6859faf8e141c601e5c856c55440120000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&rawtx).unwrap();
        let expected = Some(Pool {
            name: "ViaBTC".to_string(),
            link: Some("https://viabtc.com/".to_string()),
            identification_method: IdentificationMethod::Tag,
        });

        assert_eq!(tx.identify_pool(), expected);
        assert_eq!(tx.identify_coinbase_output_address(), None);
        assert_eq!(tx.identify_coinbase_tag(), expected);
    }

    #[test]
    fn test_coinbase_ghashio() {
        // Bitcoin mainnet coinbase transaction of block 300000 mined by GHashIO:
        // b39fa6c39b99683ac8f456721b270786c627ecb246700888315991877024b983
        // Identified by its output address.
        let rawtx = hex::decode("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4803e09304062f503253482f0403c86d53087ceca141295a00002e522cfabe6d6d7561cf262313da1144026c8f7a43e3899c44f6145f39a36507d36679a8b7006104000000000000000000000001c8704095000000001976a91480ad90d403581fa3bf46086a91b2d9d4125db6c188ac00000000").unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&rawtx).unwrap();
        let expected = Some(Pool {
            name: "GHash.IO".to_string(),
            link: Some("https://ghash.io/".to_string()),
            identification_method: IdentificationMethod::Address,
        });

        assert_eq!(tx.identify_pool(), expected);
        assert_eq!(tx.identify_coinbase_output_address(), expected);
        assert_eq!(tx.identify_coinbase_tag(), None);
    }

    #[test]
    fn test_coinbase_with_address_output_not_first() {
        // Bitcoin mainnet coinbase transaction where the first output is an
        // OP_RETURN output.
        // 980fab41429b321b4722dcfb780d6f39f9f19065f1a96a5058689c312e0b16be
        // Mined in Block 455860 by BitcoinRussia.
        // 0000000000000000002f5721c2d63215a6a956a356d170339377ac24518e1df8
        let rawtx = hex::decode("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4c03b4f40604f4fbbb5808fabe6d6dc6c7031efbd1de4725926e45c2ba9443fd84234cfb4cfb606e7d873cbdbdb88001000000000000005fffff799b3703000d2f6e6f64655374726174756d2f00000000020000000000000000266a24aa21a9ed159d16a5ce680dbe165700ef4a5776fcbf4fe216dc886c895d5dd5e0bd923aa0f5c77751000000001976a9142573e708154145b6a6a4a8898a2e458e6828d10688ac00000000").unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&rawtx).unwrap();
        let expected = Some(Pool {
            name: "BitcoinRussia".to_string(),
            link: Some("https://bitcoin-russia.ru/".to_string()),
            identification_method: IdentificationMethod::Address,
        });

        assert_eq!(tx.identify_pool(), expected);
        assert_eq!(tx.identify_coinbase_output_address(), expected);
        assert_eq!(tx.identify_coinbase_tag(), None);
    }
}
