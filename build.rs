use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use serde_with::NoneAsEmptyString;

#[derive(Serialize, Deserialize, Debug)]
struct PoolsJsonFile {
    coinbase_tags: HashMap<String, Pool>,
    payout_addresses: HashMap<String, Pool>,
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
struct Pool {
    name: String,
    #[serde_as(as = "NoneAsEmptyString")]
    link: Option<String>,
}

fn option_string_as_code(option: Option<String>) -> String {
    match option {
        None => return "None".to_string(),
        Some(v) => return format!("Some(\"{}\".to_string())", v).to_string(),
    }
}

fn generate_if_for_coinbase_tag(coinbase_tag: String, pool: Pool, first: bool) -> String {
    return format!(
        "{}if coinbase_utf8.contains(\"{}\") {{
                return Some(Pool{{
                    name: \"{}\".to_string(),
                    link: {}
                }});
            }}",
        if !first { " else " } else { "" },
        coinbase_tag.to_ascii_lowercase(),
        pool.name,
        option_string_as_code(pool.link)
    );
}

fn generate_matches_for_output_addresses(address: String, pool: Pool) -> String {
    return format!(
        "\"{}\" => {{
            return Some(Pool{{
                name: \"{}\".to_string(),
                link: {}
            }})
        }},\n\t",
        address,
        pool.name,
        option_string_as_code(pool.link)
    );
}

fn main() {
    let pools_json = fs::read_to_string("./known-mining-pools/pools.json").unwrap();

    let pools: PoolsJsonFile = serde_json::from_str(&pools_json).unwrap();

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("matching.rs");

    let mut coinbase_tag_matching_ifs = String::default();
    for (i, (coinbase_tag, pool)) in pools.coinbase_tags.into_iter().enumerate() {
        coinbase_tag_matching_ifs.push_str(&generate_if_for_coinbase_tag(
            coinbase_tag,
            pool,
            i == 0,
        ));
    }

    let mut coinbase_output_address_matching_matches = String::default();
    for (address, pool) in pools.payout_addresses.into_iter() {
        coinbase_output_address_matching_matches
            .push_str(&generate_matches_for_output_addresses(address, pool));
    }

    fs::write(
        &dest_path,
        format!(
            "
        // DON'T CHANGE THIS FILE MANUALLY. IT WILL BE OVERWRITTEN.
        // This is an automatically generated file.
        // Change it's generation in build.rs.

        /// Tries to match known mining pool coinbase tags to the given coinbase.
        /// Matching is case insensitive. Returning `Some(Pool)` if a pool with
        /// this tag is known. Otherwise `None` is returned.
        /// The code of this function is auto-generated.
        pub fn coinbase_tag_matching(coinbase_utf8: String) -> Option<Pool>{{
            let coinbase_utf8 = coinbase_utf8.to_ascii_lowercase();
            {}
            return None;
        }}

        /// Tries to match known mining pool addresses to the given address.
        /// Returning `Some(Pool)` if a pool with this address is known.
        /// Otherwise `None` is returned.
        /// The code of this function is auto-generated.
        pub fn coinbase_address_matching(address: String) -> Option<Pool> {{
            match address.as_str() {{
                {}
                _ => return None,
            }}
        }}

        ",
            coinbase_tag_matching_ifs, coinbase_output_address_matching_matches
        ),
    )
    .unwrap();
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=known-mining-pools/pools.json");
}
