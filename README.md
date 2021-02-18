# Bitcoin Mining Pool Identification

This Rust crate implements a new `PoolIdentification` trait on rust-bitcoin's
[bitcoin::Transaction][0] and [bitcoin::Block][1] structs. This trait can be used
for mining pool identification.

[0]: https://docs.rs/bitcoin/0.26.0/bitcoin/blockdata/transaction/struct.Transaction.html
[1]: https://docs.rs/bitcoin/0.26.0/bitcoin/blockdata/block/struct.Block.html

## Methodology

There are generally two methods to identify mining pools based on the coinbase
transaction in a block. Firstly, miners often put a human readable (ASCII or
UTF-8) tag in the coinbase transaction. For example, a block mined by the Slush
mining pool might have `/slush/` placed in the coinbase input's script sig.
Miners can be identified by mapping a tag found in the coinbase to the mining
pool identity. Secondly, mining pools often reuse the address where the coinbase
reward is paid to. These can be mapped to the pool identity too.

Both methods produce false negatives if a pool doesn't want to be identified.
The coinbase tags are not authenticated. Pools can set a different coinbase tag
(e.g. pool A mines his blocks with the coinbase tag of pool B). These would be
picked up as false positives. It's however unlikely that a pool would pay the
coinbase reward to an address he doesn't control, thus false positives are
unlikely.

## Implementation

The mapping of coinbase tags and mining pool addresses is based on data from
[0xB10C/known-mining-pools][3] which is a fork from [btccom/Blockchain-Known-Pools][4]
which in turn is a fork from [blockchain/Blockchain-Known-Pools][5]. These
projects provide a `pools.json` file mapping coinbase tags and pool addresses to
pool identities.

The [0xB10C/known-mining-pools][3] repository is included in this repository as
a Git submodule. The `pools.json` file is used during the Rust build process to
generate the code mapping coinbase tags and addresses to pool identities. The
code generation can be found in `build.rs`.

[3]: https://github.com/0xB10C/known-mining-pools
[4]: https://github.com/btccom/Blockchain-Known-Pools
[5]: https://github.com/blockchain/Blockchain-Known-Pools

## Development

The [0xB10C/known-mining-pools][3] submodule can be initialized and updated with
the following commands.

``` console
git submodule init
git submodule update
```

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.