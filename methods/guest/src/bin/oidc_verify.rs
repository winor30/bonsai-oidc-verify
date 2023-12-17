// Copyright 2023 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![no_main]

use alloy_sol_types::SolType;
use oidc::IdentityProvider;
use risc0_zkvm::guest::env;
use risc0_zkvm::sha::rust_crypto::{Digest as _, Sha256};

risc0_zkvm::guest::entry!(main);

alloy_sol_types::sol! {
    struct ClaimsData {
        bytes ident;
    }
}

fn main() {
    let (provider, jwt): (IdentityProvider, String) = env::read();

    // calculate process
    let (ident, _) = provider.validate(&jwt).unwrap();
    let ident = hex::encode(Sha256::digest(ident)).as_bytes().to_vec();
    // let output = ClaimsData { ident };
    // let output = ClaimsData::encode(&output);

    // commit
    env::commit_slice(&ident);
}
