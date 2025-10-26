// SPDX-License-Identifier: MIT

use alloy::{
    network::{EthereumWallet, TransactionBuilder},
    primitives::{Address, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
    sol,
};
use alloy_sol_types::{SolCall, SolValue};
use anyhow::{Context, Result};
use url::Url;

sol! {
    enum Operation {
        Call,
        DelegateCall
    }

    interface IZKGuardSafeModule {
        function verifyAndExec(
            address safe,
            bytes calldata userAction,
            bytes calldata seal,
            bytes calldata journal,
            Operation operation
        ) external returns (bytes memory returnData);
    }
}

pub async fn verify_onchain(
    private_key: &str,
    eth_rpc_url: &str,
    contract_address: &str,
    onchain_seal: Vec<u8>,
    onchain_journal: Vec<u8>,
    from: Vec<u8>,
    to: Vec<u8>,
    value: u128,
    data: Vec<u8>,
    nonce: u64,
) -> Result<(), anyhow::Error> {
    let private_key_signer = private_key.parse::<PrivateKeySigner>()?;
    let wallet = EthereumWallet::from(private_key_signer.clone());
    let rpc_url: Url = eth_rpc_url.parse()?;
    let provider = ProviderBuilder::new().wallet(wallet).on_http(rpc_url);

    let safe_address_str = std::env::var("SAFE_ADDRESS").expect("SAFE_ADDRESS must be set");
    let safe_address = safe_address_str.parse::<Address>()?;

    let from_addr = Address::from_slice(&from);
    let to_addr = Address::from_slice(&to);
    let val_u256 = U256::from(value);
    let nonce_u256 = U256::from(nonce);

    let user_action =
        (from_addr, to_addr, val_u256, nonce_u256, Bytes::from(data)).abi_encode_params();

    let calldata = IZKGuardSafeModule::verifyAndExecCall {
        userAction: user_action.into(),
        seal: onchain_seal.into(),
        journal: onchain_journal.into(),
        operation: Operation::Call,
    };

    println!("Smart-Contract Address: {}", contract_address);
    let address_contract = contract_address.parse::<Address>()?;

    // Log the calldata before encodig it
    println!("Safe address: {}", safe_address);
    println!(
        "User action (len={}): {:x?}",
        calldata.abi_encoded_size(),
        hex::encode(calldata.abi_encode())
    );

    let tx = TransactionRequest::default()
        .with_to(address_contract)
        .with_input(calldata.abi_encode());

    let estimate = provider.estimate_gas(tx.clone()).await?;
    println!("Gas estimate: {}", estimate);
    let tx = tx.with_gas_limit((estimate as f64 * 1.125) as u64); // add 12.5% buffer

    let transaction_result = provider
        .send_transaction(tx)
        .await
        .context("Failed to send transaction")?;

    let tx_hash = transaction_result.tx_hash();
    println!("\nTransaction sent with hash: {} \n", tx_hash);

    let receipt = transaction_result.get_receipt().await?;
    println!("Transaction receipt: {:?}", receipt);

    Ok(())
}
