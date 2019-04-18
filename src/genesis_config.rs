use crate::generator_settings::*;
use crate::waves_crypto::*;
use base58::*;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct AccountInfo {
    seed: String,
    share: i64,
    address: Address,
    key_pair: KeyPair,
}

pub struct GenesisTx {
    recipient: AccountInfo,
    amount: i64,
}

impl GenesisTx {
    pub fn new(recipient: AccountInfo, amount: i64) -> GenesisTx {
        GenesisTx { recipient, amount }
    }
}

pub struct GenesisConfig {
    chain_id: char,
    base_target: i64,
    initial_balance: i64,
    block_delay: i64,
    timestamp: i64,
    transactions: Vec<GenesisTx>,
    signature: Signature,
}

impl GenesisConfig {
    pub fn generate(settings: &GeneratorSettings) -> Result<GenesisConfig, String> {
        let chain_id = settings.chain_id;

        let base_target = settings.base_target;
        let initial_balance = settings.initial_balance;
        let block_delay = settings.average_block_delay;
        let timestamp = settings.timestamp.unwrap_or(get_current_time_millis());

        validate_params(
            base_target,
            initial_balance,
            block_delay,
            timestamp,
            &settings.distribution,
        )?;

        let mut transactions = Vec::new();

        settings
            .distribution
            .iter()
            .for_each(|(seed_phrase, balance)| {
                let seed = seed_phrase.to_string();
                let share = *balance;
                let key_pair = KeyPair::from_seed(seed_phrase, 0);
                let address = key_pair.public_key().to_address(settings.chain_id as u8);

                let acc_info = AccountInfo {
                    seed,
                    share,
                    address,
                    key_pair,
                };

                let tx = GenesisTx::new(acc_info, share);

                transactions.push(tx);
            });

        let signature = sign_genesis_block(base_target, timestamp, &transactions);

        Ok(GenesisConfig {
            chain_id,
            base_target,
            initial_balance,
            block_delay,
            timestamp,
            transactions,
            signature,
        })
    }
}

fn validate_params(
    base_target: i64,
    initial_balance: i64,
    block_delay: i64,
    timestamp: i64,
    shares: &HashMap<String, i64>,
) -> Result<(), String> {
    validate_posistive(base_target, "Base target")?;
    validate_posistive(initial_balance, "Initial balance")?;
    validate_posistive(block_delay, "Block delay")?;
    validate_posistive(timestamp, "Timestamp")?;
    validate_shares(initial_balance, shares)?;

    Ok(())
}

fn validate_shares(initial_balance: i64, shares: &HashMap<String, i64>) -> Result<(), String> {
    let all_amounts_valid = shares.iter().all(|(_, &share)| share > 0);

    let total = shares.iter().fold(0 as i64, |sum, (_, share)| sum + share);

    if !all_amounts_valid {
        Err("All shares should be greater than 0.".to_string())
    } else if total != initial_balance {
        Err("Sum of shares should be equal to initial balance.".to_string())
    } else {
        Ok(())
    }
}

fn validate_posistive(value: i64, name: &str) -> Result<(), String> {
    if value <= 0 {
        Err(format!("{} should be greater than 0.", name))
    } else {
        Ok(())
    }
}

fn sign_genesis_block(
    base_target: i64,
    timestamp: i64,
    transactions: &Vec<GenesisTx>,
) -> Signature {
    let reference =
        "67rpwLCuS5DGA8KGZXKsVQ7dnPb9goRLoKfgGbLfQg9WoLUgNY77E2jT11fem3coV9nAkguBACzrU1iyZM4B8roQ"
            .from_base58()
            .unwrap();
    let signer = KeyPair::new(Vec::new().as_slice());

    let timestamp_bytes = timestamp.to_be_bytes();

    let mut consensus_data_bytes: Vec<u8> = Vec::new();

    consensus_data_bytes.extend(&base_target.to_be_bytes());
    consensus_data_bytes.extend(&[0u8; 32]);

    let mut transaction_data_bytes: Vec<u8> = Vec::new();

    transaction_data_bytes.push(transactions.len() as u8);

    transactions.iter().for_each(|tx| {
        let mut tx_bytes: Vec<u8> = Vec::new();

        tx_bytes.push(1 as u8);
        tx_bytes.extend(&timestamp_bytes);
        tx_bytes.extend(&tx.recipient.address.bytes());
        tx_bytes.extend(&tx.amount.to_be_bytes());

        let tx_size_bytes = (tx_bytes.len() as i32).to_be_bytes();

        transaction_data_bytes.extend(&tx_size_bytes);
        transaction_data_bytes.extend(&tx_bytes);
    });

    let mut bytes_to_sign: Vec<u8> = Vec::new();

    bytes_to_sign.push(1 as u8);
    bytes_to_sign.extend(&timestamp_bytes);
    bytes_to_sign.extend(&reference);
    bytes_to_sign.extend(&(consensus_data_bytes.len() as i32).to_be_bytes());
    bytes_to_sign.extend(&consensus_data_bytes);
    bytes_to_sign.extend(&(transaction_data_bytes.len() as i32).to_be_bytes());
    bytes_to_sign.extend(&transaction_data_bytes);
    bytes_to_sign.extend(&signer.public_key().bytes());

    signer.sign(&bytes_to_sign.as_slice())
}

fn get_current_time_millis() -> i64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    (secs * 1000) as i64
}

pub fn print_account_info(config: &GenesisConfig) -> String {
    let mut infos_str_repr = String::new();

    config.transactions.iter().for_each(|tx| {
        let addr_info = &tx.recipient;
        let addr_info_str = format!(
            "
# Seed: {}
# Address: {}
# Private key: {}
# Public key: {}
# Share: {}
",
            addr_info.seed,
            addr_info
                .key_pair
                .public_key()
                .to_address(config.chain_id as u8)
                .to_base58(),
            addr_info.key_pair.private_key().to_base58(),
            addr_info.key_pair.public_key().to_base58(),
            addr_info.share
        );

        infos_str_repr.push_str(&addr_info_str);
    });

    infos_str_repr
}

pub fn print_config(config: &GenesisConfig) -> String {
    let mut txs = String::new();

    config.transactions.iter().for_each(|tx| {
        let tx_str_repr = format!(
            "\n          {{ recipient = {}, amount = {} }},",
            tx.recipient.address.to_base58(),
            tx.amount
        );

        txs.push_str(&tx_str_repr);
    });

    format!(
        "
waves {{
  blockchain {{
    type = CUSTOM
    custom {{
      address-scheme-character = {}
      genesis {{
        average-block-delay = {}ms
        initial-base-target = {}
        timestamp = {}
        block-timestamp = {}
        signature = {}
        initial-balance = {}
        transactions = [{}
        ]
      }}
    }}
  }}
}}
",
        config.chain_id,
        config.block_delay,
        config.base_target,
        config.timestamp,
        config.timestamp,
        config.signature.to_base58(),
        config.initial_balance,
        txs
    )
}
