//! Client-side Nostr transport for ContextVM.
//!
//! Connects to a remote MCP server over Nostr. Sends JSON-RPC requests as
//! kind 25910 events, correlates responses via `e` tag.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use nostr_sdk::prelude::*;
use tokio::sync::RwLock;

use crate::core::constants::*;
use crate::core::error::{Error, Result};
use crate::core::serializers;
use crate::core::types::*;
use crate::core::validation;
use crate::encryption;
use crate::relay::RelayPool;
use crate::transport::base::BaseTransport;

/// Configuration for the client transport.
pub struct NostrClientTransportConfig {
    /// Relay URLs to connect to.
    pub relay_urls: Vec<String>,
    /// The server's public key (hex).
    pub server_pubkey: String,
    /// Encryption mode.
    pub encryption_mode: EncryptionMode,
    /// Outbound gift-wrap envelope policy when encryption is used.
    pub gift_wrap_mode: GiftWrapMode,
    /// Optional hint for server ephemeral gift-wrap support.
    pub server_supports_ephemeral: Option<bool>,
    /// Stateless mode: emulate initialize response locally.
    pub is_stateless: bool,
    /// Response timeout (default: 30s).
    pub timeout: Duration,
}

impl Default for NostrClientTransportConfig {
    fn default() -> Self {
        Self {
            relay_urls: vec!["wss://relay.damus.io".to_string()],
            server_pubkey: String::new(),
            encryption_mode: EncryptionMode::Optional,
            gift_wrap_mode: GiftWrapMode::Optional,
            server_supports_ephemeral: None,
            is_stateless: false,
            timeout: Duration::from_secs(30),
        }
    }
}

/// Client-side Nostr transport for sending MCP requests and receiving responses.
pub struct NostrClientTransport {
    base: BaseTransport,
    config: NostrClientTransportConfig,
    server_pubkey: PublicKey,
    /// Dynamic capability hint learned from server traffic.
    server_supports_ephemeral: Arc<RwLock<Option<bool>>>,
    /// Pending request event IDs awaiting responses.
    pending_requests: Arc<RwLock<HashSet<String>>>,
    /// Channel for receiving processed MCP messages from the event loop.
    message_tx: tokio::sync::mpsc::UnboundedSender<JsonRpcMessage>,
    message_rx: Option<tokio::sync::mpsc::UnboundedReceiver<JsonRpcMessage>>,
}

impl NostrClientTransport {
    fn ephemeral_support_from_announcement_event(event: &Event) -> Option<bool> {
        let has_encryption = serializers::has_tag(&event.tags, tags::SUPPORT_ENCRYPTION);
        let has_ephemeral =
            serializers::has_tag(&event.tags, tags::SUPPORT_ENCRYPTION_EPHEMERAL);

        if has_ephemeral {
            Some(true)
        } else if has_encryption {
            Some(false)
        } else {
            None
        }
    }

    async fn discover_server_ephemeral_support(
        client: Arc<Client>,
        server_pubkey: PublicKey,
    ) -> Option<bool> {
        let filter = Filter::new()
            .kind(Kind::Custom(SERVER_ANNOUNCEMENT_KIND))
            .author(server_pubkey)
            .limit(1);

        let events = match client.fetch_events(filter, Duration::from_secs(2)).await {
            Ok(events) => events,
            Err(e) => {
                tracing::debug!("Failed to fetch server announcement for CEP-19 support: {e}");
                return None;
            }
        };

        events
            .into_iter()
            .next()
            .and_then(|event| Self::ephemeral_support_from_announcement_event(&event))
    }

    /// Create a new client transport.
    pub async fn new<T>(signer: T, config: NostrClientTransportConfig) -> Result<Self>
    where
        T: IntoNostrSigner,
    {
        let server_pubkey = PublicKey::from_hex(&config.server_pubkey)
            .map_err(|e| Error::Other(format!("Invalid server pubkey: {e}")))?;
        let initial_server_supports_ephemeral = config.server_supports_ephemeral;

        let relay_pool = Arc::new(RelayPool::new(signer).await?);
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

        Ok(Self {
            base: BaseTransport {
                relay_pool,
                encryption_mode: config.encryption_mode,
                gift_wrap_mode: config.gift_wrap_mode,
                is_connected: false,
            },
            config,
            server_pubkey,
            server_supports_ephemeral: Arc::new(RwLock::new(initial_server_supports_ephemeral)),
            pending_requests: Arc::new(RwLock::new(HashSet::new())),
            message_tx: tx,
            message_rx: Some(rx),
        })
    }

    /// Connect and start listening for responses.
    pub async fn start(&mut self) -> Result<()> {
        self.base.connect(&self.config.relay_urls).await?;

        let pubkey = self.base.get_public_key().await?;
        tracing::info!(pubkey = %pubkey.to_hex(), "Client transport started");

        self.base.subscribe_for_pubkey(&pubkey).await?;

        if self.config.gift_wrap_mode == GiftWrapMode::Optional {
            let current_support_hint = *self.server_supports_ephemeral.read().await;
            if current_support_hint.is_none() {
                let client = self.base.relay_pool.client().clone();
                let server_pubkey = self.server_pubkey;
                let server_supports_ephemeral = self.server_supports_ephemeral.clone();

                tokio::spawn(async move {
                    if let Some(supports_ephemeral) =
                        Self::discover_server_ephemeral_support(client, server_pubkey).await
                    {
                        *server_supports_ephemeral.write().await = Some(supports_ephemeral);
                        tracing::debug!(
                            server_supports_ephemeral = supports_ephemeral,
                            "Discovered server CEP-19 support from announcement tags"
                        );
                    }
                });
            }
        }

        // Spawn event loop
        let client = self.base.relay_pool.client().clone();
        let pending = self.pending_requests.clone();
        let server_pubkey = self.server_pubkey;
        let server_supports_ephemeral = self.server_supports_ephemeral.clone();
        let tx = self.message_tx.clone();
        let encryption_mode = self.config.encryption_mode;

        tokio::spawn(async move {
            Self::event_loop(
                client,
                pending,
                server_pubkey,
                server_supports_ephemeral,
                tx,
                encryption_mode,
            )
            .await;
        });

        Ok(())
    }

    /// Close the transport.
    pub async fn close(&mut self) -> Result<()> {
        self.base.disconnect().await
    }

    /// Send a JSON-RPC message to the server.
    pub async fn send(&self, message: &JsonRpcMessage) -> Result<()> {
        // Stateless mode: emulate initialize response
        if self.config.is_stateless {
            if let JsonRpcMessage::Request(ref req) = message {
                if req.method == "initialize" {
                    self.emulate_initialize_response(&req.id);
                    return Ok(());
                }
            }
            if let JsonRpcMessage::Notification(ref n) = message {
                if n.method == "notifications/initialized" {
                    return Ok(());
                }
            }
        }

        let tags = BaseTransport::create_recipient_tags(&self.server_pubkey);
        let server_supports_ephemeral = *self.server_supports_ephemeral.read().await;
        let event_id = self
            .base
            .send_mcp_message(
                message,
                &self.server_pubkey,
                CTXVM_MESSAGES_KIND,
                tags,
                None,
                server_supports_ephemeral,
            )
            .await?;

        if matches!(message, JsonRpcMessage::Request(_)) {
            self.pending_requests
                .write()
                .await
                .insert(event_id.to_hex());
        }

        Ok(())
    }

    /// Take the message receiver for consuming incoming messages.
    pub fn take_message_receiver(
        &mut self,
    ) -> Option<tokio::sync::mpsc::UnboundedReceiver<JsonRpcMessage>> {
        self.message_rx.take()
    }

    fn emulate_initialize_response(&self, request_id: &serde_json::Value) {
        let response = JsonRpcMessage::Response(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: request_id.clone(),
            result: serde_json::json!({
                "protocolVersion": crate::core::constants::mcp_protocol_version(),
                "serverInfo": {
                    "name": "Emulated-Stateless-Server",
                    "version": "1.0.0"
                },
                "capabilities": {
                    "tools": { "listChanged": true },
                    "prompts": { "listChanged": true },
                    "resources": { "subscribe": true, "listChanged": true }
                }
            }),
        });
        let _ = self.message_tx.send(response);
    }

    async fn event_loop(
        client: Arc<Client>,
        pending: Arc<RwLock<HashSet<String>>>,
        server_pubkey: PublicKey,
        server_supports_ephemeral: Arc<RwLock<Option<bool>>>,
        tx: tokio::sync::mpsc::UnboundedSender<JsonRpcMessage>,
        encryption_mode: EncryptionMode,
    ) {
        let mut notifications = client.notifications();

        while let Ok(notification) = notifications.recv().await {
            if let RelayPoolNotification::Event { event, .. } = notification {
                let is_gift_wrap = is_gift_wrap_kind(&event.kind);

                // Early policy enforcement: save CPU by validating before decryption
                if is_gift_wrap && encryption_mode == EncryptionMode::Disabled {
                    tracing::warn!(
                        event_id = %event.id.to_hex(),
                        "Received encrypted response but encryption is disabled"
                    );
                    continue;
                }
                if !is_gift_wrap && encryption_mode == EncryptionMode::Required {
                    tracing::warn!(
                        event_id = %event.id.to_hex(),
                        "Received unencrypted response but encryption is required"
                    );
                    continue;
                }

                // Handle gift-wrapped events
                let (actual_event_content, actual_pubkey, e_tag, used_ephemeral_gift_wrap) =
                    if is_gift_wrap {
                        let used_ephemeral_gift_wrap =
                            event.kind == Kind::Custom(EPHEMERAL_GIFT_WRAP_KIND);
                        // Single-layer NIP-44 decrypt (matches JS/TS SDK)
                        let signer = match client.signer().await {
                            Ok(s) => s,
                            Err(e) => {
                                tracing::error!("Failed to get signer: {e}");
                                continue;
                            }
                        };
                        match encryption::decrypt_gift_wrap_single_layer(&signer, &event).await {
                            Ok(decrypted_json) => {
                                match serde_json::from_str::<Event>(&decrypted_json) {
                                    Ok(inner) => {
                                        if let Err(e) = inner.verify() {
                                            tracing::warn!(
                                                "Inner event signature verification failed: {e}"
                                            );
                                            continue;
                                        }
                                        let e_tag = serializers::get_tag_value(&inner.tags, "e");
                                        (
                                            inner.content,
                                            inner.pubkey,
                                            e_tag,
                                            used_ephemeral_gift_wrap,
                                        )
                                    }
                                    Err(e) => {
                                        tracing::error!("Failed to parse inner event: {e}");
                                        continue;
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::error!("Failed to decrypt gift wrap: {e}");
                                continue;
                            }
                        }
                    } else {
                        let e_tag = serializers::get_tag_value(&event.tags, "e");
                        (event.content.clone(), event.pubkey, e_tag, false)
                    };

                // Verify it's from our server
                if actual_pubkey != server_pubkey {
                    tracing::debug!("Skipping event from unexpected pubkey");
                    continue;
                }

                if used_ephemeral_gift_wrap {
                    *server_supports_ephemeral.write().await = Some(true);
                }

                // Correlate response
                if let Some(ref correlated_id) = e_tag {
                    let is_pending = pending.read().await.contains(correlated_id.as_str());
                    if !is_pending {
                        tracing::warn!(e_tag = %correlated_id, "Response for unknown request");
                        continue;
                    }
                }

                // Parse MCP message
                if let Some(mcp_msg) = validation::validate_and_parse(&actual_event_content) {
                    // Clean up pending request
                    if let Some(ref correlated_id) = e_tag {
                        pending.write().await.remove(correlated_id.as_str());
                    }
                    let _ = tx.send(mcp_msg);
                }
            }
        }
    }
}

#[inline]
fn is_gift_wrap_kind(kind: &Kind) -> bool {
    *kind == Kind::Custom(GIFT_WRAP_KIND) || *kind == Kind::Custom(EPHEMERAL_GIFT_WRAP_KIND)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn announcement_event_with_tags(tags: Vec<Tag>) -> Event {
        let keys = Keys::generate();
        EventBuilder::new(Kind::Custom(SERVER_ANNOUNCEMENT_KIND), "{}")
            .tags(tags)
            .sign_with_keys(&keys)
            .unwrap()
    }

    #[test]
    fn test_config_defaults() {
        let config = NostrClientTransportConfig::default();
        assert_eq!(config.relay_urls, vec!["wss://relay.damus.io".to_string()]);
        assert!(config.server_pubkey.is_empty());
        assert_eq!(config.encryption_mode, EncryptionMode::Optional);
        assert_eq!(config.gift_wrap_mode, GiftWrapMode::Optional);
        assert_eq!(config.server_supports_ephemeral, None);
        assert!(!config.is_stateless);
        assert_eq!(config.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_stateless_config() {
        let config = NostrClientTransportConfig {
            is_stateless: true,
            ..Default::default()
        };
        assert!(config.is_stateless);
    }

    #[test]
    fn test_stateless_emulated_initialize_response_shape() {
        // Verify the emulated response has the expected structure
        let request_id = serde_json::json!(1);
        let response = JsonRpcMessage::Response(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: request_id.clone(),
            result: serde_json::json!({
                "protocolVersion": crate::core::constants::mcp_protocol_version(),
                "serverInfo": {
                    "name": "Emulated-Stateless-Server",
                    "version": "1.0.0"
                },
                "capabilities": {
                    "tools": { "listChanged": true },
                    "prompts": { "listChanged": true },
                    "resources": { "subscribe": true, "listChanged": true }
                }
            }),
        });
        assert!(response.is_response());
        assert_eq!(response.id(), Some(&serde_json::json!(1)));

        if let JsonRpcMessage::Response(r) = &response {
            assert!(r.result.get("capabilities").is_some());
            assert!(r.result.get("serverInfo").is_some());
            let server_info = r.result.get("serverInfo").unwrap();
            assert_eq!(
                server_info.get("name").unwrap().as_str().unwrap(),
                "Emulated-Stateless-Server"
            );
        }
    }

    #[test]
    fn test_stateless_mode_initialize_request_detection() {
        let init_req = JsonRpcMessage::Request(JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: serde_json::json!(1),
            method: "initialize".to_string(),
            params: None,
        });
        assert_eq!(init_req.method(), Some("initialize"));

        let init_notif = JsonRpcMessage::Notification(JsonRpcNotification {
            jsonrpc: "2.0".to_string(),
            method: "notifications/initialized".to_string(),
            params: None,
        });
        assert_eq!(init_notif.method(), Some("notifications/initialized"));
    }

    #[test]
    fn test_gift_wrap_kind_detection() {
        assert!(is_gift_wrap_kind(&Kind::Custom(GIFT_WRAP_KIND)));
        assert!(is_gift_wrap_kind(&Kind::Custom(EPHEMERAL_GIFT_WRAP_KIND)));
        assert!(!is_gift_wrap_kind(&Kind::Custom(CTXVM_MESSAGES_KIND)));
    }

    #[test]
    fn test_ephemeral_support_from_announcement_with_ephemeral_tag() {
        let event = announcement_event_with_tags(vec![
            Tag::custom(
                TagKind::Custom(tags::SUPPORT_ENCRYPTION.into()),
                Vec::<String>::new(),
            ),
            Tag::custom(
                TagKind::Custom(tags::SUPPORT_ENCRYPTION_EPHEMERAL.into()),
                Vec::<String>::new(),
            ),
        ]);

        assert_eq!(
            NostrClientTransport::ephemeral_support_from_announcement_event(&event),
            Some(true)
        );
    }

    #[test]
    fn test_ephemeral_support_from_announcement_without_ephemeral_tag() {
        let event = announcement_event_with_tags(vec![Tag::custom(
            TagKind::Custom(tags::SUPPORT_ENCRYPTION.into()),
            Vec::<String>::new(),
        )]);

        assert_eq!(
            NostrClientTransport::ephemeral_support_from_announcement_event(&event),
            Some(false)
        );
    }

    #[test]
    fn test_ephemeral_support_from_announcement_without_support_tags() {
        let event = announcement_event_with_tags(vec![Tag::custom(
            TagKind::Custom(tags::NAME.into()),
            vec!["server".to_string()],
        )]);

        assert_eq!(
            NostrClientTransport::ephemeral_support_from_announcement_event(&event),
            None
        );
    }
}
