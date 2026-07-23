//! #135 L2.3 — MCP tool dispatch over an Agent-Fabric channel.
//!
//! The application layer that turns the persistent request/response session ([`crate::a2a::serve_request_loop`],
//! L2.1) into a **callable service**: each framed request body is a JSON-RPC 2.0 message, this module
//! routes it to a registered tool and produces the JSON-RPC response body. It is transport-agnostic —
//! it never sees the Noise tunnel or the channel; the runner frames these bytes and the pump carries
//! them encrypted. MCP (Model Context Protocol) is JSON-RPC 2.0, so we model exactly the subset an
//! agent needs to expose capabilities: `tools/list` (advertise) and `tools/call` (invoke), plus a
//! minimal `initialize` handshake. Trust is unchanged: the channel already authenticated the peer via
//! Noise + the holder-attested membership (invariants #1–#3); a tool decides its own authorization.
//!
//! Envelope note: the frame envelope stays `noise::frame` (L2.1/L2.2) — JSON-RPC carries its own `id`
//! for request/response correlation inside the body, so no richer wire envelope is required here; any
//! version/type framing (the open L2.2 question) remains additive underneath this.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// The JSON-RPC protocol version every message carries.
const JSONRPC_VERSION: &str = "2.0";
/// The MCP protocol version this dispatcher advertises at `initialize`.
pub const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

// Standard JSON-RPC 2.0 error codes.
const PARSE_ERROR: i64 = -32700;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;
/// Implementation-defined server error range (JSON-RPC reserves -32000..=-32099); a tool that fails.
const TOOL_ERROR: i64 = -32000;

/// A parsed JSON-RPC 2.0 request. `id` is echoed verbatim into the response so a caller can correlate
/// concurrent calls; `params` is method-specific.
#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    #[serde(default)]
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Value,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

/// A JSON-RPC 2.0 response — exactly one of `result` / `error` is set.
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

/// A JSON-RPC 2.0 error object.
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

impl JsonRpcResponse {
    fn ok(id: Value, result: Value) -> Self {
        Self { jsonrpc: JSONRPC_VERSION.to_string(), id, result: Some(result), error: None }
    }
    fn err(id: Value, code: i64, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            result: None,
            error: Some(JsonRpcError { code, message: message.into() }),
        }
    }
    /// Serialize to the bytes that become one framed message body.
    fn into_bytes(self) -> Vec<u8> {
        // A response we constructed always serializes; fall back to a hand-built parse-error object.
        serde_json::to_vec(&self).unwrap_or_else(|_| {
            br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"response encode failed"}}"#
                .to_vec()
        })
    }
}

/// A tool the agent advertises + can be asked to run. `handler` maps the call's `arguments` object to a
/// result value (or an error message → a JSON-RPC tool error). Handlers are `Send + Sync` so the
/// registry can live behind an `Arc` in the persistent serve loop.
type ToolHandler = Box<dyn Fn(&Value) -> Result<Value, String> + Send + Sync>;

struct Tool {
    description: String,
    handler: ToolHandler,
}

/// A set of MCP tools an agent exposes over its channel. Dispatches JSON-RPC requests against them;
/// unknown methods/tools and malformed input all produce a well-formed JSON-RPC error response (never
/// a panic, never a dropped request), so one bad call can't wedge the persistent session.
#[derive(Default)]
pub struct ToolRegistry {
    tools: BTreeMap<String, Tool>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self { tools: BTreeMap::new() }
    }

    /// Register a tool by `name`, with a human `description` and a `handler(arguments) -> result`.
    pub fn register(
        &mut self,
        name: impl Into<String>,
        description: impl Into<String>,
        handler: impl Fn(&Value) -> Result<Value, String> + Send + Sync + 'static,
    ) -> &mut Self {
        self.tools.insert(
            name.into(),
            Tool { description: description.into(), handler: Box::new(handler) },
        );
        self
    }

    /// The `tools/list` payload — each tool's `name` + `description`.
    fn list(&self) -> Value {
        let tools: Vec<Value> = self
            .tools
            .iter()
            .map(|(name, t)| json!({ "name": name, "description": t.description }))
            .collect();
        json!({ "tools": tools })
    }

    /// Route one already-parsed request to a response.
    fn route(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let id = req.id;
        match req.method.as_str() {
            // Minimal MCP handshake — advertise the protocol version + that we serve tools.
            "initialize" => JsonRpcResponse::ok(
                id,
                json!({
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "ct-agent", "version": env!("CARGO_PKG_VERSION") }
                }),
            ),
            "tools/list" => JsonRpcResponse::ok(id, self.list()),
            "tools/call" => {
                let name = match req.params.get("name").and_then(Value::as_str) {
                    Some(n) => n,
                    None => {
                        return JsonRpcResponse::err(id, INVALID_PARAMS, "tools/call requires a string `name`")
                    }
                };
                let arguments = req.params.get("arguments").cloned().unwrap_or(Value::Null);
                match self.tools.get(name) {
                    Some(tool) => match (tool.handler)(&arguments) {
                        Ok(result) => JsonRpcResponse::ok(id, result),
                        Err(msg) => JsonRpcResponse::err(id, TOOL_ERROR, msg),
                    },
                    None => JsonRpcResponse::err(id, INVALID_PARAMS, format!("unknown tool `{name}`")),
                }
            }
            other => JsonRpcResponse::err(id, METHOD_NOT_FOUND, format!("unknown method `{other}`")),
        }
    }

    /// Dispatch one JSON-RPC request **body** to its response body (#135 L2.3). Malformed JSON yields a
    /// JSON-RPC parse-error response (id `null`) rather than an error — so `serve_request_loop` keeps
    /// serving. This is the `handle` a channel-`--serve` session runs.
    pub fn dispatch(&self, request: &[u8]) -> Vec<u8> {
        let req: JsonRpcRequest = match serde_json::from_slice(request) {
            Ok(r) => r,
            Err(e) => {
                return JsonRpcResponse::err(Value::Null, PARSE_ERROR, format!("invalid JSON-RPC: {e}"))
                    .into_bytes()
            }
        };
        self.route(req).into_bytes()
    }
}

/// Encode a JSON-RPC 2.0 request **body** (#135 L2.3, client side) — the bytes a caller frames and
/// sends to a peer's `--serve` MCP endpoint. `id` correlates the eventual response; `params` is
/// method-specific (`Value::Null` when a method takes none).
pub fn encode_request(id: impl Into<Value>, method: &str, params: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": id.into(),
        "method": method,
        "params": params,
    }))
    .expect("a request we constructed always serializes")
}

/// Decode a JSON-RPC 2.0 response **body** a peer's MCP endpoint returned (#135 L2.3, client side).
pub fn decode_response(bytes: &[u8]) -> Result<JsonRpcResponse, String> {
    serde_json::from_slice(bytes).map_err(|e| format!("invalid JSON-RPC response: {e}"))
}

/// A minimal default tool registry for `ct-agent channel --serve` (#135 L2.3): a `ping` liveness tool,
/// so the persistent service is callable out of the box (`tools/list` → `[ping]`, `tools/call ping` →
/// `pong`). A real agent extends this with its own capability tools.
pub fn default_registry() -> ToolRegistry {
    let mut r = ToolRegistry::new();
    r.register("ping", "liveness check → returns pong", |_| Ok(json!({ "reply": "pong" })));
    r
}

fn to_hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Register #147-L4.3 settlement-chain **gossip** tools on a registry, over a shared `chain`, so the
/// ledger propagates over the SAME authenticated #135 Agent-Fabric channel agents discover + cooperate
/// on (no separate P2P layer):
/// - `settlement/block` `{block: <hex>}` — decode + [`accept_block`](crate::settlement::Chain::accept_block)
///   a peer's block; returns the new `height` + `tip` (or a JSON-RPC tool error if it doesn't extend
///   the tip / is invalid — the ledger stays unchanged).
/// - `settlement/balance` `{account: <hex 32-byte>}` — query an account balance.
///
/// The send side is an agent calling `settlement/block` on its peers with `chain.tip_block().encode()`.
pub fn register_settlement_tools(
    reg: &mut ToolRegistry,
    chain: std::sync::Arc<std::sync::Mutex<crate::settlement::Chain>>,
) {
    let accept = std::sync::Arc::clone(&chain);
    reg.register(
        "settlement/block",
        "accept a gossiped settlement block (hex-encoded) into the ledger",
        move |args| {
            let hex = args.get("block").and_then(Value::as_str).ok_or("missing hex `block`")?;
            let bytes = from_hex(hex).ok_or("`block` is not valid hex")?;
            let block = crate::settlement::Block::decode(&bytes).ok_or("malformed block encoding")?;
            let mut chain = accept.lock().map_err(|_| "settlement chain lock poisoned")?;
            chain.accept_block(block).map_err(|e| e.to_string())?;
            Ok(json!({ "accepted": true, "height": chain.height(), "tip": to_hex(&chain.tip_hash()) }))
        },
    );
    let query = std::sync::Arc::clone(&chain);
    reg.register(
        "settlement/balance",
        "query a settlement account balance (32-byte hex account)",
        move |args| {
            let hex = args.get("account").and_then(Value::as_str).ok_or("missing hex `account`")?;
            let account: [u8; 32] = from_hex(hex)
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .ok_or("`account` must be 32-byte hex")?;
            let chain = query.lock().map_err(|_| "settlement chain lock poisoned")?;
            Ok(json!({ "balance": chain.balance(&account) }))
        },
    );
}

/// The [`default_registry`] plus an **`agent/card`** tool returning `card_json` (#144 × #135): a peer
/// that has connected over the authenticated channel can fetch the agent's holder-signed `AgentCard`
/// directly, bound to the live session — the channel is authenticated by the same holder key, so the
/// card the peer gets here is provably the one the connected agent holds (not merely one served at a
/// URL). `card_json` is the card's JSON profile (`serde_json::to_value(&card)`).
pub fn registry_with_card(card_json: Value) -> ToolRegistry {
    let mut r = default_registry();
    r.register(
        "agent/card",
        "the agent's holder-signed AgentCard — identity over the authenticated channel",
        move |_| Ok(card_json.clone()),
    );
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> ToolRegistry {
        let mut r = ToolRegistry::new();
        r.register("ping", "liveness check → pong", |_args| Ok(json!({ "reply": "pong" })));
        r.register("echo", "echo the `text` argument", |args| {
            let text = args.get("text").and_then(Value::as_str).ok_or("missing `text`")?;
            Ok(json!({ "text": text }))
        });
        r
    }

    fn call(reg: &ToolRegistry, body: Value) -> JsonRpcResponse {
        let bytes = reg.dispatch(&serde_json::to_vec(&body).unwrap());
        serde_json::from_slice(&bytes).expect("response is valid JSON-RPC")
    }

    #[test]
    fn tools_list_advertises_registered_tools() {
        // #135 L2.3 (frozen): tools/list returns each registered tool's name + description, id echoed.
        let resp = call(&registry(), json!({ "jsonrpc": "2.0", "id": 7, "method": "tools/list" }));
        assert_eq!(resp.id, json!(7), "the request id is echoed back for correlation");
        let tools = resp.result.unwrap();
        let names: Vec<&str> =
            tools["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"ping") && names.contains(&"echo"), "advertises both tools, got {names:?}");
    }

    #[test]
    fn tools_call_invokes_the_named_tool_and_returns_its_result() {
        // #135 L2.3 (frozen): tools/call routes to the handler by name and returns its result.
        let resp = call(
            &registry(),
            json!({ "jsonrpc": "2.0", "id": "a", "method": "tools/call",
                    "params": { "name": "echo", "arguments": { "text": "hi" } } }),
        );
        assert_eq!(resp.id, json!("a"));
        assert_eq!(resp.result.unwrap(), json!({ "text": "hi" }), "the echo tool's result flows back");
        assert!(resp.error.is_none());
    }

    #[test]
    fn tools_call_reports_a_tool_error_without_wedging() {
        // A handler that fails on bad args returns a JSON-RPC tool error (not a panic / dropped request).
        let resp = call(
            &registry(),
            json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": { "name": "echo", "arguments": {} } }),
        );
        let err = resp.error.expect("a failing tool yields an error object");
        assert_eq!(err.code, TOOL_ERROR);
        assert!(err.message.contains("text"), "the handler's message is surfaced: {}", err.message);
        assert!(resp.result.is_none());
    }

    #[test]
    fn unknown_tool_and_unknown_method_and_malformed_all_return_wellformed_errors() {
        let reg = registry();

        // Unknown tool → invalid params.
        let unknown_tool = call(
            &reg,
            json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": { "name": "nope" } }),
        );
        assert_eq!(unknown_tool.error.unwrap().code, INVALID_PARAMS);

        // Unknown method → method not found.
        let unknown_method =
            call(&reg, json!({ "jsonrpc": "2.0", "id": 3, "method": "does/not/exist" }));
        assert_eq!(unknown_method.error.unwrap().code, METHOD_NOT_FOUND);

        // Malformed JSON → parse error, id null, still a well-formed JSON-RPC response.
        let bytes = reg.dispatch(b"{ this is not json");
        let resp: JsonRpcResponse = serde_json::from_slice(&bytes).expect("parse-error response is valid JSON-RPC");
        assert_eq!(resp.id, Value::Null);
        assert_eq!(resp.error.unwrap().code, PARSE_ERROR);
    }

    #[test]
    fn client_encode_and_server_dispatch_interoperate_round_trip() {
        // #135 L2.3 (frozen): the client encodes a JSON-RPC request, the server's ToolRegistry
        // dispatches it, and the client decodes the response — the full call/serve pair interoperates
        // at exactly the message layer that rides one framed message over the channel.
        let reg = registry();

        let req = encode_request(42, "tools/call", json!({ "name": "ping" }));
        let resp = decode_response(&reg.dispatch(&req)).expect("a valid JSON-RPC response");
        assert_eq!(resp.id, json!(42), "the id correlates the response to the request");
        assert_eq!(resp.result.unwrap(), json!({ "reply": "pong" }), "ping answered over the pair");
        assert!(resp.error.is_none());

        // A string id and a params-less method also round-trip.
        let list = decode_response(&reg.dispatch(&encode_request("c1", "tools/list", Value::Null)))
            .expect("valid response");
        assert_eq!(list.id, json!("c1"));
        assert!(list.result.unwrap()["tools"].as_array().unwrap().len() >= 2);
    }

    #[test]
    fn settlement_tools_gossip_a_block_over_mcp_and_report_balances() {
        // #147-L4.3 (frozen): a producer mines a block, encodes it, and gossips it via the
        // `settlement/block` MCP tool to a replica — which accepts it and converges; `settlement/balance`
        // reads the result. So the settlement ledger rides the #135 authenticated channel. A malformed
        // block returns a JSON-RPC tool error and leaves the ledger unchanged.
        use crate::settlement::{Chain, Transfer};
        use ed25519_dalek::SigningKey;
        use std::collections::BTreeMap;
        use std::sync::{Arc, Mutex};

        let alice = SigningKey::from_bytes(&[1u8; 32]);
        let bob = SigningKey::from_bytes(&[2u8; 32]);
        let (a, b) = (alice.verifying_key().to_bytes(), bob.verifying_key().to_bytes());
        let genesis = BTreeMap::from([(a, 100u64)]);

        let mut producer = Chain::new(genesis.clone());
        producer.append(vec![Transfer::sign_new(&alice, b, 40, 0)]).unwrap();
        let block_hex = to_hex(&producer.tip_block().encode());

        // The replica exposes the gossip tools over its own (same-genesis) chain.
        let replica = Arc::new(Mutex::new(Chain::new(genesis)));
        let mut reg = default_registry();
        register_settlement_tools(&mut reg, Arc::clone(&replica));

        // Gossip the block over MCP → accepted, height 1.
        let resp = call(&reg, json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "settlement/block", "arguments": { "block": block_hex } } }));
        let r = resp.result.expect("settlement/block succeeds");
        assert_eq!(r["accepted"], json!(true));
        assert_eq!(r["height"], json!(1), "the replica advanced to height 1");

        // Query bob's balance over MCP → 40.
        let bal = call(&reg, json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": { "name": "settlement/balance", "arguments": { "account": to_hex(&b) } } }));
        assert_eq!(bal.result.unwrap()["balance"], json!(40), "settlement/balance reads the replicated ledger");

        // A malformed block → JSON-RPC tool error, ledger unchanged.
        let bad = call(&reg, json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": { "name": "settlement/block", "arguments": { "block": "zz" } } }));
        assert!(bad.error.is_some(), "a malformed block is a tool error, not a panic");
        assert_eq!(replica.lock().unwrap().height(), 1, "no bad block was committed");
    }

    #[test]
    fn registry_with_card_serves_the_agent_card_over_the_tool() {
        // #144 × #135 (frozen): a card-aware registry exposes `agent/card`; tools/list advertises it
        // and tools/call returns exactly the supplied card JSON (the identity a peer fetches over the
        // authenticated channel). ping still works alongside it.
        let card = json!({ "holder_pubkey": "af1491a7", "role_tags": ["sink"], "expires_at": 5000 });
        let reg = registry_with_card(card.clone());

        let listed: Vec<String> = reg
            .list()["tools"].as_array().unwrap()
            .iter().map(|t| t["name"].as_str().unwrap().to_string()).collect();
        assert!(listed.contains(&"agent/card".to_string()), "agent/card advertised, got {listed:?}");
        assert!(listed.contains(&"ping".to_string()), "ping still present");

        let resp = call(&reg, json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                      "params": { "name": "agent/card" } }));
        assert_eq!(resp.result.unwrap(), card, "agent/card returns the exact card JSON");
    }

    #[test]
    fn initialize_advertises_the_mcp_protocol_version_and_tools_capability() {
        let resp = call(&registry(), json!({ "jsonrpc": "2.0", "id": 0, "method": "initialize" }));
        let result = resp.result.unwrap();
        assert_eq!(result["protocolVersion"], json!(MCP_PROTOCOL_VERSION));
        assert!(result["capabilities"].get("tools").is_some(), "advertises the tools capability");
    }
}
