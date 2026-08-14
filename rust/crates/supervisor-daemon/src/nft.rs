//! nftables rule engine, ported rule-for-rule from the Python firewall
//! (src/aleph/vm/network/firewall.py).
//!
//! Two layers, so parity is testable without root:
//!
//! - A PURE layer: functions from a ruleset snapshot (the parsed
//!   `nft -j list ruleset` entries, ip and ip6 merged) to nftables JSON
//!   command batches, mirroring the Python builders and their dedup
//!   (`is_entity_present` / `add_entities_if_not_present`). The committed
//!   fixture `tests/fixtures/nftables.json`, captured from the actual
//!   firewall.py with its fetch/execute edges stubbed, pins every scenario:
//!   same input ruleset in, same command batches out.
//! - A thin APPLY layer at the edge: [`NftExecutor`] fetches rulesets and
//!   runs command batches. The production implementation shells out to
//!   `nft -j` (the same libnftables JSON dialect the Python `nftables`
//!   binding speaks); tests use [`StaticRuleset`].
//!
//! Everything operates on `serde_json::Value`, like the Python dicts: the
//! nftables JSON schema is the shared vocabulary and typing it would only
//! invite drift.

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

/// `NoBaseChainFound`: the host has no base chain for a hook the setup
/// needs. The Python exception aborts the calling operation the same way.
#[derive(Debug, thiserror::Error)]
#[error("Could not find any base chain for hook '{hook}'")]
pub struct NoBaseChainFound {
    pub hook: String,
}

/// Failures fetching or applying nftables state via `nft(8)`.
#[derive(Debug, thiserror::Error)]
pub enum NftError {
    #[error("Failed to find or create a 'nat' type prerouting chain")]
    NoNatPrerouting,

    #[error("cannot run nft: {source}")]
    Run { source: std::io::Error },

    #[error("nft list ruleset {family} failed ({status}): {stderr}")]
    ListFailed {
        family: String,
        status: std::process::ExitStatus,
        stderr: String,
    },

    #[error("nft returned invalid JSON: {source}")]
    InvalidJson { source: serde_json::Error },

    #[error("cannot serialize nft commands: {source}")]
    Serialize { source: serde_json::Error },

    #[error("cannot write to nft stdin: {source}")]
    StdinWrite { source: std::io::Error },

    #[error("nft did not terminate: {source}")]
    Wait { source: std::io::Error },

    #[error("nft -j -f - failed ({status}): {stderr}")]
    ApplyFailed {
        status: std::process::ExitStatus,
        stderr: String,
    },

    /// A fabricated error for test `NftExecutor` fakes that need to report a
    /// specific failure without shelling out to a real `nft`.
    #[error("injected nft failure (matched {needle:?})")]
    Injected { needle: String },
}

// ── Entity presence (the dedup) ─────────────────────────────────────────

/// Python `_is_superset`: every key of `a` exists in `b` with a superset
/// value; lists must have equal length and pairwise-superset items.
fn is_superset(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Object(a), Value::Object(b)) => a
            .iter()
            .all(|(key, value)| b.get(key).is_some_and(|other| is_superset(value, other))),
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| is_superset(x, y))
        }
        _ => a == b,
    }
}

/// Python `is_entity_present`: at least the entity's own keys match some
/// ruleset entry of the same kind (extra attributes like handles ignored).
fn is_entity_present(ruleset: &[Value], kind: &str, entity: &Value) -> bool {
    ruleset.iter().any(|entry| {
        entry
            .get(kind)
            .is_some_and(|listed| is_superset(entity, listed))
    })
}

/// One entity is `{"chain": {...}}` / `{"rule": {...}}` / `{"table": {...}}`,
/// exactly the Python `dict[EntityType, dict]` shape.
fn entity_kind(entity: &Value) -> (&str, &Value) {
    let object = entity
        .as_object()
        .expect("nft entities are single-key objects");
    debug_assert_eq!(object.len(), 1, "nft entities are single-key objects");
    let (kind, value) = object.iter().next().expect("entity cannot be empty");
    (kind, value)
}

/// Python `add_entity_if_not_present`: the `add` command when missing.
fn add_entity_if_not_present(ruleset: &[Value], entity: &Value) -> Vec<Value> {
    let (kind, value) = entity_kind(entity);
    if is_entity_present(ruleset, kind, value) {
        Vec::new()
    } else {
        vec![json!({"add": entity})]
    }
}

/// Python `add_entities_if_not_present`.
pub fn add_entities_if_not_present(ruleset: &[Value], entities: &[Value]) -> Vec<Value> {
    entities
        .iter()
        .flat_map(|entity| add_entity_if_not_present(ruleset, entity))
        .collect()
}

// ── Base chain discovery ────────────────────────────────────────────────

/// Python `get_base_chains_for_hook`: chains of `family` hooked at `hook`.
fn get_base_chains_for_hook<'r>(ruleset: &'r [Value], hook: &str, family: &str) -> Vec<&'r Value> {
    ruleset
        .iter()
        .filter(|entry| {
            entry.get("chain").is_some_and(|chain| {
                chain.get("family").and_then(Value::as_str) == Some(family)
                    && chain.get("hook").and_then(Value::as_str) == Some(hook)
            })
        })
        .collect()
}

fn prio_of(chain_entry: &Value) -> i64 {
    // Python get_table_for_hook: x["chain"].get("prio", 0).
    chain_entry["chain"]
        .get("prio")
        .and_then(Value::as_i64)
        .unwrap_or(0)
}

/// Python `get_table_for_hook`: the table whose base chain the aleph chains
/// hang off. prerouting needs a `nat`-type chain (highest priority wins);
/// the other hooks take the earliest (lowest priority) chain.
pub fn get_table_for_hook(
    ruleset: &[Value],
    hook: &str,
    family: &str,
) -> Result<String, NoBaseChainFound> {
    let mut chains = get_base_chains_for_hook(ruleset, hook, family);
    if chains.is_empty() {
        return Err(NoBaseChainFound {
            hook: hook.to_string(),
        });
    }
    chains.sort_by_key(|entry| prio_of(entry));
    let table_of = |entry: &Value| {
        entry["chain"]["table"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    };
    if hook == "prerouting" {
        let nat_chains: Vec<&&Value> = chains
            .iter()
            .filter(|entry| entry["chain"].get("type").and_then(Value::as_str) == Some("nat"))
            .collect();
        match nat_chains.last() {
            Some(entry) => Ok(table_of(entry)),
            None => {
                // Python falls back to the highest-priority chain with a
                // warning (the subsequent DNAT rule will fail, as its log
                // message admits); ported as-is.
                tracing::warn!(
                    "No 'nat' type prerouting chain found. Falling back to highest prio chain."
                );
                Ok(table_of(chains.last().expect("chains is non-empty")))
            }
        }
    } else {
        Ok(table_of(chains.first().expect("chains is non-empty")))
    }
}

// ── initialize_nftables ─────────────────────────────────────────────────

/// Phase 1 of Python `initialize_nftables`: the ip-family base chains
/// (created when absent) and the three supervisor chains with their jump
/// rules. Pure: `ruleset` stands in for every fetch the Python code makes
/// during this phase (the kernel state does not change under it).
pub fn initialize_ipv4_commands(ruleset: &[Value], prefix: &str) -> Result<Vec<Value>, NftError> {
    let mut commands: Vec<Value> = Vec::new();
    // hook -> the base chain object the aleph chains attach to.
    let mut base_chains: Vec<(&str, Value)> = Vec::new();

    for hook in ["prerouting", "postrouting", "forward"] {
        // Owned copies: a missing base chain is materialized below and joins
        // the candidate list, like the Python `chains.append(new_chain)`.
        let mut chains: Vec<Value> = get_base_chains_for_hook(ruleset, hook, "ip")
            .into_iter()
            .cloned()
            .collect();
        if chains.is_empty() {
            let default_chain = match hook {
                "postrouting" => json!({
                    "family": "ip", "table": "nat", "name": "POSTROUTING",
                    "type": "nat", "hook": "postrouting", "prio": 100,
                }),
                "forward" => json!({
                    "family": "ip", "table": "filter", "name": "FORWARD",
                    "type": "filter", "hook": "forward", "prio": 0,
                }),
                _ => json!({
                    "family": "ip", "table": "nat", "name": "PREROUTING",
                    "type": "nat", "hook": "prerouting", "prio": -100,
                    "policy": "accept",
                }),
            };
            // The table dedup checks the ORIGINAL ruleset every time, so on
            // an empty host the `add table nat` command is emitted once per
            // nat-hook (prerouting and postrouting). Python wart, kept:
            // re-adding an existing table is a no-op for nft.
            commands.extend(add_entity_if_not_present(
                ruleset,
                &json!({"table": {"family": "ip", "name": default_chain["table"]}}),
            ));
            commands.push(json!({"add": {"chain": default_chain}}));
            chains.push(json!({"chain": default_chain}));
        }

        chains.sort_by_key(prio_of);
        let selected = if hook == "prerouting" {
            let nat_chains: Vec<&Value> = chains
                .iter()
                .filter(|entry| entry["chain"].get("type").and_then(Value::as_str) == Some("nat"))
                .collect();
            match nat_chains.last() {
                Some(entry) => (*entry).clone(),
                // Python raises a bare Exception here and its daemon dies
                // at boot; the Rust boot logs and serves instead (ledger
                // entry 22) while the RecreateNetwork RPC fails the same
                // way as Python's.
                None => return Err(NftError::NoNatPrerouting),
            }
        } else {
            chains.first().expect("chains is non-empty").clone()
        };
        base_chains.push((hook, selected["chain"].clone()));
    }

    let table_for = |hook: &str| -> Value {
        base_chains
            .iter()
            .find(|(name, _)| *name == hook)
            .map(|(_, chain)| chain["table"].clone())
            .expect("all three hooks were resolved above")
    };
    let name_for = |hook: &str| -> Value {
        base_chains
            .iter()
            .find(|(name, _)| *name == hook)
            .map(|(_, chain)| chain["name"].clone())
            .expect("all three hooks were resolved above")
    };

    // The supervisor chains and their jump rules, in Python emission order.
    for entity in [
        json!({"chain": {
            "family": "ip", "table": table_for("postrouting"),
            "name": format!("{prefix}-supervisor-nat"),
        }}),
        json!({"rule": {
            "family": "ip", "table": table_for("postrouting"),
            "chain": name_for("postrouting"),
            "expr": [{"jump": {"target": format!("{prefix}-supervisor-nat")}}],
        }}),
        json!({"chain": {
            "family": "ip", "table": table_for("forward"),
            "name": format!("{prefix}-supervisor-filter"),
        }}),
        json!({"rule": {
            "family": "ip", "table": table_for("forward"),
            "chain": name_for("forward"),
            "expr": [{"jump": {"target": format!("{prefix}-supervisor-filter")}}],
        }}),
        json!({"rule": {
            "family": "ip", "table": table_for("forward"),
            "chain": format!("{prefix}-supervisor-filter"),
            "expr": [
                {"match": {
                    "op": "in",
                    "left": {"ct": {"key": "state"}},
                    "right": ["established", "related"],
                }},
                {"accept": null},
            ],
        }}),
        json!({"chain": {
            "family": "ip", "table": table_for("prerouting"),
            "name": format!("{prefix}-supervisor-prerouting"),
        }}),
        json!({"rule": {
            "family": "ip", "table": table_for("prerouting"),
            "chain": name_for("prerouting"),
            "expr": [{"jump": {"target": format!("{prefix}-supervisor-prerouting")}}],
        }}),
    ] {
        commands.extend(add_entity_if_not_present(ruleset, &entity));
    }
    Ok(commands)
}

/// Phase 2 of Python `initialize_nftables` (IPV6_FORWARDING_ENABLED only):
/// the ip6 forward chain plus the supervisor filter chain. Python re-fetches
/// the ruleset between the phases; the apply layer does the same.
pub fn initialize_ipv6_commands(ruleset: &[Value], prefix: &str) -> Vec<Value> {
    let mut commands: Vec<Value> = Vec::new();
    let mut chains: Vec<Value> = get_base_chains_for_hook(ruleset, "forward", "ip6")
        .into_iter()
        .cloned()
        .collect();
    if chains.is_empty() {
        commands.extend(add_entity_if_not_present(
            ruleset,
            &json!({"table": {"family": "ip6", "name": "filter"}}),
        ));
        let base = json!({
            "family": "ip6", "table": "filter", "name": "FORWARD",
            "type": "filter", "hook": "forward", "prio": 0,
        });
        commands.push(json!({"add": {"chain": base}}));
        chains.push(json!({"chain": base}));
    }
    chains.sort_by_key(prio_of);
    let base = chains.first().expect("chains is non-empty")["chain"].clone();

    for entity in [
        json!({"chain": {
            "family": "ip6", "table": base["table"],
            "name": format!("{prefix}-supervisor-filter"),
        }}),
        json!({"rule": {
            "family": "ip6", "table": base["table"], "chain": base["name"],
            "expr": [{"jump": {"target": format!("{prefix}-supervisor-filter")}}],
        }}),
        json!({"rule": {
            "family": "ip6", "table": base["table"],
            "chain": format!("{prefix}-supervisor-filter"),
            "expr": [
                {"match": {
                    "op": "in",
                    "left": {"ct": {"key": "state"}},
                    "right": ["established", "related"],
                }},
                {"accept": null},
            ],
        }}),
    ] {
        commands.extend(add_entity_if_not_present(ruleset, &entity));
    }
    commands
}

// ── Per-VM chains and rules ─────────────────────────────────────────────

/// Python `build_postrouting_chain_entities`.
fn postrouting_chain_entities(table: &str, chain_name: &str, prefix: &str) -> Vec<Value> {
    vec![
        json!({"chain": {"family": "ip", "table": table, "name": chain_name}}),
        json!({"rule": {
            "family": "ip", "table": table,
            "chain": format!("{prefix}-supervisor-nat"),
            "expr": [{"jump": {"target": chain_name}}],
        }}),
    ]
}

/// Python `build_forward_chain_entities`.
fn forward_chain_entities(table: &str, chain_name: &str, family: &str, prefix: &str) -> Vec<Value> {
    vec![
        json!({"chain": {"family": family, "table": table, "name": chain_name}}),
        json!({"rule": {
            "family": family, "table": table,
            "chain": format!("{prefix}-supervisor-filter"),
            "expr": [{"jump": {"target": chain_name}}],
        }}),
    ]
}

/// Python `build_masquerading_rule_entities`.
fn masquerading_rule_entities(
    table: &str,
    vm_index: i64,
    device_name: &str,
    network_interface: &str,
    prefix: &str,
) -> Vec<Value> {
    vec![json!({"rule": {
        "family": "ip", "table": table,
        "chain": format!("{prefix}-vm-nat-{vm_index}"),
        "expr": [
            {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": device_name}},
            {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": network_interface}},
            {"masquerade": null},
        ],
    }})]
}

/// Python `build_forward_rule_entities`.
fn forward_rule_entities(
    table: &str,
    vm_index: i64,
    device_name: &str,
    family: &str,
    network_interface: &str,
    prefix: &str,
) -> Vec<Value> {
    vec![json!({"rule": {
        "family": family, "table": table,
        "chain": format!("{prefix}-vm-filter-{vm_index}"),
        "expr": [
            {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": device_name}},
            {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": network_interface}},
            {"accept": null},
        ],
    }})]
}

/// Python `setup_nftables_for_vm`, pure half: the missing per-VM chains and
/// rules for one VM, deduplicated against `ruleset`.
pub fn setup_vm_commands(
    ruleset: &[Value],
    vm_index: i64,
    device_name: &str,
    network_interface: &str,
    prefix: &str,
    ipv6_forwarding_enabled: bool,
) -> Result<Vec<Value>, NoBaseChainFound> {
    let post_table = get_table_for_hook(ruleset, "postrouting", "ip")?;
    let fwd_table = get_table_for_hook(ruleset, "forward", "ip")?;
    let nat_chain = format!("{prefix}-vm-nat-{vm_index}");
    let filter_chain = format!("{prefix}-vm-filter-{vm_index}");

    let mut entities = Vec::new();
    entities.extend(postrouting_chain_entities(&post_table, &nat_chain, prefix));
    entities.extend(forward_chain_entities(
        &fwd_table,
        &filter_chain,
        "ip",
        prefix,
    ));
    entities.extend(masquerading_rule_entities(
        &post_table,
        vm_index,
        device_name,
        network_interface,
        prefix,
    ));
    entities.extend(forward_rule_entities(
        &fwd_table,
        vm_index,
        device_name,
        "ip",
        network_interface,
        prefix,
    ));
    if ipv6_forwarding_enabled {
        let ip6_fwd_table = get_table_for_hook(ruleset, "forward", "ip6")?;
        entities.extend(forward_chain_entities(
            &ip6_fwd_table,
            &filter_chain,
            "ip6",
            prefix,
        ));
        entities.extend(forward_rule_entities(
            &ip6_fwd_table,
            vm_index,
            device_name,
            "ip6",
            network_interface,
            prefix,
        ));
    }
    Ok(add_entities_if_not_present(ruleset, &entities))
}

/// Python `build_port_redirect_entities`: the DNAT prerouting rule plus the
/// forward-accept rule in the per-VM filter chain.
#[allow(clippy::too_many_arguments)] // mirrors the Python builder signature
pub fn port_redirect_entities(
    vm_index: i64,
    guest_ipv4: &str,
    host_port: u32,
    vm_port: u32,
    protocol: &str,
    prerouting_table: &str,
    forward_table: &str,
    network_interface: &str,
    prefix: &str,
) -> Vec<Value> {
    vec![
        json!({"rule": {
            "family": "ip", "table": prerouting_table,
            "chain": format!("{prefix}-supervisor-prerouting"),
            "expr": [
                {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": network_interface}},
                {"match": {"op": "==", "left": {"payload": {"protocol": protocol, "field": "dport"}}, "right": host_port}},
                {"dnat": {"addr": guest_ipv4, "port": vm_port}},
            ],
        }}),
        json!({"rule": {
            "family": "ip", "table": forward_table,
            "chain": format!("{prefix}-vm-filter-{vm_index}"),
            "expr": [
                {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": network_interface}},
                {"match": {"op": "==", "left": {"payload": {"protocol": protocol, "field": "dport"}}, "right": vm_port}},
                {"accept": null},
            ],
        }}),
    ]
}

/// Python `add_port_redirect_rule`, pure half (`ensure_entities` dedup).
#[allow(clippy::too_many_arguments)]
pub fn add_port_redirect_commands(
    ruleset: &[Value],
    vm_index: i64,
    guest_ipv4: &str,
    host_port: u32,
    vm_port: u32,
    protocol: &str,
    network_interface: &str,
    prefix: &str,
) -> Result<Vec<Value>, NoBaseChainFound> {
    let prerouting_table = get_table_for_hook(ruleset, "prerouting", "ip")?;
    let forward_table = get_table_for_hook(ruleset, "forward", "ip")?;
    let entities = port_redirect_entities(
        vm_index,
        guest_ipv4,
        host_port,
        vm_port,
        protocol,
        &prerouting_table,
        &forward_table,
        network_interface,
        prefix,
    );
    Ok(add_entities_if_not_present(ruleset, &entities))
}

/// Lax integer read: nft emits numbers, but Python coerces with `int(...)`
/// which also accepts numeric strings; mirror that.
fn as_int(value: &Value) -> Option<i64> {
    match value {
        Value::Number(number) => number.as_i64(),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

fn match_of(expression: &Value) -> Option<&Value> {
    expression.get("match")
}

fn is_iifname_match(expression: &Value, interface: &str) -> bool {
    match_of(expression).is_some_and(|matched| {
        matched["left"]["meta"]["key"].as_str() == Some("iifname")
            && matched["right"].as_str() == Some(interface)
    })
}

fn is_dport_match(expression: &Value, protocol: &str, port: u32) -> bool {
    match_of(expression).is_some_and(|matched| {
        matched["left"]["payload"]["protocol"].as_str() == Some(protocol)
            && matched["left"]["payload"]["field"].as_str() == Some("dport")
            && matched
                .get("right")
                .and_then(as_int)
                .is_some_and(|value| value == i64::from(port))
    })
}

/// Python `remove_port_redirect_rule`, pure half: handle-addressed deletes
/// for the DNAT rule and its forward-accept counterpart.
#[allow(clippy::too_many_arguments)]
pub fn remove_port_redirect_commands(
    ruleset: &[Value],
    device_name: &str,
    guest_ipv4: &str,
    host_port: u32,
    vm_port: u32,
    protocol: &str,
    network_interface: &str,
    prefix: &str,
) -> Result<Vec<Value>, NoBaseChainFound> {
    let chain_name = format!("{prefix}-supervisor-prerouting");
    let prerouting_table = get_table_for_hook(ruleset, "prerouting", "ip")?;
    let forward_table = get_table_for_hook(ruleset, "forward", "ip")?;
    // Python: vm_index = device_name.removeprefix("vmtap").
    let vm_index = device_name.strip_prefix("vmtap").unwrap_or(device_name);
    let filter_chain = format!("{prefix}-vm-filter-{vm_index}");

    let mut commands = Vec::new();
    for entry in ruleset {
        let Some(rule) = entry.get("rule") else {
            continue;
        };
        let Some(expr) = rule.get("expr").and_then(Value::as_array) else {
            continue;
        };
        if rule["family"].as_str() != Some("ip") || expr.len() != 3 {
            continue;
        }

        // The DNAT prerouting rule.
        if rule["table"].as_str() == Some(prerouting_table.as_str())
            && rule["chain"].as_str() == Some(chain_name.as_str())
            && is_iifname_match(&expr[0], network_interface)
            && is_dport_match(&expr[1], protocol, host_port)
            && expr[2].get("dnat").is_some_and(|dnat| {
                dnat["addr"].as_str() == Some(guest_ipv4)
                    && dnat
                        .get("port")
                        .and_then(as_int)
                        .is_some_and(|port| port == i64::from(vm_port))
            })
        {
            commands.push(json!({"delete": {"rule": {
                "family": "ip", "table": prerouting_table, "chain": chain_name,
                "handle": rule["handle"],
            }}}));
        }

        // The matching forward-accept rule.
        if rule["table"].as_str() == Some(forward_table.as_str())
            && rule["chain"].as_str() == Some(filter_chain.as_str())
            && is_iifname_match(&expr[0], network_interface)
            && is_dport_match(&expr[1], protocol, vm_port)
            && expr[2].get("accept").is_some()
        {
            commands.push(json!({"delete": {"rule": {
                "family": "ip", "table": forward_table, "chain": filter_chain,
                "handle": rule["handle"],
            }}}));
        }
    }
    Ok(commands)
}

/// Python `remove_chain`, pure half: delete every jump to `name` (any
/// family), then the chains named `name` themselves.
pub fn remove_chain_commands(ruleset: &[Value], name: &str) -> Vec<Value> {
    let mut commands = Vec::new();
    let mut chain_deletes = Vec::new();
    for entry in ruleset {
        if let Some(rule) = entry.get("rule")
            && rule
                .get("expr")
                .and_then(Value::as_array)
                .and_then(|expr| expr.first())
                .and_then(|first| first.get("jump"))
                .is_some_and(|jump| jump["target"].as_str() == Some(name))
        {
            commands.push(json!({"delete": {"rule": {
                "family": rule["family"], "table": rule["table"],
                "chain": rule["chain"], "handle": rule["handle"],
            }}}));
        } else if let Some(chain) = entry.get("chain")
            && chain["name"].as_str() == Some(name)
        {
            chain_deletes.push(json!({"delete": {"chain": {
                "family": chain["family"], "table": chain["table"],
                "name": chain["name"],
            }}}));
        }
    }
    commands.extend(chain_deletes);
    commands
}

/// Python `get_all_aleph_chains`: every chain name starting with the prefix,
/// in listing order (duplicates across families kept, as in Python).
pub fn get_all_aleph_chains(ruleset: &[Value], prefix: &str) -> Vec<String> {
    ruleset
        .iter()
        .filter_map(|entry| entry.get("chain"))
        .filter_map(|chain| chain.get("name").and_then(Value::as_str))
        .filter(|name| name.starts_with(prefix))
        .map(str::to_string)
        .collect()
}

/// Python `check_port_redirect_exists`: a DNAT rule in the supervisor
/// prerouting chain matching (host_port, vm_ip, vm_port, protocol).
pub fn check_port_redirect_exists(
    ruleset: &[Value],
    host_port: u32,
    vm_ip: &str,
    vm_port: u32,
    protocol: &str,
    prefix: &str,
) -> bool {
    let chain_name = format!("{prefix}-supervisor-prerouting");
    for entry in ruleset {
        let Some(rule) = entry.get("rule") else {
            continue;
        };
        if rule["chain"].as_str() != Some(chain_name.as_str()) {
            continue;
        }
        let expr = rule
            .get("expr")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut found_dport = false;
        let mut found_dnat = false;
        for expression in &expr {
            if is_dport_match(expression, protocol, host_port) {
                found_dport = true;
            }
            if let Some(dnat) = expression.get("dnat")
                && !dnat.is_null()
                && dnat["addr"].as_str() == Some(vm_ip)
                && dnat
                    .get("port")
                    .and_then(as_int)
                    .is_some_and(|port| port == i64::from(vm_port))
            {
                found_dnat = true;
            }
        }
        if found_dport && found_dnat {
            return true;
        }
    }
    false
}

/// Python `check_nftables_redirections`: any rule matching on dport == port
/// or DNAT-ing to it. Python compares without int coercion here (a numeric
/// string would not match); mirrored.
pub fn check_nftables_redirections(ruleset: &[Value], port: u32) -> bool {
    let port = Value::from(port);
    for entry in ruleset {
        let Some(rule) = entry.get("rule") else {
            continue;
        };
        let expr = rule
            .get("expr")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for expression in &expr {
            if let Some(matched) = match_of(expression)
                && matched["left"]["payload"]["field"].as_str() == Some("dport")
                && matched.get("right") == Some(&port)
            {
                return true;
            }
            if let Some(dnat) = expression.get("dnat")
                && dnat.get("port") == Some(&port)
            {
                return true;
            }
        }
    }
    false
}

// ── Apply layer ─────────────────────────────────────────────────────────

/// Where rulesets come from and command batches go: `nft -j` in production,
/// a canned ruleset in tests. Both methods are blocking; callers hop to the
/// blocking pool.
pub trait NftExecutor: Send + Sync {
    /// The parsed entries of `nft -j list ruleset <family>` (without the
    /// wrapping `{"nftables": [...]}`).
    fn list_ruleset(&self, family: &str) -> Result<Vec<Value>, NftError>;

    /// Execute one command batch (`{"nftables": commands}`).
    fn run_commands(&self, commands: &[Value]) -> Result<(), NftError>;
}

/// Python `get_existing_nftables_ruleset`: ip and ip6 merged; a failing
/// family contributes nothing (the Python edge returns {} and logs).
pub fn fetch_ruleset(executor: &dyn NftExecutor) -> Vec<Value> {
    let mut combined = Vec::new();
    for family in ["ip", "ip6"] {
        match executor.list_ruleset(family) {
            Ok(entries) => combined.extend(entries),
            Err(error) => {
                tracing::error!(family, %error, "failed to list the nftables ruleset");
            }
        }
    }
    combined
}

/// Run a batch like the Python `execute_json_nft_commands`: empty batches
/// are skipped, failures are logged and swallowed (the Python edge only
/// logs the error and returns the output).
pub fn run_commands_logged(executor: &dyn NftExecutor, commands: &[Value]) {
    if commands.is_empty() {
        return;
    }
    if let Err(error) = executor.run_commands(commands) {
        tracing::error!(
            %error,
            payload = %serde_json::to_string(commands).unwrap_or_default(),
            "failed to apply nftables commands"
        );
    }
}

/// Production executor: the `nft` binary with JSON input/output, the same
/// libnftables dialect the Python `nftables` binding drives in-process.
/// `-s` (stateless) and `-p` (numeric protocol) mirror the binding options
/// firewall.py sets (service and reverse-DNS output are off by default).
pub struct NftCli;

impl NftExecutor for NftCli {
    fn list_ruleset(&self, family: &str) -> Result<Vec<Value>, NftError> {
        let output = Command::new("nft")
            .args(["-j", "-s", "-p", "list", "ruleset", family])
            .output()
            .map_err(|source| NftError::Run { source })?;
        if !output.status.success() {
            return Err(NftError::ListFailed {
                family: family.to_string(),
                status: output.status,
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            });
        }
        let parsed: Value = serde_json::from_slice(&output.stdout)
            .map_err(|source| NftError::InvalidJson { source })?;
        Ok(parsed
            .get("nftables")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default())
    }

    fn run_commands(&self, commands: &[Value]) -> Result<(), NftError> {
        let payload = serde_json::to_vec(&json!({"nftables": commands}))
            .map_err(|source| NftError::Serialize { source })?;
        let mut child = Command::new("nft")
            .args(["-j", "-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| NftError::Run { source })?;
        child
            .stdin
            .take()
            .expect("stdin was requested piped")
            .write_all(&payload)
            .map_err(|source| NftError::StdinWrite { source })?;
        let output = child
            .wait_with_output()
            .map_err(|source| NftError::Wait { source })?;
        if !output.status.success() {
            return Err(NftError::ApplyFailed {
                status: output.status,
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            });
        }
        Ok(())
    }
}

/// Test executor: a frozen ruleset, recorded command batches, an optional
/// shared event log interleaving nft batches with the other fakes' calls.
#[derive(Default)]
pub struct StaticRuleset {
    pub entries: Vec<Value>,
    pub batches: std::sync::Mutex<Vec<Vec<Value>>>,
    event_log: std::sync::OnceLock<crate::test_fixtures::EventLog>,
    fail_matching: std::sync::Mutex<Option<String>>,
}

impl StaticRuleset {
    pub fn new(entries: Vec<Value>) -> Self {
        Self {
            entries,
            batches: std::sync::Mutex::new(Vec::new()),
            event_log: std::sync::OnceLock::new(),
            fail_matching: std::sync::Mutex::new(None),
        }
    }

    /// Attach a shared chronological event log.
    pub fn set_event_log(&self, log: crate::test_fixtures::EventLog) {
        let _ = self.event_log.set(log);
    }

    /// Failure injection: every run_commands whose serialized batch
    /// contains `needle` errors instead of recording.
    pub fn fail_batches_containing(&self, needle: &str) {
        *self
            .fail_matching
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(needle.to_string());
    }
}

impl NftExecutor for StaticRuleset {
    fn list_ruleset(&self, family: &str) -> Result<Vec<Value>, NftError> {
        Ok(self
            .entries
            .iter()
            .filter(|entry| {
                entry.as_object().is_some_and(|object| {
                    object
                        .values()
                        .next()
                        .and_then(|value| value.get("family"))
                        .and_then(Value::as_str)
                        == Some(family)
                })
            })
            .cloned()
            .collect())
    }

    fn run_commands(&self, commands: &[Value]) -> Result<(), NftError> {
        if let Some(log) = self.event_log.get() {
            log.record(&format!(
                "nft: batch {}",
                serde_json::to_string(commands).unwrap_or_default()
            ));
        }
        if let Some(needle) = self
            .fail_matching
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_deref()
            && serde_json::to_string(commands)
                .unwrap_or_default()
                .contains(needle)
        {
            return Err(NftError::Injected {
                needle: needle.to_string(),
            });
        }
        self.batches
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(commands.to_vec());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures;

    fn fixture() -> Value {
        let path = test_fixtures::fixtures_dir().join("nftables.json");
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
    }

    fn ruleset(fixture: &Value, name: &str) -> Vec<Value> {
        fixture["rulesets"][name].as_array().unwrap().clone()
    }

    /// Replay every captured firewall.py scenario: same input ruleset, same
    /// command batches. The fixture is the oracle (generated by
    /// scripts/generate_rust_fixtures.py from the actual Python module).
    #[test]
    fn scenarios_replay_the_python_firewall_byte_for_byte() {
        let fixture = fixture();
        let interface = fixture["network_interface"].as_str().unwrap();
        let prefix = fixture["chain_prefix"].as_str().unwrap();

        let scenarios = fixture["scenarios"].as_object().unwrap();
        assert_eq!(scenarios.len(), 12, "update this test with new scenarios");
        for (name, scenario) in scenarios {
            if name == "recreate-redirects-both-protocols" {
                // Captured through VmExecution.recreate_port_redirect_rules,
                // not a bare firewall.py call; replayed by the lifecycle test
                // recreate_redirects_replay_the_python_both_protocols_batch.
                continue;
            }
            let input = ruleset(&fixture, scenario["ruleset"].as_str().unwrap());
            let expected = scenario["batches"].as_array().unwrap().clone();
            let batches: Vec<Vec<Value>> = match name.as_str() {
                "initialize-empty" | "initialize-bare-host" | "initialize-typical" => vec![
                    initialize_ipv4_commands(&input, prefix).unwrap(),
                    initialize_ipv6_commands(&input, prefix),
                ],
                "initialize-empty-no-ipv6" => {
                    vec![initialize_ipv4_commands(&input, prefix).unwrap()]
                }
                "setup-vm-new" => {
                    vec![setup_vm_commands(&input, 4, "vmtap4", interface, prefix, true).unwrap()]
                }
                "setup-vm-existing" => {
                    vec![setup_vm_commands(&input, 3, "vmtap3", interface, prefix, true).unwrap()]
                }
                "add-redirect-new" => vec![
                    add_port_redirect_commands(
                        &input,
                        3,
                        "172.16.3.2",
                        24010,
                        8080,
                        "udp",
                        interface,
                        prefix,
                    )
                    .unwrap(),
                ],
                "add-redirect-existing" => vec![
                    add_port_redirect_commands(
                        &input,
                        3,
                        "172.16.3.2",
                        24000,
                        22,
                        "tcp",
                        interface,
                        prefix,
                    )
                    .unwrap(),
                ],
                "remove-redirect" => vec![
                    remove_port_redirect_commands(
                        &input,
                        "vmtap3",
                        "172.16.3.2",
                        24000,
                        22,
                        "tcp",
                        interface,
                        prefix,
                    )
                    .unwrap(),
                ],
                "teardown-vm" => vec![
                    remove_chain_commands(&input, &format!("{prefix}-vm-nat-3")),
                    remove_chain_commands(&input, &format!("{prefix}-vm-filter-3")),
                ],
                "remove-all-aleph-chains" => get_all_aleph_chains(&input, prefix)
                    .iter()
                    .map(|chain| remove_chain_commands(&input, chain))
                    .collect(),
                other => panic!("unknown fixture scenario {other:?}"),
            };
            let batches: Vec<Value> = batches.into_iter().map(Value::from).collect();
            assert_eq!(
                Value::from(batches),
                Value::from(expected),
                "scenario {name} diverged from the Python capture"
            );
        }
    }

    #[test]
    fn predicates_agree_with_the_python_firewall() {
        let fixture = fixture();
        let prefix = fixture["chain_prefix"].as_str().unwrap();
        let typical = ruleset(&fixture, "typical");

        for (name, expectations) in fixture["predicates"]["table-for-hook"].as_object().unwrap() {
            let input = ruleset(&fixture, name);
            for (key, expected) in expectations.as_object().unwrap() {
                let (hook, family) = key.split_once('/').unwrap();
                assert_eq!(
                    get_table_for_hook(&input, hook, family).unwrap(),
                    expected.as_str().unwrap(),
                    "table-for-hook {name} {key}"
                );
            }
        }

        for case in fixture["predicates"]["port-redirect-exists"]
            .as_array()
            .unwrap()
        {
            let args = case["args"].as_array().unwrap();
            assert_eq!(
                check_port_redirect_exists(
                    &typical,
                    args[0].as_u64().unwrap() as u32,
                    args[1].as_str().unwrap(),
                    args[2].as_u64().unwrap() as u32,
                    args[3].as_str().unwrap(),
                    prefix,
                ),
                case["expected"].as_bool().unwrap(),
                "port-redirect-exists {args:?}"
            );
        }

        for case in fixture["predicates"]["nftables-redirections"]
            .as_array()
            .unwrap()
        {
            assert_eq!(
                check_nftables_redirections(&typical, case["port"].as_u64().unwrap() as u32),
                case["expected"].as_bool().unwrap(),
                "nftables-redirections {}",
                case["port"]
            );
        }

        assert_eq!(
            Value::from(get_all_aleph_chains(&typical, prefix)),
            fixture["predicates"]["all-aleph-chains"]
        );
    }

    #[test]
    fn a_missing_base_chain_is_the_python_no_base_chain_error() {
        let error = get_table_for_hook(&[], "postrouting", "ip").unwrap_err();
        assert_eq!(
            error.to_string(),
            "Could not find any base chain for hook 'postrouting'"
        );
    }

    #[test]
    fn the_static_executor_filters_by_family_like_the_per_family_fetch() {
        let fixture = fixture();
        let executor = StaticRuleset::new(ruleset(&fixture, "typical"));
        let ip = executor.list_ruleset("ip").unwrap();
        let ip6 = executor.list_ruleset("ip6").unwrap();
        assert!(!ip.is_empty() && !ip6.is_empty());
        assert_eq!(
            ip.len() + ip6.len(),
            executor.entries.len(),
            "every fixture entry carries a family"
        );
        // fetch_ruleset merges the families back in order.
        assert_eq!(fetch_ruleset(&executor).len(), executor.entries.len());
    }

    #[test]
    fn fail_batches_containing_injects_a_typed_error() {
        let executor = StaticRuleset::new(Vec::new());
        executor.fail_batches_containing("supervisor-nat");
        let error = executor
            .run_commands(&[json!({"add": {"chain": {"name": "aleph-supervisor-nat"}}})])
            .unwrap_err();
        assert!(matches!(error, NftError::Injected { .. }));
        assert_eq!(
            error.to_string(),
            "injected nft failure (matched \"supervisor-nat\")"
        );
    }

    #[test]
    fn is_superset_mirrors_the_python_helper() {
        let listed = json!({"family": "ip", "table": "nat", "name": "x", "handle": 4});
        assert!(is_superset(&json!({"family": "ip", "name": "x"}), &listed));
        assert!(!is_superset(
            &json!({"family": "ip6", "name": "x"}),
            &listed
        ));
        // Lists compare pairwise with equal length.
        assert!(is_superset(&json!([1, 2]), &json!([1, 2])));
        assert!(!is_superset(&json!([1]), &json!([1, 2])));
    }
}
