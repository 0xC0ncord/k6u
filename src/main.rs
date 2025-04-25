use anyhow::{Context, Result, anyhow};
use futures::stream::StreamExt;
use k8s_openapi::api::core::v1::Node;
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use kube::{
    Client,
    api::{Api, ListParams, Patch, PatchParams, ResourceExt},
    core::{ApiResource, CustomResourceExt, DynamicObject, GroupVersionKind},
    runtime::wait::{await_condition, conditions},
};
use kube_leader_election::{LeaseLock, LeaseLockParams};
use rand::prelude::*;
use signal_hook::consts::signal::{SIGINT, SIGTERM};
use signal_hook_tokio::Signals;
use std::collections::{BTreeMap, HashSet};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

mod crds;
use crate::crds::{
    ConditionStatus, IP6UpdateCondition, IP6UpdateConfig, IP6UpdateNodeConfig, IP6UpdateStatus,
};
mod ip6;

const DEFAULT_UPDATE_INTERVAL_SECONDS: u64 = 10;

const CRD_UPDATE_TIMEOUT: u64 = 10;
const SUBPREFIX_SIZE: u8 = 64;
const CONDITION_TYPES_KEEP_HISTORY: usize = 3;

#[tokio::main]
async fn main() {
    unsafe {
        std::env::set_var(
            "RUST_LOG",
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()),
        );
    }
    env_logger::init();

    if let Err(e) = run().await {
        log::error!("Error: {e}");
        std::process::exit(1);
    }
}

async fn handle_signals(shutdown_notify: Arc<tokio::sync::Notify>) {
    let mut signals = Signals::new([SIGINT, SIGTERM]).unwrap();
    while let Some(signal) = signals.next().await {
        log::info!("Signal {signal} received, notifying shutdown.");
        shutdown_notify.notify_waiters();
    }
}

async fn update_crds(client: Client) -> Result<()> {
    log::info!("Updating custom resource definitions...");

    let crds: Api<CustomResourceDefinition> = Api::all(client);

    crds.patch(
        "ip6updateconfigs.apps.fuwafuwatime.moe",
        &PatchParams::apply("update_crds"),
        &Patch::Apply(IP6UpdateConfig::crd()),
    )
    .await?;
    tokio::time::timeout(
        std::time::Duration::from_secs(CRD_UPDATE_TIMEOUT),
        await_condition(
            crds.clone(),
            "ip6updateconfigs.apps.fuwafuwatime.moe",
            conditions::is_crd_established(),
        ),
    )
    .await?
    .expect("Failed to update IP6UpdateConfig custom resource definition!");

    crds.patch(
        "ip6updatenodeconfigs.apps.fuwafuwatime.moe",
        &PatchParams::apply("update_crds"),
        &Patch::Apply(IP6UpdateNodeConfig::crd()),
    )
    .await?;
    tokio::time::timeout(
        std::time::Duration::from_secs(CRD_UPDATE_TIMEOUT),
        await_condition(
            crds,
            "ip6updatenodeconfigs.apps.fuwafuwatime.moe",
            conditions::is_crd_established(),
        ),
    )
    .await?
    .expect("Failed to update IP6UpdateNodeConfig custom resource definition!");

    Ok(())
}

async fn run() -> Result<()> {
    let shutdown_notify = Arc::new(tokio::sync::Notify::new());
    tokio::spawn(handle_signals(shutdown_notify.clone()));

    // Grab required values from env vars.
    let node_name = std::env::var("NODE_NAME").context("No NODE_NAME set, cannot continue!")?;
    let update_interval: u64 = std::env::var("UPDATE_INTERVAL")
        .unwrap_or(DEFAULT_UPDATE_INTERVAL_SECONDS.to_string())
        .parse()
        .context("UPDATE_INTERVAL conversion to u64 failed.")?;

    let client = Client::try_default().await?;

    // Creade a lease lock so we aren't racing to update CIDR groups.
    let is_leader: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    let leadership = LeaseLock::new(
        client.clone(),
        &std::env::var("POD_NAMESPACE").unwrap_or_else(|_| "kube-system".to_string()),
        LeaseLockParams {
            holder_id: std::env::var("POD_NAME").unwrap_or(format!(
                "k6u-random-{}",
                rand::rng()
                    .sample_iter(rand::distr::Alphanumeric)
                    .take(7)
                    .map(char::from)
                    .collect::<String>()
                    .to_lowercase()
            )),
            lease_name: "k6u-lease".to_string(),
            lease_ttl: std::time::Duration::from_secs(15),
        },
    );

    // First try and update CRDs.
    update_crds(client.clone()).await?;

    let config_api: Api<IP6UpdateConfig> = Api::all(client.clone());

    // Grab this node's labels for finding the config for it.
    let node_api: Api<Node> = Api::all(client.clone());
    let node = node_api.get(&node_name).await?;
    let node_labels = node.metadata.labels.unwrap_or_default();

    // Build a dynamic object to reference the CiliumCIDRGroups.
    let gvk = GroupVersionKind::gvk("cilium.io", "v2alpha1", "CiliumCIDRGroup");
    let resource = ApiResource::from_gvk_with_plural(&gvk, "ciliumcidrgroups");
    let cidr_api: Api<DynamicObject> = Api::all_with(client.clone(), &resource);

    // This is our main update task.
    let try_update = async || -> Result<()> {
        // Find all IP6UpdateConfigs, give up if not only one.
        let update_configs = config_api.list(&ListParams::default()).await?;
        if update_configs.items.len() > 1 {
            return Err(anyhow!(
                "More than one IP6UpdateConfig found, cannot continue!"
            ));
        } else if update_configs.items.is_empty() {
            return Err(anyhow!("No IP6UpdateConfigs found."));
        }
        let config = update_configs.items.first().unwrap();

        // Now find our node config, and get the delegated prefix combining these configs.
        let node_config = get_node_config(&client, &node_labels).await?;
        let delegated_prefix = ip6::get_global_ipv6_prefix_from_interface(
            &node_config.spec.interface,
            config.spec.delegated_prefix_length,
        )?;

        // Get all of the CiliumCIDRGroups we need to update, making sure we aren't targeting
        // any duplicates.
        let groups = &config.spec.get_validated_mapped_groups()?;

        for (group, prefixes) in groups {
            // Get the prefixes for this group.
            let new_prefixes: HashSet<String> = prefixes
                .iter()
                .map(|p| {
                    format!(
                        "{}/{}",
                        std::net::Ipv6Addr::from_bits(
                            delegated_prefix.to_bits() + (1u128 << SUBPREFIX_SIZE) * (*p as u128)
                        ),
                        SUBPREFIX_SIZE
                    )
                })
                .collect();

            log::debug!("Identified CIDRs to apply: {:?}", new_prefixes);

            // Get existing CIDRs in the CiliumCIDRGroup.
            let cidr_group = cidr_api.get(group).await?;
            let existing_cidrs: HashSet<String> = cidr_group
                .data
                .get("spec")
                .unwrap()
                .get("externalCIDRs")
                .unwrap()
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap();

            log::debug!("Existing CIDRs to possibly overwrite: {:?}", existing_cidrs);

            if existing_cidrs == new_prefixes {
                // No need to update.
                continue;
            } else {
                let patch = Patch::Merge(serde_json::json!({
                    "spec": {
                        "externalCIDRs": new_prefixes
                    }
                }));

                log::debug!("Patching CiliumCIDRGroup {}", group);

                // Patch it and update the status accordingly.
                let status: IP6UpdateCondition = match cidr_api
                    .patch(&cidr_group.name_any(), &PatchParams::default(), &patch)
                    .await
                {
                    Ok(_) => {
                        log::info!("Patching CiliumCIDRGroup {group} completed successfully.");
                        IP6UpdateCondition {
                            last_transition_time: Time(chrono::Utc::now()),
                            message: format!(
                                "Updated IPv6 address in {} from {:?} to {:?}",
                                group, existing_cidrs, new_prefixes,
                            ),
                            reason: "UpdateSucceeded".to_string(),
                            status: ConditionStatus::True,
                            type_: "Ready".to_string(),
                        }
                    }
                    Err(e) => {
                        log::info!("Failed to patch CiliumCIDRGroup {group}.");
                        IP6UpdateCondition {
                            last_transition_time: Time(chrono::Utc::now()),
                            message: format!(
                                "Failed to update IPv6 address in {} from {:?} to {:?}: {}",
                                group, existing_cidrs, new_prefixes, e,
                            ),
                            reason: "UpdateFailed".to_string(),
                            status: ConditionStatus::False,
                            type_: "Failed".to_string(),
                        }
                    }
                };

                // Prepare the status by only keeping the last 3 of each condition type, sorted by
                // newest to oldest.
                let ip6_api: Api<IP6UpdateConfig> = Api::all(client.clone());
                let mut object = ip6_api.get_status(&config.name_any()).await?;
                let mut conditions = object
                    .status
                    .as_ref()
                    .map(|s| s.conditions.clone())
                    .unwrap_or_default();
                conditions.push(status);

                let mut grouped: BTreeMap<String, Vec<IP6UpdateCondition>> = BTreeMap::new();
                for cond in conditions {
                    grouped.entry(cond.type_.clone()).or_default().push(cond);
                }

                let mut trimmed: Vec<IP6UpdateCondition> = grouped
                    .into_iter()
                    .flat_map(|(_, mut group)| {
                        group.sort_by(|a, b| b.last_transition_time.cmp(&a.last_transition_time));
                        group.truncate(CONDITION_TYPES_KEEP_HISTORY);
                        group
                    })
                    .collect();

                trimmed.sort_by(|a, b| b.last_transition_time.cmp(&a.last_transition_time));

                object.status = Some(IP6UpdateStatus {
                    conditions: trimmed,
                });

                // Patch the status.
                ip6_api
                    .replace_status(
                        &config.name_any(),
                        &Default::default(),
                        serde_json::to_vec(&object)?,
                    )
                    .await?;
            }
        }

        Ok(())
    };

    loop {
        tokio::select! {
            // Shut down if we received a signal.
            _ = shutdown_notify.notified() => {
                log::info!("Shutting down.");
                leadership.step_down().await?;
                break;
            },
            // The main loop.
            _ = tokio::time::sleep(std::time::Duration::from_secs(update_interval)) => {
                match leadership.try_acquire_or_renew().await {
                    Ok(ll) => {
                        // We are the leader, try and update.
                        is_leader.store(ll.acquired_lease, Ordering::Relaxed);
                        if is_leader.load(Ordering::Relaxed) {
                            if let Err(e) = try_update().await {
                                log::error!("{}", e);
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("{:?}", e);
                    }
                }
            },
        }
    }

    Ok(())
}

async fn get_node_config(
    client: &Client,
    node_labels: &BTreeMap<String, String>,
) -> Result<IP6UpdateNodeConfig> {
    let api: Api<IP6UpdateNodeConfig> = Api::all(client.clone());
    let list = api.list(&ListParams::default()).await?;
    let matched_configs: Vec<_> = list
        .into_iter()
        .filter(|cr| {
            cr.spec
                .node_selector
                .iter()
                .all(|(k, v)| node_labels.get(k) == Some(v))
        })
        .collect();

    if matched_configs.is_empty() {
        return Err(anyhow!("No configs found for this node."));
    }

    let mut seen = BTreeMap::new();
    let mut duplicates = vec![];
    for config in &matched_configs {
        let key = (config.spec.node_selector.clone(),);
        if let Some(existing) = seen.insert(key.clone(), config.name_any()) {
            duplicates.push((existing, config.name_any()));
        }
    }

    if !duplicates.is_empty() {
        log::error!("Found duplicate IP6UpdateConfigs:");
        for (a, b) in duplicates {
            log::error!(" - Conflict between {} and {}", a, b);
        }
        return Err(anyhow!("Conflicts must be resolved before continuing."));
    }

    Ok(matched_configs.into_iter().next().unwrap())
}
