use anyhow::{Result, anyhow};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "apps.fuwafuwatime.moe",
    version = "v1",
    kind = "IP6UpdateNodeConfig"
)]
#[serde(rename_all = "camelCase")]
pub struct IP6UpdateNodeConfigSpec {
    pub node_selector: BTreeMap<String, String>,
    pub interface: String,
}

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "apps.fuwafuwatime.moe",
    version = "v1",
    kind = "IP6UpdateConfig",
    status = "IP6UpdateStatus"
)]
#[serde(rename_all = "camelCase")]
pub struct IP6UpdateConfigSpec {
    pub delegated_prefix_length: u8,
    #[serde(rename = "ciliumCIDRGroups")]
    pub cidr_groups: Vec<IP6UpdateCIDRGroup>,
}
#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct IP6UpdateCIDRGroup {
    #[serde(rename = "ciliumCIDRGroupName")]
    pub cidr_group_name: String,
    pub prefix_ids: Vec<u8>,
}
#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct IP6UpdateStatus {
    pub conditions: Vec<IP6UpdateCondition>,
}
#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct IP6UpdateCondition {
    #[schemars(with = "String")]
    pub last_transition_time: Time,
    pub message: String,
    pub reason: String,
    pub status: ConditionStatus,
    #[serde(rename = "type")]
    pub type_: String,
}
#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub enum ConditionStatus {
    True,
    False,
    Unknown,
}

impl IP6UpdateConfigSpec {
    pub fn get_validated_mapped_groups(&self) -> Result<BTreeMap<String, Vec<u8>>> {
        let mut map = BTreeMap::new();

        for entry in &self.cidr_groups {
            if map.contains_key(&entry.cidr_group_name) {
                return Err(anyhow!(
                    "Duplicate ciliumCIDRGroupName: {}",
                    entry.cidr_group_name
                ));
            }
            map.insert(entry.cidr_group_name.clone(), entry.prefix_ids.clone());
        }

        Ok(map)
    }
}
