// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OpenShift SCC and least-privilege checks.

use serde_json::Value; // used for dynamic json parsing of K8s API resources
use std::collections::BTreeSet; // provides sorted, unique set operations for capabilities and event UIDs

use openshell_e2e::harness::sandbox::SandboxGuard;
use crate::common::{gateway_namespace, oc_json, release, sandbox_namespace};

const PRIVILEGED_SCC_ROLE: &str = "system:openshift:scc:privileged"; // consts define the RBAC role for privileged access & whitelist of allowed gateway SCCs
const ALLOWED_GATEWAY_SCCS: &[&str] = &["restricted-v2"];

#[tokio::test]
async fn test_gateway_pods_use_restricted_scc() { // verifies that all running gateway pods are constrained to restricted or nonroot-v2 SCCs
    let namespace = gateway_namespace();
    let release_name = release();
    let selector = format!("app.kubernetes.io/instance={release_name}"); // constructs a label selector for deployment instance

    let pods = oc_json(&[
        "get", "pods", "-n", &namespace, "-l", &selector, "-o", "json",
    ])
    .await; // async fetches matching pods in JSON format

    let items = pods["items"] // extracts the items array from K8s PodList json
        .as_array()
        .expect("oc get pods should return an items array"); 

    assert!(
        !items.is_empty(), // fails early if no pods match the selector
        "no gateway pods found with selector {selector:?} in namespace {namespace:?}"
    );

    let mut errors = Vec::new();

    for pod in items {
        let name = pod["metadata"]["name"].as_str().unwrap_or("<unknown>");

        let scc = pod
            .pointer("/metadata/annotations/openshift.io~1scc") // ~1 = escaped forward slash inside JSON key
            .and_then(Value::as_str); // extracts pod.metadata.annotations["openshift.io/scc"]

        match scc {
            Some(scc) if ALLOWED_GATEWAY_SCCS.contains(&scc) => {}
            Some(scc) => errors.push(format!(
                "{name}: SCC {scc:?}; expected one of {ALLOWED_GATEWAY_SCCS:?}"
            )),
            None => errors.push(format!("{name}: missing openshift.io/scc annotation")), // validates that assigned SCC matches allowed list, unmatched/missing annotations append errors to 'errors'
        }
    }

    assert!(
        errors.is_empty(),
        "gateway SCC check failed:\n{}",
        errors.join("\n")
    )
}

#[tokio::test]
async fn test_privileged_scc_is_exclusive_to_sandbox_service_account() { // audits cluster RBAC to ensure system:openshift:scc:privileged is granted only to the dedicated sandbox SA within designated namespace
    let sandbox_namespace = sandbox_namespace();
    let sandbox_sa = format!("{}-sandbox", release());
    let mut errors = Vec::new();
    let mut sandbox_binding_found = false;

    let bindings = oc_json(&["get", "rolebindings", "-A", "-o", "json"]).await; // -A = all namespaces
    let items = bindings["items"]
        .as_array()
        .expect("rolebindings response should have items");

    for binding in items {
        if binding["roleRef"]["name"].as_str() != Some(PRIVILEGED_SCC_ROLE) {
            continue;
        } // filters out any RoleBinding that doesnt ref privileged SCC role

        let binding_namespace = binding["metadata"]["namespace"]
            .as_str()
            .unwrap_or("<missing>");
        let binding_name = binding["metadata"]["name"].as_str().unwrap_or("<unknown>");

        let subjects = binding["subjects"].as_array().cloned().unwrap_or_default();
        let subject = subjects.first();
        let subject_namespace = subject
            .and_then(|subject| subject["namespace"].as_str())
            .unwrap_or(binding_namespace);

        let valid = binding_namespace == sandbox_namespace.as_str()
            && subjects.len() == 1
            && subject.and_then(|subject| subject["kind"].as_str()) == Some("ServiceAccount")
            && subject.and_then(|subject| subject["name"].as_str()) == Some(sandbox_sa.as_str())
            && subject_namespace == sandbox_namespace.as_str(); // strict ownership criteria: fails if binding on wrong namespace, multiple subjects, non-SAs or targets unexpected account name

        if valid {
            sandbox_binding_found = true;
        } else {
            errors.push(format!(
                "RoleBinding {binding_namespace}/{binding_name} grants {PRIVILEGED_SCC_ROLE:?} to unexpected subjects: {subjects:?}"
            ));
        }
    }

    if !sandbox_binding_found {
        errors.push(format!(
            "no RoleBinding grants {PRIVILEGED_SCC_ROLE:?} exclusively to ServiceAccount {sandbox_namespace}/{sandbox_sa}"
        ));
    }

    let cluster_bindings = oc_json(&["get", "clusterrolebindings", "-o", "json"]).await; // checks ClusterRoleBindings
    let items = cluster_bindings["items"]
        .as_array()
        .expect("clusterrolebindings response should have items");

    for cluster_binding in items {
        if cluster_binding["roleRef"]["name"].as_str() == Some(PRIVILEGED_SCC_ROLE) {
            let name = cluster_binding["metadata"]["name"]
                .as_str()
                .unwrap_or("<unknown>");
            let subjects = cluster_binding["subjects"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            errors.push(format!(
                "ClusterRoleBinding {name} grants {PRIVILEGED_SCC_ROLE:?} cluster-wide to subjects: {subjects:?}" // if any CRB grants PRIVILEGED_SCC_ROLE, it flags an error immediately
            ));
        }
    }

    assert!(
        errors.is_empty(),
        "privileged SCC binding check failed:\n{}",
        errors.join("\n")
    );

}

#[tokio::test]
async fn test_supervisor_capabilities_are_minimal() { // spawns temporary sandbox environment using SandboxGuard to verify container-level security settings.
    let namespace = sandbox_namespace();
    let mut sb = SandboxGuard::create(&["--", "sh", "-c", "sleep 1 && echo odh-smoke-ok"]) // spawns ephemeral sandbox container
        .await
        .expect("sandbox create should succeed");

    let sandbox_selector = format!("openshell.ai/sandbox-name={}", sb.name);
    let sandbox_crs = oc_json(&[
        "get",
        "sandboxes.agents.x-k8s.io",
        "-n",
        &namespace,
        "-l",
        &sandbox_selector,
        "-o",
        "json",
    ])
    .await;

    let pod_selector = sandbox_crs
        .get("items")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(|cr| cr["status"]["selector"].as_str())
        .map(str::to_string); // navigates sandbox CR status block to extract target pod label selector

    let Some(pod_selector) = pod_selector else {
        sb.cleanup().await;
        panic!("Sandbox CR did not report a pod selector");
    };

    let pods = oc_json(&[
        "get",
        "pods",
        "-n",
        &namespace,
        "-l",
        &pod_selector,
        "-o",
        "json",
    ])
    .await;

    let expected: BTreeSet<&str> = ["NET_ADMIN", "SYS_ADMIN"].into_iter().collect();
    let mut errors = Vec::new();

    let items = pods["items"]
        .as_array()
        .expect("sandbox pod response should have an items array");
    if items.is_empty() {
        errors.push(format!(
            "no sandbox pods found with selector {pod_selector:?}"
        ));
    }

    for pod in items {
        let pod_name = pod["metadata"]["name"].as_str().unwrap_or("<unknown>");
        let containers = pod["spec"]["containers"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let supervisor = containers.iter().find(|container| {
            ["command", "args"].iter().any(|key| {
                container[*key].as_array().is_some_and(|values| {
                    values
                        .iter()
                        .filter_map(Value::as_str)
                        .any(|value| value.contains("openshell-sandbox")) // identifies the specific supervisor container by scanning command & args arrays for openshell-sandbox
                })
            })
        });

        let Some(supervisor) = supervisor else {
            errors.push(format!(
                "{pod_name}: no container command or args mention openshell-sandbox; cannot identify the supervisor"
            ));
            continue;
        };

        let container_name = supervisor["name"].as_str().unwrap_or("<unknown");
        if supervisor["securityContext"]["privileged"].as_bool() == Some(true) {
            errors.push(format!(
                "{pod_name}/{container_name}: privileged must not be true" // asserts privileged flag explicitly disabled
            ));
        }
        if supervisor["securityContext"]["allowPrivilegeEscalation"].as_bool() == Some(true) {
            errors.push(format!(
                "{pod_name}/{container_name}: allowPrivilegeEscalation must not be true" // asserts that allowPrivilegeEscalation flag explicitly disabled
            ));
        }

        let actual: BTreeSet<&str> = supervisor["securityContext"]["capabilities"]["add"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect(); // collects added Linux capabilities into a BTreeSet and enforces that it matches ["NET_ADMIN", "SYS_ADMIN"] exactly
        if actual != expected {
            errors.push(format!(
                "{pod_name}/{container_name}: added capabilities {actual:?}; expected exactly {expected:?}"
            ));
        }
    }

    sb.cleanup().await;

    assert!(
        errors.is_empty(),
        "supervisor capability check failed:\n{}",
        errors.join("\n")
    );
}

#[tokio::test]
async fn test_no_new_scc_warnings() { // captures a baseline of cluster events before sandbox creation and verifies no new SCC-related warning events occur during deployment
    let namespaces: BTreeSet<String> = [gateway_namespace(), sandbox_namespace()]
        .into_iter()
        .collect();
    let mut existing_event_uids = BTreeSet::new(); // records baseline Warning events across target namespaces to ignore legaxy cluster warnings.

    for namespace in &namespaces {
        let events = oc_json(&["get", "events", "-n", namespace, "-o", "json"]).await;
        for event in events["items"].as_array().into_iter().flatten() {
            if let Some(uid) = event["metadata"]["uid"].as_str() {
                existing_event_uids.insert(format!("{namespace}/{uid}"));
            }
        }
    }

    let mut sb = SandboxGuard::Create(&["--", "sh", "-c", "sleep 1 && echo scc-events-ok"])
        .await
        .expect("sandbox create should succeed without SCC escalation warnings");

    let mut errors = Vec::new();
    for namespace in &namespaces {
        let events = oc_json(&["get", "events", "-n", namespace, "-o", "json"]).await;
        for event in events["items"].as_array().into_iter().flatten() {
            continue;
        };
        if existing_event_uids.contains(&format!("{namespace}/{uid}")) {
            continue;
        }
        if event["type"].as_str() != Some("Warning") {
            continue;
        }

        let reason = event["reason"].as_str().unwrap_or("");
        let message = event["message"].as_str().unwrap_or("");
        let text = format!("{reason} {message}").to_lowercase();
        let is_scc_warning = text.contains("securitycontextconstraint")
            || text.contains("security context constrain")
            || text.contains("scc"); // filters new warning events for SCC privilege rejection or escalation keywords

        if is_scc_warning {
            let name = event["metadata"]["name"].as_str().unwrap_or("<unknown>");
            errors.push(format!(
                "{namespace}/{name}: reason={reason:?}, message={message:?}"
            ));
        }
    }

    sb.cleanup().await;

    assert!(
        errors.is_empty(),
        "new SCC-related Warning events found during sandbox creation:\n{}",
        errors.join("\n")
    );
}