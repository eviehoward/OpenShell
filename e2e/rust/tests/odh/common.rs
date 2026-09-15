use serde_json::Value;

pub(crate) fn gateway_namespace() -> String {
    std::env::var("NAMESPACE").unwrap_or_else(|_| "openshell".to_string())
}

pub(crate) fn sandbox_namespace() -> String {
    std::env::var("SANDBOX_NAMESPACE".unwrap_or_else(|_| gateway_namespace()))
}

pub(crate) fn release() -> String {
    std::env::var("RELEASE").unwrap_or_else(|_| "openshell".to_string())
}

pub(crate) async fn oc_json(args: &[&str]) -> Value {
    let output = tokio::process::Command::new("oc")
        .args(args)
        .output()
        .await
        .expect(
            "failed to run `oc` — required for checks; ensure it is in PATH \
             and KUBECONFIG targets the cluster",
        );
    assert!(
        output.status.success(),
        "oc {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("oc {args:?} did not return valid JSON: {e}"))
}