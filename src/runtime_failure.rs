// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use anyhow::Error;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RuntimeFailureCode {
    UnknownRuntimeFailure,
    NamespaceUnshareFailed,
    UserNamespaceMappingFailed,
    MountPropagationBlocked,
    ResolvConfBindBlocked,
    HostsBindBlocked,
    RootlessBootstrapSyncFailed,
    TapCreateBlocked,
    PacketCaptureBlocked,
    RuntimeShutdownFailed,
}

impl RuntimeFailureCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnknownRuntimeFailure => "unknown_runtime_failure",
            Self::NamespaceUnshareFailed => "namespace_unshare_failed",
            Self::UserNamespaceMappingFailed => "user_namespace_mapping_failed",
            Self::MountPropagationBlocked => "mount_propagation_blocked",
            Self::ResolvConfBindBlocked => "resolv_conf_bind_blocked",
            Self::HostsBindBlocked => "hosts_bind_blocked",
            Self::RootlessBootstrapSyncFailed => "rootless_bootstrap_sync_failed",
            Self::TapCreateBlocked => "tap_create_blocked",
            Self::PacketCaptureBlocked => "packet_capture_blocked",
            Self::RuntimeShutdownFailed => "runtime_shutdown_failed",
        }
    }
}

pub fn classify_error(err: &Error) -> Option<RuntimeFailureCode> {
    for cause in err.chain() {
        if let Some(code) = classify_text(&cause.to_string()) {
            return Some(code);
        }
    }

    classify_text(&format!("{err:#}"))
}

fn classify_text(text: &str) -> Option<RuntimeFailureCode> {
    if text.contains("failed to make mount propagation private") {
        return Some(RuntimeFailureCode::MountPropagationBlocked);
    }
    if text.contains("failed to bind-mount") && text.contains("/etc/resolv.conf") {
        return Some(RuntimeFailureCode::ResolvConfBindBlocked);
    }
    if text.contains("failed to bind-mount") && text.contains("/etc/hosts") {
        return Some(RuntimeFailureCode::HostsBindBlocked);
    }
    if text.contains("failed to create tap device") || text.contains("using TUNSETIFF") {
        return Some(RuntimeFailureCode::TapCreateBlocked);
    }
    if text.contains("failed to open AF_PACKET channel")
        || text.contains("failed to start packet capture")
    {
        return Some(RuntimeFailureCode::PacketCaptureBlocked);
    }
    if text.contains("failed to configure the child user namespace")
        || text.contains("could not map the current non-root user into the `rootless-internal` child namespace")
    {
        return Some(RuntimeFailureCode::UserNamespaceMappingFailed);
    }
    if text.contains("unshare for the `rootless-internal` backend failed")
        || text.contains("unshare(CLONE_NEWNET|CLONE_NEWNS) failed")
    {
        return Some(RuntimeFailureCode::NamespaceUnshareFailed);
    }
    if text.contains("failed to wait for the child to finish rootless tap bootstrap")
        || text.contains("failed to wait for the child to finish unsharing the rootless user namespace")
        || text.contains("failed while waiting for the parent to finish starting the rootless userspace networking engine")
    {
        return Some(RuntimeFailureCode::RootlessBootstrapSyncFailed);
    }
    if text.contains("one or more runtime components failed during shutdown") {
        return Some(RuntimeFailureCode::RuntimeShutdownFailed);
    }

    None
}

pub fn classify_or_unknown(err: &Error) -> RuntimeFailureCode {
    classify_error(err).unwrap_or(RuntimeFailureCode::UnknownRuntimeFailure)
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;

    use super::{classify_error, RuntimeFailureCode};

    #[test]
    fn classify_error_detects_tap_creation_failures() {
        let err = anyhow!(
            "failed to create tap device `tap0` inside the rootless-internal child namespace using TUNSETIFF"
        );
        assert_eq!(
            classify_error(&err),
            Some(RuntimeFailureCode::TapCreateBlocked)
        );
    }

    #[test]
    fn classify_error_detects_resolv_conf_bind_failures() {
        let err = anyhow!("failed to bind-mount /tmp/resolv.conf over /etc/resolv.conf");
        assert_eq!(
            classify_error(&err),
            Some(RuntimeFailureCode::ResolvConfBindBlocked)
        );
    }

    #[test]
    fn classify_error_detects_af_packet_failures_through_context() {
        let err = anyhow!("failed to start packet capture")
            .context("failed to open AF_PACKET channel on tap0");
        assert_eq!(
            classify_error(&err),
            Some(RuntimeFailureCode::PacketCaptureBlocked)
        );
    }

    #[test]
    fn runtime_failure_codes_use_stable_strings() {
        assert_eq!(
            RuntimeFailureCode::UnknownRuntimeFailure.as_str(),
            "unknown_runtime_failure"
        );
        assert_eq!(
            RuntimeFailureCode::UserNamespaceMappingFailed.as_str(),
            "user_namespace_mapping_failed"
        );
        assert_eq!(
            RuntimeFailureCode::RuntimeShutdownFailed.as_str(),
            "runtime_shutdown_failed"
        );
    }
}
