// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

mod forwarder;
mod plan;

#[cfg(test)]
mod tests;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use anyhow::Result;

use crate::network::NetworkBackend;

pub struct DnsPlan {
    resolv_guard: Option<plan::TempFileGuard>,
    rootful_upstream: Option<IpAddr>,
    rootless_upstream: Option<IpAddr>,
    resolv_conf_required: bool,
}

impl DnsPlan {
    pub fn prepare(
        run_id: &str,
        backend: NetworkBackend,
        dns: Option<IpAddr>,
        inherited_dns_ipv4: Ipv4Addr,
        inherited_dns_ipv6: Ipv6Addr,
    ) -> Result<Self> {
        match backend {
            NetworkBackend::Rootful => {
                plan::prepare_rootful_dns_plan(run_id, dns, inherited_dns_ipv4, inherited_dns_ipv6)
            }
            NetworkBackend::RootlessInternal => {
                plan::prepare_rootless_dns_plan(run_id, dns, inherited_dns_ipv4, inherited_dns_ipv6)
            }
        }
    }

    pub fn resolv_conf_path(&self) -> Option<&Path> {
        self.resolv_guard.as_ref().map(|guard| guard.path.as_path())
    }

    pub fn start_forwarder(
        &self,
        bind_ipv4: Ipv4Addr,
        bind_ipv6: Ipv6Addr,
        offline: bool,
    ) -> Result<Option<DnsHandle>> {
        if offline {
            return Ok(None);
        }
        self.rootful_upstream
            .map(|upstream| DnsHandle::start(bind_ipv4, bind_ipv6, upstream))
            .transpose()
    }

    pub fn rootless_upstream(&self) -> Option<IpAddr> {
        self.rootless_upstream
    }

    pub fn resolv_conf_required(&self) -> bool {
        self.resolv_conf_required
    }
}

pub struct DnsHandle {
    stop: Arc<AtomicBool>,
    joins: Vec<JoinHandle<Result<()>>>,
}

impl DnsHandle {
    pub fn start(bind_ipv4: Ipv4Addr, bind_ipv6: Ipv6Addr, upstream_ip: IpAddr) -> Result<Self> {
        forwarder::start(bind_ipv4, bind_ipv6, upstream_ip)
    }

    fn stop_and_join(&mut self) -> Result<()> {
        self.stop.store(true, Ordering::Relaxed);
        let mut failures = Vec::new();
        while let Some(join) = self.joins.pop() {
            match join.join() {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    failures.push(format!("{err:#}"));
                }
                Err(_) => failures.push("DNS forwarder thread panicked".to_string()),
            }
        }
        if failures.is_empty() {
            return Ok(());
        }
        anyhow::bail!(failures.join("\n"));
    }

    pub fn shutdown(mut self) -> Result<()> {
        self.stop_and_join()
    }
}

impl Drop for DnsHandle {
    fn drop(&mut self) {
        if let Err(err) = self.stop_and_join() {
            crate::util::warn(format!("DNS forwarder stopped with an error: {err:#}"));
        }
    }
}
