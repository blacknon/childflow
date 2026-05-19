// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

pub mod addr;
mod bootstrap;
pub mod engine;
mod icmp;
pub mod packet;
pub mod route;
mod routes;
mod setup;
pub mod state;
pub mod tap;
mod transport;

use crate::capture::CapturePlan;

pub use self::bootstrap::ChildBootstrap;
pub use self::setup::{setup, RootlessSetupParams};

pub struct NetworkContext {
    engine: engine::EngineHandle,
    capture_plan: Option<CapturePlan>,
}

impl NetworkContext {
    pub fn shutdown(self) -> anyhow::Result<()> {
        self.engine.shutdown()
    }

    pub fn leak_detected(&self) -> bool {
        self.engine.leak_detected()
    }

    pub fn capture_plan(&self) -> Option<CapturePlan> {
        self.capture_plan.clone()
    }
}
