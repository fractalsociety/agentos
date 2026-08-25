//! # FractalOS SDK
//!
//! Core abstractions for the world's first operating system designed for AI agents.
//!
//! ## Design Philosophy
//!
//! Traditional OS primitives were designed for human-driven processes.
//! FractalOS inverts this: every primitive is designed around what agents actually need.
//!
//! ### Core Abstractions
//!
//! - **Capability**: Unforgeable access token to a resource (seL4 kernel-enforced)
//! - **AgentContext**: An agent's runtime environment (caps, memory, identity)
//! - **Message**: Typed, schema-validated inter-agent communication
//! - **EventChannel**: Pub/sub communication primitive
//! - **VectorRef**: Handle to an embedding in the native VectorStore

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod agent_context;
pub mod capability;
pub mod context;
pub mod cuda;
pub mod daily_root;
pub mod event;

/// Canonical Fractal control-plane surface, generated from
/// `interfaces/wit/fractalos-capabilities-v1/capabilities.wit`.
#[cfg(feature = "wit-bindings")]
pub mod fractal;

#[cfg(feature = "wit-bindings")]
pub mod wit_generated {
    wit_bindgen::generate!({
        path: "../../interfaces/wit/fractalos-capabilities-v1",
        world: "agent-runtime-v1",
        // The WIT world must stay usable from no_std seL4 PDs: gate the
        // generated `std::error::Error` implementations behind this crate's
        // own `std` feature instead of assuming `std` is linked.
        std_feature,
    });
}
pub mod identity;
pub mod memory;
pub mod message;
pub mod net;
pub mod scheduler;
pub mod vector;

// Re-export the most common types
pub use capability::{Capability, CapabilityKind, CapabilitySet};
pub use context::AgentContext;
pub use cuda::{CudaError, CudaKernel, CUDA_SECTION_NAME};
pub use event::{Event, EventChannel, EventKind, Priority};
pub use identity::{AgentId, AgentIdentity};
pub use message::{Message, MessageKind};

/// FractalOS SDK version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// FractalOS kernel interface version this SDK targets
pub const KERNEL_ABI_VERSION: u32 = 1;
