//! Audience-bound RemoteGrant and execution-lease fencing for MeshGateway.
//!
//! Tailnet / discovery identity never authorizes Agent ISA. A grant must bind
//! subject_node to the authenticated peer, audience to the local node, and a
//! CapBroker-derived local badge is minted only after full validation. Remote
//! badges are never trusted.

use sha2::{Digest, Sha512};
use std::collections::HashMap;
use thiserror::Error;

pub const GRANT_SIGNATURE_DOMAIN: &[u8] = b"fractalos/fractal-remote-grant/1";
pub const LEASE_SIGNATURE_DOMAIN: &[u8] = b"fractalos/fractal-execution-lease/1";
pub const ID_BYTES: usize = 32;
pub const SIGNATURE_BYTES: usize = 64;
pub const NONCE_BYTES: usize = 32;
pub const GRANT_SIGNING_BYTES: usize = 304;
pub const LEASE_SIGNING_BYTES: usize = 168;
pub const REMOTE_BADGE_PREFIX: u64 = 0x5245_4d4f_0000_0000; // "REMO"
const MAX_NONCE_CACHE: usize = 64;
const MAX_LOCAL_BADGES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum EffectClass {
    ReadOnly = 0,
    Local = 1,
    Shared = 2,
    External = 3,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GrantError {
    #[error("bad argument")]
    BadArg,
    #[error("fabricated or invalid signature")]
    Signature,
    #[error("untrusted issuer")]
    Issuer,
    #[error("issuer or grant revoked")]
    Revoked,
    #[error("tailnet peer is not the grant subject")]
    PeerSubject,
    #[error("wrong audience")]
    Audience,
    #[error("wrong agent binding")]
    Agent,
    #[error("wrong space binding")]
    Space,
    #[error("wrong interface binding")]
    Interface,
    #[error("operation escalation")]
    Operation,
    #[error("object scope escape")]
    ObjectScope,
    #[error("effect ceiling escalation")]
    Effect,
    #[error("over budget")]
    Budget,
    #[error("expired grant or lease")]
    Expired,
    #[error("zero nonce")]
    Nonce,
    #[error("stale authority epoch")]
    StaleAuthority,
    #[error("replayed grant nonce")]
    Replay,
    #[error("remote badge injection")]
    RemoteBadge,
    #[error("lease signature invalid")]
    LeaseSignature,
    #[error("lease subject binding mismatch")]
    LeaseSubject,
    #[error("partitioned execution lease")]
    LeasePartitioned,
    #[error("grant not admitted")]
    NotAdmitted,
    #[error("capbroker derivation refused")]
    CapBroker,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteGrant {
    pub issuer: [u8; ID_BYTES],
    pub subject_node: [u8; ID_BYTES],
    pub subject_agent: [u8; ID_BYTES],
    pub audience_node: [u8; ID_BYTES],
    pub space_id: [u8; ID_BYTES],
    pub interface_hash: [u8; ID_BYTES],
    pub object_scope: [u8; ID_BYTES],
    pub operation_mask: u64,
    pub scope_flags: u32,
    pub effect_class: u32,
    pub budget_units: u64,
    pub expiry_unix_ms: u64,
    pub authority_epoch: u64,
    pub revocation_epoch: u64,
    pub nonce: [u8; NONCE_BYTES],
    pub signature: [u8; SIGNATURE_BYTES],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionLease {
    pub lease_id: u64,
    pub fence_epoch: u64,
    pub expires_unix_ms: u64,
    pub authority_epoch: u64,
    pub revocation_epoch: u64,
    pub holder_node: [u8; ID_BYTES],
    pub subject_agent: [u8; ID_BYTES],
    pub space_id: [u8; ID_BYTES],
    pub nonce: [u8; NONCE_BYTES],
    pub signature: [u8; SIGNATURE_BYTES],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityContext {
    pub authenticated_tailnet_peer: [u8; ID_BYTES],
    pub local_node: [u8; ID_BYTES],
    pub expected_agent: [u8; ID_BYTES],
    pub expected_space: [u8; ID_BYTES],
    pub expected_interface: [u8; ID_BYTES],
    pub expected_object_scope: [u8; ID_BYTES],
    pub requested_operations: u64,
    pub required_scope_flags: u32,
    pub requested_effect_class: u32,
    pub max_effect_class: u32,
    pub requested_budget_units: u64,
    pub now_unix_ms: u64,
    pub authority_epoch: u64,
    pub revocation_epoch: u64,
    pub expected_lease_fence_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmitResult {
    pub local_badge: u64,
}

#[derive(Debug, Clone)]
struct NonceEntry {
    issuer: [u8; ID_BYTES],
    nonce: [u8; NONCE_BYTES],
    expiry_unix_ms: u64,
}

#[derive(Debug, Clone)]
struct BadgeEntry {
    badge: u64,
    issuer: [u8; ID_BYTES],
    subject_agent: [u8; ID_BYTES],
    space_id: [u8; ID_BYTES],
    nonce: [u8; NONCE_BYTES],
    operations: u64,
    effect_class: u32,
    budget_units: u64,
    expiry_unix_ms: u64,
    authority_epoch: u64,
    revocation_epoch: u64,
}

/// Host-side CapBroker + MeshAgent remote-authority mirror.
#[derive(Debug)]
pub struct RemoteAuthority {
    secret: [u8; 32],
    trusted_issuers: HashMap<[u8; ID_BYTES], [u8; ID_BYTES]>,
    revoked_issuers: HashMap<[u8; ID_BYTES], ()>,
    nonces: Vec<NonceEntry>,
    badges: Vec<BadgeEntry>,
    next_badge: u64,
    pub allowed_events: u32,
    pub denied_events: u32,
}

impl RemoteAuthority {
    pub fn new(secret: [u8; 32]) -> Self {
        Self {
            secret,
            trusted_issuers: HashMap::new(),
            revoked_issuers: HashMap::new(),
            nonces: Vec::new(),
            badges: Vec::new(),
            next_badge: 1,
            allowed_events: 0,
            denied_events: 0,
        }
    }

    pub fn trust_issuer(&mut self, issuer: [u8; ID_BYTES], public_key: [u8; ID_BYTES]) {
        self.revoked_issuers.remove(&issuer);
        self.trusted_issuers.insert(issuer, public_key);
    }

    pub fn revoke_issuer(&mut self, issuer: &[u8; ID_BYTES]) {
        self.revoked_issuers.insert(*issuer, ());
    }

    pub fn sign_grant(&self, grant: &mut RemoteGrant) {
        grant.signature = sign_bytes(GRANT_SIGNATURE_DOMAIN, &grant.signing_bytes(), &self.secret);
    }

    pub fn sign_lease(&self, lease: &mut ExecutionLease, issuer: &[u8; ID_BYTES]) {
        let mut body = Vec::with_capacity(LEASE_SIGNATURE_DOMAIN.len() + ID_BYTES + LEASE_SIGNING_BYTES);
        body.extend_from_slice(LEASE_SIGNATURE_DOMAIN);
        body.extend_from_slice(issuer);
        body.extend_from_slice(&lease.signing_bytes());
        lease.signature = hash64(&body, &self.secret);
    }

    pub fn admit(
        &mut self,
        grant: &RemoteGrant,
        ctx: &AuthorityContext,
        serialized_badge: u64,
    ) -> Result<AdmitResult, GrantError> {
        if serialized_badge != 0 {
            self.denied_events += 1;
            return Err(GrantError::RemoteBadge);
        }
        match self.validate_grant(grant, ctx) {
            Ok(()) => {}
            Err(err) => {
                self.denied_events += 1;
                return Err(err);
            }
        }
        if self.nonce_seen(grant, ctx.now_unix_ms) {
            self.denied_events += 1;
            return Err(GrantError::Replay);
        }
        let badge = self.derive_badge(grant, ctx)?;
        self.remember_nonce(grant);
        self.allowed_events += 1;
        Ok(AdmitResult { local_badge: badge })
    }

    pub fn dispatch(
        &mut self,
        grant: &RemoteGrant,
        lease: Option<&ExecutionLease>,
        ctx: &AuthorityContext,
        local_badge: u64,
    ) -> Result<AdmitResult, GrantError> {
        if local_badge == 0 || (local_badge & REMOTE_BADGE_PREFIX) == REMOTE_BADGE_PREFIX {
            // Local badges use CapBroker prefix shape; a pure REMOTE_BADGE_PREFIX
            // without generation bits is treated as injection.
            if local_badge != 0 && self.badges.iter().all(|entry| entry.badge != local_badge) {
                self.denied_events += 1;
                return Err(GrantError::RemoteBadge);
            }
        }
        if let Err(err) = self.validate_grant(grant, ctx) {
            self.denied_events += 1;
            return Err(err);
        }
        if !self.nonce_seen(grant, ctx.now_unix_ms) {
            self.denied_events += 1;
            return Err(GrantError::NotAdmitted);
        }
        if !self.badge_matches(local_badge, grant, ctx) {
            self.denied_events += 1;
            return Err(GrantError::CapBroker);
        }
        if let Some(lease) = lease {
            if let Err(err) = self.validate_lease(lease, grant, ctx) {
                self.denied_events += 1;
                return Err(err);
            }
        }
        self.allowed_events += 1;
        Ok(AdmitResult {
            local_badge,
        })
    }

    fn validate_grant(&self, grant: &RemoteGrant, ctx: &AuthorityContext) -> Result<(), GrantError> {
        if grant.subject_node != ctx.authenticated_tailnet_peer {
            return Err(GrantError::PeerSubject);
        }
        self.verify_grant_signature(grant)?;
        if grant.audience_node != ctx.local_node {
            return Err(GrantError::Audience);
        }
        if grant.subject_agent != ctx.expected_agent {
            return Err(GrantError::Agent);
        }
        if grant.space_id != ctx.expected_space {
            return Err(GrantError::Space);
        }
        if grant.interface_hash != ctx.expected_interface {
            return Err(GrantError::Interface);
        }
        if ctx.requested_operations == 0
            || (ctx.requested_operations & !grant.operation_mask) != 0
        {
            return Err(GrantError::Operation);
        }
        if (ctx.required_scope_flags & !grant.scope_flags) != 0
            || grant.object_scope != ctx.expected_object_scope
        {
            return Err(GrantError::ObjectScope);
        }
        if ctx.requested_effect_class > grant.effect_class
            || grant.effect_class > ctx.max_effect_class
            || ctx.max_effect_class > EffectClass::External as u32
        {
            return Err(GrantError::Effect);
        }
        if ctx.requested_budget_units == 0 || ctx.requested_budget_units > grant.budget_units {
            return Err(GrantError::Budget);
        }
        if grant.expiry_unix_ms <= ctx.now_unix_ms {
            return Err(GrantError::Expired);
        }
        if grant.nonce.iter().all(|b| *b == 0) {
            return Err(GrantError::Nonce);
        }
        if grant.authority_epoch != ctx.authority_epoch {
            return Err(GrantError::StaleAuthority);
        }
        if grant.revocation_epoch != ctx.revocation_epoch {
            return Err(GrantError::Revoked);
        }
        Ok(())
    }

    fn validate_lease(
        &self,
        lease: &ExecutionLease,
        grant: &RemoteGrant,
        ctx: &AuthorityContext,
    ) -> Result<(), GrantError> {
        if !self.verify_lease_signature(lease, &grant.issuer) {
            return Err(GrantError::LeaseSignature);
        }
        if lease.nonce.iter().all(|b| *b == 0) {
            return Err(GrantError::Nonce);
        }
        if lease.expires_unix_ms <= ctx.now_unix_ms || lease.expires_unix_ms > grant.expiry_unix_ms
        {
            return Err(GrantError::Expired);
        }
        if lease.authority_epoch != ctx.authority_epoch
            || lease.authority_epoch != grant.authority_epoch
        {
            return Err(GrantError::StaleAuthority);
        }
        if lease.revocation_epoch != ctx.revocation_epoch
            || lease.revocation_epoch != grant.revocation_epoch
        {
            return Err(GrantError::Revoked);
        }
        if lease.fence_epoch != ctx.expected_lease_fence_epoch {
            return Err(GrantError::LeasePartitioned);
        }
        if lease.holder_node != grant.subject_node
            || lease.holder_node != ctx.authenticated_tailnet_peer
            || lease.subject_agent != grant.subject_agent
            || lease.space_id != grant.space_id
        {
            return Err(GrantError::LeaseSubject);
        }
        Ok(())
    }

    fn verify_grant_signature(&self, grant: &RemoteGrant) -> Result<(), GrantError> {
        if self.revoked_issuers.contains_key(&grant.issuer) {
            return Err(GrantError::Revoked);
        }
        if !self.trusted_issuers.contains_key(&grant.issuer) {
            return Err(GrantError::Issuer);
        }
        let expected = sign_bytes(GRANT_SIGNATURE_DOMAIN, &grant.signing_bytes(), &self.secret);
        if expected != grant.signature {
            return Err(GrantError::Signature);
        }
        Ok(())
    }

    fn verify_lease_signature(&self, lease: &ExecutionLease, issuer: &[u8; ID_BYTES]) -> bool {
        let mut body = Vec::with_capacity(LEASE_SIGNATURE_DOMAIN.len() + ID_BYTES + LEASE_SIGNING_BYTES);
        body.extend_from_slice(LEASE_SIGNATURE_DOMAIN);
        body.extend_from_slice(issuer);
        body.extend_from_slice(&lease.signing_bytes());
        hash64(&body, &self.secret) == lease.signature
    }

    fn nonce_seen(&self, grant: &RemoteGrant, now_unix_ms: u64) -> bool {
        self.nonces.iter().any(|entry| {
            entry.expiry_unix_ms > now_unix_ms
                && entry.issuer == grant.issuer
                && entry.nonce == grant.nonce
        })
    }

    fn remember_nonce(&mut self, grant: &RemoteGrant) {
        if self.nonces.len() >= MAX_NONCE_CACHE {
            self.nonces.remove(0);
        }
        self.nonces.push(NonceEntry {
            issuer: grant.issuer,
            nonce: grant.nonce,
            expiry_unix_ms: grant.expiry_unix_ms,
        });
    }

    fn derive_badge(
        &mut self,
        grant: &RemoteGrant,
        ctx: &AuthorityContext,
    ) -> Result<u64, GrantError> {
        if let Some(existing) = self.badges.iter().find(|entry| {
            entry.issuer == grant.issuer
                && entry.subject_agent == grant.subject_agent
                && entry.space_id == grant.space_id
                && entry.nonce == grant.nonce
                && entry.operations == ctx.requested_operations
                && entry.effect_class == ctx.requested_effect_class
                && entry.budget_units == ctx.requested_budget_units
        }) {
            return Ok(existing.badge);
        }
        if self.badges.len() >= MAX_LOCAL_BADGES {
            self.badges.remove(0);
        }
        let generation = self.next_badge;
        self.next_badge = self.next_badge.saturating_add(1);
        let badge = 0x4342_0000_0000_0000u64 | (generation << 16) | (self.badges.len() as u64 + 1);
        self.badges.push(BadgeEntry {
            badge,
            issuer: grant.issuer,
            subject_agent: grant.subject_agent,
            space_id: grant.space_id,
            nonce: grant.nonce,
            operations: ctx.requested_operations,
            effect_class: ctx.requested_effect_class,
            budget_units: ctx.requested_budget_units,
            expiry_unix_ms: grant.expiry_unix_ms,
            authority_epoch: grant.authority_epoch,
            revocation_epoch: grant.revocation_epoch,
        });
        Ok(badge)
    }

    fn badge_matches(&self, badge: u64, grant: &RemoteGrant, ctx: &AuthorityContext) -> bool {
        self.badges.iter().any(|entry| {
            entry.badge == badge
                && entry.issuer == grant.issuer
                && entry.subject_agent == grant.subject_agent
                && entry.space_id == grant.space_id
                && entry.nonce == grant.nonce
                && entry.operations == ctx.requested_operations
                && entry.effect_class == ctx.requested_effect_class
                && entry.budget_units == ctx.requested_budget_units
                && entry.expiry_unix_ms == grant.expiry_unix_ms
                && entry.authority_epoch == ctx.authority_epoch
                && entry.revocation_epoch == ctx.revocation_epoch
        })
    }
}

impl RemoteGrant {
    pub fn signing_bytes(&self) -> [u8; GRANT_SIGNING_BYTES] {
        let mut out = [0u8; GRANT_SIGNING_BYTES];
        let mut o = 0usize;
        for field in [
            &self.issuer,
            &self.subject_node,
            &self.subject_agent,
            &self.audience_node,
            &self.space_id,
            &self.interface_hash,
            &self.object_scope,
        ] {
            out[o..o + ID_BYTES].copy_from_slice(field);
            o += ID_BYTES;
        }
        out[o..o + 8].copy_from_slice(&self.operation_mask.to_le_bytes());
        o += 8;
        out[o..o + 4].copy_from_slice(&self.scope_flags.to_le_bytes());
        o += 4;
        out[o..o + 4].copy_from_slice(&self.effect_class.to_le_bytes());
        o += 4;
        out[o..o + 8].copy_from_slice(&self.budget_units.to_le_bytes());
        o += 8;
        out[o..o + 8].copy_from_slice(&self.expiry_unix_ms.to_le_bytes());
        o += 8;
        out[o..o + 8].copy_from_slice(&self.authority_epoch.to_le_bytes());
        o += 8;
        out[o..o + 8].copy_from_slice(&self.revocation_epoch.to_le_bytes());
        o += 8;
        out[o..o + NONCE_BYTES].copy_from_slice(&self.nonce);
        o += NONCE_BYTES;
        debug_assert_eq!(o, GRANT_SIGNING_BYTES);
        out
    }
}

impl ExecutionLease {
    pub fn signing_bytes(&self) -> [u8; LEASE_SIGNING_BYTES] {
        let mut out = [0u8; LEASE_SIGNING_BYTES];
        let mut o = 0usize;
        for value in [
            self.lease_id,
            self.fence_epoch,
            self.expires_unix_ms,
            self.authority_epoch,
            self.revocation_epoch,
        ] {
            out[o..o + 8].copy_from_slice(&value.to_le_bytes());
            o += 8;
        }
        for field in [&self.holder_node, &self.subject_agent, &self.space_id] {
            out[o..o + ID_BYTES].copy_from_slice(field);
            o += ID_BYTES;
        }
        out[o..o + NONCE_BYTES].copy_from_slice(&self.nonce);
        o += NONCE_BYTES;
        debug_assert_eq!(o, LEASE_SIGNING_BYTES);
        out
    }
}

fn sign_bytes(domain: &[u8], signing: &[u8], secret: &[u8; 32]) -> [u8; SIGNATURE_BYTES] {
    let mut body = Vec::with_capacity(domain.len() + signing.len());
    body.extend_from_slice(domain);
    body.extend_from_slice(signing);
    hash64(&body, secret)
}

fn hash64(body: &[u8], secret: &[u8; 32]) -> [u8; SIGNATURE_BYTES] {
    let mut hasher = Sha512::new();
    hasher.update(body);
    hasher.update(secret);
    let digest = hasher.finalize();
    let mut out = [0u8; SIGNATURE_BYTES];
    out.copy_from_slice(&digest);
    out
}

pub fn fill_id(seed: u8) -> [u8; ID_BYTES] {
    let mut out = [0u8; ID_BYTES];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = seed.wrapping_add(i as u8);
    }
    out
}
