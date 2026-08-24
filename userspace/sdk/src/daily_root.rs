
use alloc::string::String;
use alloc::vec::Vec;

pub type ObjectId = [u8; 32];
const ZERO_ID: ObjectId = [0u8; 32];
const SCHEMA_MAJOR: u32 = 1;
const SCHEMA_MINOR: u32 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SchemaVersion { pub major: u32, pub minor: u32 }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRange { pub stream_id: u32, pub first_seq: u64, pub last_seq: u64, pub head: ObjectId }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grant { Project, Progress, DailyRoot, Health, WorkerMemory, TaskIntent }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceClass { Projection, Credential, PersonalRecord, ShellCommand, FilesystemPath, Promotion }
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RedactionClass { Public, Summary, Hashed, Withheld }
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SourceFreshness { Fresh, Stale, Offline }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergePolicy { PreserveConflicts, SchemaDeclared }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentKind { Acknowledge, Defer, Prioritize, RequestProof, Cancel }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskIntentReference { pub intent_id: ObjectId, pub kind: IntentKind, pub subject: ObjectId, pub expect_root: ObjectId }
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportError { Invalid, UnsupportedSchema, Denied, StaleAuthority, StaleCursor, ResultTooLarge, NotFound, Unavailable, Conflict, Redacted, StaleSource, RateLimited, Expired }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DailyItem {
    pub item_id: ObjectId, pub subject: ObjectId, pub ordering_key: String, pub ordinal: u32,
    pub event_seq: u64, pub origin: SourceClass, pub provenance: ObjectId,
    pub freshness_seconds: u32, pub source_freshness: SourceFreshness,
    pub intent: Option<TaskIntentReference>, pub redaction: RedactionClass,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DailyRoot {
    pub schema: SchemaVersion, pub bundle_id: ObjectId, pub project_root: ObjectId,
    pub event_root: ObjectId, pub range: EventRange, pub date_key: String, pub tz_key: String,
    pub utc_offset_minutes: i32, pub built_at_unix: u64, pub freshness_seconds: u32,
    pub source_freshness: SourceFreshness, pub item_count: u32, pub items: Vec<DailyItem>,
    pub provenance: ObjectId, pub conflict_heads: Vec<ObjectId>, pub merge_policy: MergePolicy,
    pub merge_schema: Option<ObjectId>, pub redaction: RedactionClass,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedSummary {
    pub summary_id: ObjectId, pub subject: ObjectId, pub local_date_key: String, pub tz_key: String,
    pub ordering_key: String, pub ordinal: u32, pub event_seq: u64, pub source_class: SourceClass,
    pub redaction: RedactionClass, pub source_freshness: SourceFreshness, pub freshness_seconds: u32,
    pub provenance: ObjectId, pub intent: Option<TaskIntentReference>, pub authorized: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DailyRootRequest { pub authority_epoch: u64, pub date_key: String, pub tz_key: String, pub utc_offset_minutes: i32, pub built_at_unix: u64 }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DailyRootInput {
    pub schema: SchemaVersion, pub authority_epoch: u64, pub grants: Vec<Grant>,
    pub project_root: ObjectId, pub event_root: ObjectId, pub range: EventRange,
    pub summaries: Vec<AuthorizedSummary>, pub conflict_heads: Vec<ObjectId>,
    pub merge_schema: Option<ObjectId>, pub max_daily_items: u32, pub max_conflict_heads: u32,
    pub freshness_window_seconds: u32,
}

pub struct DailyRootProjector;
impl DailyRootProjector {
    pub const fn new() -> Self { Self }
    pub fn build(&self, request: DailyRootRequest, input: DailyRootInput) -> Result<DailyRoot, ExportError> {
        validate_request(&request, &input)?;
        let mut summaries = input.summaries.into_iter().filter(|s| s.local_date_key == request.date_key && s.tz_key == request.tz_key).collect::<Vec<_>>();
        for summary in &summaries { validate_summary(summary, input.freshness_window_seconds)?; }
        summaries.sort_by(|a, b| a.ordering_key.as_bytes().cmp(b.ordering_key.as_bytes()).then_with(|| a.ordinal.cmp(&b.ordinal)).then_with(|| a.event_seq.cmp(&b.event_seq)).then_with(|| a.summary_id.cmp(&b.summary_id)));
        if summaries.len() > input.max_daily_items as usize { return Err(ExportError::ResultTooLarge); }
        let mut items = Vec::with_capacity(summaries.len());
        for summary in summaries {
            let item_id = item_id(&summary, &input.project_root, &input.event_root);
            items.push(DailyItem { item_id, subject: summary.subject, ordering_key: summary.ordering_key, ordinal: summary.ordinal, event_seq: summary.event_seq, origin: summary.source_class, provenance: summary.provenance, freshness_seconds: summary.freshness_seconds, source_freshness: summary.source_freshness, intent: summary.intent, redaction: summary.redaction });
        }
        let mut conflict_heads = input.conflict_heads;
        conflict_heads.sort(); conflict_heads.dedup(); conflict_heads.retain(|h| *h != ZERO_ID);
        if conflict_heads.len() > input.max_conflict_heads as usize { return Err(ExportError::Conflict); }
        let merge_policy = if input.merge_schema.is_some() { MergePolicy::SchemaDeclared } else { MergePolicy::PreserveConflicts };
        let freshness_seconds = items.iter().map(|i| i.freshness_seconds).min().unwrap_or(0);
        let source_freshness = fold_freshness(items.iter().map(|i| i.source_freshness));
        let redaction = fold_redaction(items.iter().map(|i| i.redaction));
        let provenance = root_provenance(&request, &input.project_root, &input.event_root, &input.range, &items, &conflict_heads, input.merge_schema.as_ref());
        let bundle_id = bundle_id(&request.date_key, &request.tz_key, request.utc_offset_minutes, &input.project_root, &input.event_root, &input.range, &provenance);
        Ok(DailyRoot { schema: input.schema, bundle_id, project_root: input.project_root, event_root: input.event_root, range: input.range, date_key: request.date_key, tz_key: request.tz_key, utc_offset_minutes: request.utc_offset_minutes, built_at_unix: request.built_at_unix, freshness_seconds, source_freshness, item_count: items.len() as u32, items, provenance, conflict_heads, merge_policy, merge_schema: input.merge_schema, redaction })
    }
}
impl Default for DailyRootProjector { fn default() -> Self { Self::new() } }
pub fn project_daily_root(request: DailyRootRequest, input: DailyRootInput) -> Result<DailyRoot, ExportError> { DailyRootProjector::new().build(request, input) }

fn validate_request(request: &DailyRootRequest, input: &DailyRootInput) -> Result<(), ExportError> {
    if input.schema.major != SCHEMA_MAJOR || input.schema.minor > SCHEMA_MINOR { return Err(ExportError::UnsupportedSchema); }
    if request.authority_epoch != input.authority_epoch { return Err(ExportError::StaleAuthority); }
    if !input.grants.iter().any(|grant| *grant == Grant::DailyRoot) { return Err(ExportError::Denied); }
    if !valid_date_key(&request.date_key) || request.tz_key.is_empty() || request.utc_offset_minutes < -1440 || request.utc_offset_minutes > 1440 || input.project_root == ZERO_ID || input.event_root == ZERO_ID || input.range.first_seq > input.range.last_seq || (input.range.first_seq == 0 && input.range.last_seq != 0) { return Err(ExportError::Invalid); }
    Ok(())
}
fn validate_summary(summary: &AuthorizedSummary, freshness_window: u32) -> Result<(), ExportError> {
    if !summary.authorized { return Err(ExportError::Denied); }
    if summary.source_class != SourceClass::Projection { return Err(ExportError::Redacted); }
    if summary.redaction != RedactionClass::Public && summary.redaction != RedactionClass::Summary { return Err(ExportError::Redacted); }
    if summary.source_freshness == SourceFreshness::Offline { return Err(ExportError::Unavailable); }
    if summary.source_freshness == SourceFreshness::Stale || summary.freshness_seconds > freshness_window { return Err(ExportError::StaleSource); }
    if summary.summary_id == ZERO_ID || summary.subject == ZERO_ID || summary.provenance == ZERO_ID { return Err(ExportError::Invalid); }
    Ok(())
}
fn valid_date_key(date: &str) -> bool {
    let bytes = date.as_bytes(); bytes.len() == 10 && bytes[4] == b'-' && bytes[7] == b'-' && bytes.iter().enumerate().all(|(idx, b)| idx == 4 || idx == 7 || (*b >= b'0' && *b <= b'9'))
}
fn fold_freshness<I: IntoIterator<Item = SourceFreshness>>(iter: I) -> SourceFreshness { let mut out = SourceFreshness::Fresh; for f in iter { if f > out { out = f; } } out }
fn fold_redaction<I: IntoIterator<Item = RedactionClass>>(iter: I) -> RedactionClass { let mut out = RedactionClass::Public; for r in iter { if r > out { out = r; } } out }
fn item_id(summary: &AuthorizedSummary, project_root: &ObjectId, event_root: &ObjectId) -> ObjectId { let mut h = StableHash::new(b"agentos.daily-item.v1"); h.bytes(project_root); h.bytes(event_root); h.bytes(&summary.summary_id); h.bytes(&summary.subject); h.str(&summary.ordering_key); h.u32(summary.ordinal); h.u64(summary.event_seq); h.finish() }
fn root_provenance(request: &DailyRootRequest, project_root: &ObjectId, event_root: &ObjectId, range: &EventRange, items: &[DailyItem], conflict_heads: &[ObjectId], merge_schema: Option<&ObjectId>) -> ObjectId {
    let mut h = StableHash::new(b"agentos.daily-root.provenance.v1"); h.bytes(project_root); h.bytes(event_root); h.u32(range.stream_id); h.u64(range.first_seq); h.u64(range.last_seq); h.bytes(&range.head); h.str(&request.date_key); h.str(&request.tz_key); h.i32(request.utc_offset_minutes);
    for item in items { h.bytes(&item.item_id); h.bytes(&item.subject); h.str(&item.ordering_key); h.u32(item.ordinal); h.u64(item.event_seq); h.bytes(&item.provenance); if let Some(intent) = &item.intent { h.bytes(&intent.intent_id); h.bytes(&intent.subject); h.bytes(&intent.expect_root); h.u32(intent.kind as u32); } else { h.u32(u32::MAX); } }
    for head in conflict_heads { h.bytes(head); } if let Some(schema) = merge_schema { h.bytes(schema); } h.finish()
}
fn bundle_id(date_key: &str, tz_key: &str, utc_offset_minutes: i32, project_root: &ObjectId, event_root: &ObjectId, range: &EventRange, provenance: &ObjectId) -> ObjectId { let mut h = StableHash::new(b"agentos.daily-root.bundle.v1"); h.bytes(project_root); h.bytes(event_root); h.u32(range.stream_id); h.u64(range.first_seq); h.u64(range.last_seq); h.bytes(&range.head); h.str(date_key); h.str(tz_key); h.i32(utc_offset_minutes); h.bytes(provenance); h.finish() }

struct StableHash { state: [u64; 4] }
impl StableHash {
    fn new(domain: &[u8]) -> Self { let mut this = Self { state: [0x243f_6a88_85a3_08d3, 0x1319_8a2e_0370_7344, 0xa409_3822_299f_31d0, 0x082e_fa98_ec4e_6c89] }; this.bytes(domain); this }
    fn bytes(&mut self, bytes: &[u8]) { self.u64(bytes.len() as u64); for (idx, byte) in bytes.iter().enumerate() { let slot = idx & 3; self.state[slot] ^= (*byte as u64).wrapping_add(0x9e37_79b9_7f4a_7c15); self.state[slot] = self.state[slot].rotate_left(13).wrapping_mul(0xbf58_476d_1ce4_e5b9); self.state[(slot + 1) & 3] ^= self.state[slot].rotate_right(17); } }
    fn str(&mut self, value: &str) { self.bytes(value.as_bytes()); }
    fn u32(&mut self, value: u32) { self.bytes(&value.to_le_bytes()); }
    fn i32(&mut self, value: i32) { self.bytes(&value.to_le_bytes()); }
    fn u64(&mut self, value: u64) { self.bytes_raw(&value.to_le_bytes()); }
    fn bytes_raw(&mut self, bytes: &[u8]) { for (idx, byte) in bytes.iter().enumerate() { let slot = idx & 3; self.state[slot] ^= (*byte as u64).wrapping_mul(0x1000_0000_01b3); self.state[slot] = self.state[slot].rotate_left(7).wrapping_add(0x517c_c1b7_2722_0a95); } }
    fn finish(mut self) -> ObjectId { for round in 0..16u64 { let idx = (round as usize) & 3; self.state[idx] ^= self.state[(idx + 1) & 3].rotate_left(11); self.state[idx] = self.state[idx].wrapping_mul(0x94d0_49bb_1331_11eb ^ round); } let mut out = [0u8; 32]; for (idx, word) in self.state.iter().enumerate() { out[idx * 8..idx * 8 + 8].copy_from_slice(&word.to_le_bytes()); } if out == ZERO_ID { out[0] = 1; } out }
}
