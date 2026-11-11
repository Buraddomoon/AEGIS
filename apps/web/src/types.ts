export interface Page<T> {
  items: T[]
  total: number
  offset?: number
  limit?: number
}
export interface User {
  id: string
  username: string
  role: 'administrator' | 'operator' | 'viewer'
  active: boolean
}
export interface Lab {
  id: string
  name: string
  kind: string
  authorized: boolean
  description: string
  owner: string
  environment_version: number
  isolation: string
  active_run_id: string | null
  execution_capability: string
  connection_status: string
  synthetic: boolean
  trust?: {
    configuration_hash: string | null
    deployment_configuration_hash: string | null
    matches_deployment: boolean
    reviewed_by: string | null
    reviewed_at: string | null
  } | null
}
export interface Test {
  id: string
  name: string
  description: string
  technique_id: string | null
  behavior: string
  cleanup: string
  prerequisites: string
  demo_outcome: string
  execution_kind: 'demo' | 'linux_marker'
  approved: boolean
  platform: string
  risk: string
  version: number
  catalog_mapping_status?: 'active' | 'revoked' | 'deprecated' | 'absent' | 'unmapped'
  available_for_new_scope?: boolean
}
export type CatalogLifecycle = 'active' | 'revoked' | 'deprecated' | 'absent'
export interface CatalogReference {
  release_id: string
  version: string
  provenance: 'bundled' | 'official_commit'
  source_sha256: string
  source_commit: string | null
}
export interface CatalogRelease {
  id: string
  dataset_version: string
  provenance: 'bundled' | 'official_commit'
  source_url: string
  source_commit: string | null
  source_sha256: string
  license_sha256: string
  created_at: string
  applied_by: string | null
}
export interface CatalogStatus {
  status: 'ready' | 'uninitialized'
  current: CatalogRelease | null
  counts: Record<CatalogLifecycle, number> | null
  limitation: string
}
export interface Technique {
  id: string
  name: string
  description: string
  tactics: string[]
  platforms: string[]
  parent_id: string | null
  reference: string
  dataset_version: string
  coverage: string
  catalog_status: CatalogLifecycle
  coverage_applicable: boolean
  revoked: boolean
  deprecated: boolean
  present_in_current: boolean
}
export interface Campaign {
  id: string
  name: string
  objective: string
  laboratory_id: string
  created_at: string
  test_ids: string[]
}
export interface Scope {
  attack_catalog?: CatalogReference
  attack_techniques?: Record<string, unknown>[]
  telemetry?: {
    provider: string
    policy?: { agent_id: string; expected_rule: string; ingestion_wait_seconds: number }
  }
  environment_version: number
  asset_id: string
  mode: string
  synthetic: boolean
  rule_versions: Record<string, number>
  rule_test_links?: RuleTestLink[]
  clock_skew_seconds: number
  ingestion_window_seconds: number
  test_definitions: {
    id: string
    name: string
    technique_id: string | null
    version: number
    demo_outcome: string
  }[]
}
export interface Run {
  requested_by: string
  id: string
  campaign_id: string
  schedule_id: string | null
  laboratory_id: string
  state: string
  synthetic: boolean
  scope_hash: string
  scope: Scope
  created_at: string
  started_at: string | null
  ended_at: string | null
  error: string | null
  cancel_requested: boolean
}
export interface EventRecord {
  id: string
  source_id: string
  source: string
  timestamp: string
  kind: string
  synthetic: boolean
  rule_id: string | null
  sha256: string
  raw: Record<string, unknown>
}
export interface Result {
  id: string
  outcome: string
  reason: string
  logic_version: string
  synthetic: boolean
  collection_complete: boolean
  telemetry_available: boolean
  alerts_available: boolean
}
export interface Execution {
  collection?: {
    provider: string
    attempts: number
    complete: boolean
    window_satisfied: boolean
    reason: string
    started_at: string
    ended_at: string
  } | null
  id: string
  test_id: string
  state: string
  marker: string
  executed: boolean
  synthetic: boolean
  result: Result | null
  events: EventRecord[]
  runner_receipt: { content: Record<string, unknown>; sha256: string } | null
  runner_cleanup: { content: Record<string, unknown>; sha256: string } | null
  evidence: { id: string; event_id: string; reason: string }[]
}
export interface RunDetail extends Run {
  campaign_name: string
  objective: string
  schedule_occurrence: ScheduleOccurrence | null
  approval: {
    id: string
    approved_by: string
    expires_at: string
    max_duration_seconds: number
    used_at: string | null
    schedule_authorization_id: string | null
  } | null
  executions: Execution[]
  steps: {
    id: string
    execution_id: string | null
    state: string
    message: string
    created_at: string
  }[]
}

export interface Schedule {
  id: string
  campaign_id: string
  laboratory_id: string
  created_by: string
  state: string
  scope: Scope
  scope_hash: string
  plan_hash: string
  interval_seconds: number
  max_occurrences: number
  max_duration_seconds: number
  starts_at: string
  ends_at: string
  next_due_at: string
  occurrences_count: number
  reason: string | null
}
export interface ScheduleDetail extends Schedule {
  plan: Record<string, unknown>
  synthetic: boolean
  authorizations: {
    id: string
    created_at: string
    expires_at: string
    revoked_at: string | null
  }[]
}
export interface ScheduleOccurrence {
  id: string
  schedule_id: string
  authorization_id: string
  scheduled_for: string
  run_id: string | null
  status: string
  reason: string
}
export interface ScheduledReport {
  id: string
  schedule_id: string
  authorization_id: string
  occurrence_id: string
  run_id: string
  previous_run_id: string | null
  kind: 'BASELINE' | 'COMPARISON'
  state: 'PENDING' | 'READY' | 'FAILED'
  attempts: number
  next_attempt_at: string
  error_code: string | null
  document_sha256: string | null
  generated_at: string | null
  synthetic: boolean
}
export interface Coverage {
  scope: string
  synthetic: boolean
  catalogued_techniques: number | null
  evaluated_techniques: number | null
  historical_evaluated_techniques?: number
  attack_catalog?: CatalogReference
  selection?: CoverageSelection
  scope_sha256?: string
  snapshot_at?: string
  run_states?: Record<string, number>
  unversioned_runs?: number
  total_runs: number
  completed_tests: number
  valid_tests: number
  detected_percentage: number | null
  outcomes: Record<string, number>
  denominator: string
  limitation: string
  trend: { run_id: string; date: string; detected: number; evaluated: number }[]
}
export interface Connectors {
  items: { id: string; name: string; status: string; synthetic: boolean; description: string }[]
  worker_online: boolean
  scheduling: string
  lab_mode: string
}
export interface Rule {
  id: string
  title: string
  sigma_id: string
  latest_version: number
  created_at: string
  status: string
}
export interface RuleVersion {
  id: string
  version: number
  content: string
  techniques: string[]
  sha256: string
  created_at: string
}
export interface RuleTestLink {
  id: string
  rule_id: string
  current_rule_title: string
  rule_version_id: string
  rule_version: number
  rule_sha256: string
  latest_rule_version: number
  test_id: string
  test_name: string
  test_version: number
  current_test_version: number
  rationale: string
  created_by: string
  created_at: string
  retired_at: string | null
  retired_by: string | null
  review_required: boolean
  purpose: 'planning_only_not_deployed'
}
export interface ScopeChange {
  key: string
  before: unknown
  after: unknown
}
export interface Audit {
  id: string
  actor_id: string | null
  action: string
  resource_id: string
  details: Record<string, unknown>
  created_at: string
}
export interface Comparison {
  before_id: string
  after_id: string
  synthetic: boolean
  comparable: boolean
  same_scope: boolean
  comparability_reasons?: string[]
  before_scope: Scope
  after_scope: Scope
  scope_changes: {
    catalog_context_recorded?: boolean
    rule_versions: ScopeChange[]
    test_definitions: ScopeChange[]
    environment: ScopeChange[]
    rule_test_links: ScopeChange[] | null
    link_context_recorded: boolean
  }
  tests: { test_id: string; before: string; after: string; changed: boolean }[]
  limitation: string
}

export interface CoverageSelection {
  mode: 'demo' | 'linux'
  catalog_release: string
  requested_from: string | null
  requested_before: string | null
  resolved_catalog_release_id: string | null
  evaluation_catalog: CatalogReference | null
  time_basis: string
  interval: string
}

export interface SigmaAnalysis {
  rule_id: string
  rule_version_id: string
  rule_version: number
  sha256: string
  analyzer_version: string
  pysigma_version: string
  status: 'findings' | 'no_findings_in_selected_checks'
  checks: string[]
  skipped_checks: string[]
  findings: {
    code: string
    severity: string
    message: string
    origin: string
    selection?: string
    field?: string | null
    condition_index?: number
  }[]
  facts: {
    logsource: Record<string, string>
    conditions: string[]
    selections: string[]
    declared_fields: string[]
    keyword_selections: string[]
  }
  compatibility: {
    status: 'not_configured'
    backend: null
    pipeline: null
    conversion_performed: false
    deployment_performed: false
  }
  limitations: string[]
}

export interface ConversionProfile {
  id: string
  name: string
  sha256: string
  status: 'candidate_not_executable'
  target: string
  logsource: Record<string, string>
  fields: Record<string, string>
  index_mapping_verified: false
}
export interface BackendCompatibility {
  status: 'blocked' | 'declared_requirements_satisfied_only'
  snapshot_reviewed_at: string
  snapshot_sha256: string
  blockers: { code: string; message: string }[]
  packages: {
    name: string
    version: string
    installed: string | null
    license: string
    source: string
    requirements: { name: string; required: string; installed: string | null; satisfied: boolean }[]
  }[]
}
export interface ConversionProfiles {
  items: ConversionProfile[]
  backend: BackendCompatibility
  readiness_version: string
}
export interface ConversionReadiness {
  rule_id: string
  rule_version_id: string
  rule_version: number
  sha256: string
  readiness_version: string
  pysigma_version: string
  profile: ConversionProfile
  backend: BackendCompatibility
  status: 'blocked'
  can_convert: false
  conversion_performed: false
  deployment_performed: false
  logsource_matches: boolean
  field_mapping_complete: boolean
  mappings: { source_field: string; target_field: string | null }[]
  keyword_selections: string[]
  field_references: string[]
  blockers: { code: string; message: string }[]
  limitations: string[]
}

export interface SigmaMappingPreview {
  rule_id: string
  rule_version_id: string
  rule_version: number
  sha256: string
  preview_version: 'sigma-mapping-preview/1'
  profile: ConversionProfile
  pipeline: {
    version: string
    profile_id: string
    profile_sha256: string
    pysigma_version: string
    sha256: string
  }
  status: 'previewed' | 'unsupported'
  blockers: { code: string; message: string }[]
  before_detection: Record<string, unknown> | null
  after_detection: Record<string, unknown> | null
  document_sha256: string
  can_convert: false
  query_generated: false
  siem_queried: false
  deployment_performed: false
  index_mapping_verified: false
  limitations: string[]
}
