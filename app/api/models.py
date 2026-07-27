from __future__ import annotations

"""Pydantic request models for the VulnFlow HTTP API."""

from typing import Any

from pydantic import BaseModel, Field
class ApiAssetRecord(BaseModel):
    asset_id: str = ""
    asset_name: str = ""
    service_name: str = ""
    business_unit: str = ""
    owner: str = ""
    environment: str = ""
    criticality: int = Field(default=1, ge=1, le=5)
    data_sensitivity: int = Field(default=1, ge=1, le=5)
    internet_exposed: bool = False
    tags: str = ""
    cmdb_id: str = ""
    cloud_instance_id: str = ""
    fqdn: str = ""
    ip_address: str = ""
    mac_address: str = ""
    status: str = "ACTIVE"

class ApiAssetImport(BaseModel):
    items: list[ApiAssetRecord]

class ApiAssetIdentifierCreate(BaseModel):
    identifier_type: str
    value: str
    scope: str = ""
    source: str = "api"
    confidence: int | None = Field(default=None, ge=1, le=100)

class ApiAssetIdentityMerge(BaseModel):
    target_asset_ref_id: str
    reason: str = Field(min_length=3, max_length=1500)

class ApiAssetIdentityReject(BaseModel):
    reason: str = Field(min_length=3, max_length=1500)

class ApiAssetMergeRollbackRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=1500)

class ApiCampaignCreate(BaseModel):
    title: str
    description: str = ""
    owner: str = ""
    due_date: str = ""
    finding_ids: list[str] = Field(default_factory=list)
    cve_id: str = ""
    apply_workflow: bool = False

class ApiCampaignMembers(BaseModel):
    finding_ids: list[str] = Field(default_factory=list)
    cve_id: str = ""

class ApiCampaignStatus(BaseModel):
    status: str
    expected_row_version: int | None = Field(default=None, ge=1)

class ApiWorkflowUpdate(BaseModel):
    status: str
    owner: str = ""
    due_date: str = ""
    notes: str = ""
    expected_row_version: int | None = Field(default=None, ge=1)

class ApiRiskAcceptanceRequest(BaseModel):
    reason: str
    exception_expiry: str
    notes: str = ""
    expected_row_version: int | None = Field(default=None, ge=1)

class ApiApprovalDecision(BaseModel):
    decision: str
    decision_note: str = ""

class ApiRemediationVerificationRequest(BaseModel):
    method: str
    evidence_note: str = ""
    expected_row_version: int | None = Field(default=None, ge=1)

class ApiRemediationVerificationDecision(BaseModel):
    decision: str
    decision_note: str = ""

class ApiEvidenceRetire(BaseModel):
    reason: str = Field(min_length=1, max_length=1500)

class ApiEvidenceScanWaiver(BaseModel):
    reason: str = Field(min_length=1, max_length=1500)

class ApiEvidenceCustodyTransfer(BaseModel):
    to_custodian: str = Field(min_length=1, max_length=200)
    purpose: str = Field(min_length=1, max_length=1500)

class ApiSourceConflictDecision(BaseModel):
    field_name: str
    chosen_source_record_id: str
    reason: str = Field(min_length=1, max_length=1500)

class ApiSbomLinkDecision(BaseModel):
    decision: str

class ApiOsvMatchDecision(BaseModel):
    decision: str
    reason: str = ""

class ApiVexCreate(BaseModel):
    component_id: str
    cve_id: str
    analysis_state: str
    justification: str = ""
    responses: list[str] = Field(default_factory=list)
    impact_statement: str = ""
    action_statement: str = ""
    detail: str = ""
    finding_id: str = ""

class ApiVexDecision(BaseModel):
    decision: str
    decision_note: str = ""

class ApiPolicyCreate(BaseModel):
    content_yaml: str
    notes: str = ""

class ApiPolicyActivationRequest(BaseModel):
    reason: str

class ApiPolicyDecision(BaseModel):
    decision: str
    decision_note: str = ""

class ApiFindingsExport(BaseModel):
    decision: str = ""
    status: str = ""
    query: str = ""
    overdue: bool = False
    exception: str = ""
    record_state: str = "ALL"
    scanner_source: str = ""

class ApiConfigBaseline(BaseModel):
    note: str = Field(default="", max_length=1000)

class ApiConfigChangeRequest(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=1500)
    rollback_plan: str = Field(min_length=1, max_length=4000)
    window_start: str
    window_end: str
    target_snapshot: dict[str, Any] | None = None

class ApiConfigChangeDecision(BaseModel):
    decision: str
    decision_note: str = Field(default="", max_length=1500)

class ApiConfigChangeApply(BaseModel):
    note: str = Field(default="", max_length=1000)

class ApiExecutionReplay(BaseModel):
    reason: str = Field(min_length=3, max_length=1500)

class ApiIntegrityProofKeyTransition(BaseModel):
    from_key_id: str = Field(min_length=1, max_length=64)
    to_key_id: str = Field(min_length=1, max_length=64)
    effective_at: str = ""
    reason: str = Field(min_length=3, max_length=1500)


class ApiIntegrityProofRevocationCheckpoint(BaseModel):
    recovery_key_id: str = Field(min_length=1, max_length=64)

class ApiIntegrityProofCheckpointWitness(BaseModel):
    witness_key_id: str = Field(min_length=1, max_length=64)
    checkpoint_id: str = Field(default="", max_length=64)

class ApiIntegrityProofTransparencyPublish(BaseModel):
    log_key_id: str = Field(min_length=1, max_length=64)
    checkpoint_id: str = Field(default="", max_length=64)
    minimum_witness_quorum: int = Field(default=1, ge=1, le=32)

class ApiIntegrityProofTransparencyMirrorReceipt(BaseModel):
    mirror_key_id: str = Field(min_length=1, max_length=64)
    head_id: str = Field(default="", max_length=64)

class ApiIntegrityProofMirrorConsistencyCheckpoint(BaseModel):
    mirror_key_ids: list[str] = Field(min_length=1, max_length=32)
    minimum_quorum: int = Field(default=1, ge=1, le=32)
    head_id: str = Field(default="", max_length=64)

class ApiIntegrityProofKeyRevocation(BaseModel):
    revoked_key_id: str = Field(min_length=1, max_length=64)
    replacement_key_id: str = Field(min_length=1, max_length=64)
    recovery_key_id: str = Field(min_length=1, max_length=64)
    invalid_after: str
    effective_at: str = ""
    reason: str = Field(min_length=3, max_length=1500)

__all__ = [
    'ApiAssetRecord',
    'ApiAssetImport',
    'ApiAssetIdentifierCreate',
    'ApiAssetIdentityMerge',
    'ApiAssetIdentityReject',
    'ApiAssetMergeRollbackRequest',
    'ApiCampaignCreate',
    'ApiCampaignMembers',
    'ApiCampaignStatus',
    'ApiWorkflowUpdate',
    'ApiRiskAcceptanceRequest',
    'ApiApprovalDecision',
    'ApiRemediationVerificationRequest',
    'ApiRemediationVerificationDecision',
    'ApiEvidenceRetire',
    'ApiEvidenceScanWaiver',
    'ApiEvidenceCustodyTransfer',
    'ApiSourceConflictDecision',
    'ApiSbomLinkDecision',
    'ApiOsvMatchDecision',
    'ApiVexCreate',
    'ApiVexDecision',
    'ApiPolicyCreate',
    'ApiPolicyActivationRequest',
    'ApiPolicyDecision',
    'ApiFindingsExport',
    'ApiConfigBaseline',
    'ApiConfigChangeRequest',
    'ApiConfigChangeDecision',
    'ApiConfigChangeApply',
    'ApiExecutionReplay',
    'ApiIntegrityProofKeyTransition',
    'ApiIntegrityProofRevocationCheckpoint',
    'ApiIntegrityProofCheckpointWitness',
    'ApiIntegrityProofTransparencyPublish',
    'ApiIntegrityProofTransparencyMirrorReceipt',
    'ApiIntegrityProofMirrorConsistencyCheckpoint',
    'ApiIntegrityProofKeyRevocation',
]
