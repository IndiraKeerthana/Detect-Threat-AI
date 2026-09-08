from typing import Any, Literal

from pydantic import BaseModel, Field


EntityType = Literal["ip", "domain", "url"]
RelationshipEntityType = Literal[
    "ip",
    "domain",
    "url",
    "country",
    "region",
    "city",
    "asn",
]
ProviderState = Literal["available", "degraded", "skipped", "error"]


class ThreatEntity(BaseModel):
    """A normalized observable extracted from an email."""

    type: EntityType
    value: str
    sources: list[str] = Field(default_factory=list)


class ThreatObservation(BaseModel):
    """Provider-neutral, evidence-backed information about an entity."""

    provider: str
    entity_type: EntityType
    entity: str
    kind: str
    status: Literal["success", "not_found", "error"] = "success"
    data: dict[str, Any] = Field(default_factory=dict)
    evidence: list[str] = Field(default_factory=list)
    retrieved_at: str | None = None
    confidence: Literal["high", "medium", "low", "none"] = "none"


class ProviderStatus(BaseModel):
    provider: str
    configured: bool = True
    status: ProviderState
    checked: int = 0
    message: str | None = None


class ThreatRelationship(BaseModel):
    source_type: RelationshipEntityType
    source: str
    target_type: RelationshipEntityType
    target: str
    relationship: str
    providers: list[str] = Field(default_factory=list)


class ThreatIntelligence(BaseModel):
    """Additive Step 5 output. It deliberately contains no risk score."""

    entities: list[ThreatEntity] = Field(default_factory=list)
    observations: list[ThreatObservation] = Field(default_factory=list)
    relationships: list[ThreatRelationship] = Field(default_factory=list)
    provider_status: list[ProviderStatus] = Field(default_factory=list)
