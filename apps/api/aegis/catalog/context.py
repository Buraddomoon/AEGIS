"""Bounded official reference graph. This graph never represents collected telemetry."""

import re

from pydantic import BaseModel, ConfigDict, Field, model_validator

KINDS = {
    "x-mitre-data-source": ("DS", "datasources"),
    "x-mitre-data-component": ("DC", "datacomponents"),
    "x-mitre-detection-strategy": ("DET", "detectionstrategies"),
    "x-mitre-analytic": ("AN", None),
}


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class LogReference(Strict):
    component_ref: str
    name: str = Field(min_length=1, max_length=500)
    channel: str = Field(max_length=2000)


class Reference(Strict):
    stix_id: str
    id: str = Field(max_length=10)
    kind: str
    name: str = Field(min_length=1, max_length=500)
    reference: str = Field(max_length=180)
    source_modified: str
    revoked: bool
    deprecated: bool
    data_source_ref: str | None = None
    analytic_refs: list[str] = Field(default_factory=list, max_length=100)
    log_sources: list[LogReference] = Field(default_factory=list, max_length=200)

    @model_validator(mode="after")
    def identity(self):
        from aegis.catalog.document import stix_id, timestamp

        if self.kind not in KINDS:
            raise ValueError("Unknown reference kind")
        stix_id(self.stix_id, self.kind)
        timestamp(self.source_modified)
        prefix, path = KINDS[self.kind]
        if not re.fullmatch(prefix + r"[0-9]{4}", self.id):
            raise ValueError("Invalid official reference ID")
        expected = (
            r"https://attack\.mitre\.org/detectionstrategies/DET[0-9]{4}#" + self.id
            if path is None
            else re.escape("https://attack.mitre.org/" + path + "/" + self.id) + "/?"
        )
        if not re.fullmatch(expected, self.reference):
            raise ValueError("Official context reference mismatch")
        if len(set(self.analytic_refs)) != len(self.analytic_refs):
            raise ValueError("Duplicate analytic reference")
        if self.analytic_refs and self.kind != "x-mitre-detection-strategy":
            raise ValueError("Analytic references require a strategy")
        if self.log_sources and self.kind != "x-mitre-analytic":
            raise ValueError("Log references require an analytic")
        if self.data_source_ref and self.kind != "x-mitre-data-component":
            raise ValueError("Data source reference requires a component")
        return self


class Relationship(Strict):
    stix_id: str
    kind: str
    source_ref: str
    target_ref: str
    source_modified: str
    revoked: bool
    deprecated: bool

    @model_validator(mode="after")
    def identity(self):
        from aegis.catalog.document import stix_id, timestamp

        stix_id(self.stix_id, "relationship")
        timestamp(self.source_modified)
        if self.kind not in ("subtechnique-of", "detects"):
            raise ValueError("Unknown context relationship")
        return self


class Context(Strict):
    objects: list[Reference] = Field(max_length=10_000)
    relationships: list[Relationship] = Field(max_length=20_000)

    def validate_graph(self, techniques):
        nodes = {n.stix_id: n for n in self.objects}
        patterns = {t.stix_id: t for t in techniques}
        if [n.stix_id for n in self.objects] != sorted(nodes) or len(
            {n.id for n in self.objects}
        ) != len(nodes):
            raise ValueError("Duplicate or unordered context identity")
        if [r.stix_id for r in self.relationships] != sorted(
            {r.stix_id for r in self.relationships}
        ):
            raise ValueError("Duplicate or unordered relationship")

        def require(key, kind):
            if key not in nodes or nodes[key].kind != kind:
                raise ValueError("Missing or wrong context reference")

        for node in self.objects:
            if node.data_source_ref:
                require(node.data_source_ref, "x-mitre-data-source")
            for key in node.analytic_refs:
                require(key, "x-mitre-analytic")
            for log in node.log_sources:
                require(log.component_ref, "x-mitre-data-component")
        for edge in self.relationships:
            if edge.target_ref not in patterns:
                raise ValueError("Missing context technique")
            if edge.kind == "subtechnique-of":
                if (
                    edge.source_ref not in patterns
                    or patterns[edge.source_ref].parent_id != patterns[edge.target_ref].id
                ):
                    raise ValueError("Context parent mismatch")
            elif edge.source_ref not in nodes or nodes[edge.source_ref].kind not in (
                "x-mitre-detection-strategy",
                "x-mitre-data-component",
            ):
                raise ValueError("Invalid detects reference")
        active_parents = {
            edge.source_ref: edge.target_ref
            for edge in self.relationships
            if edge.kind == "subtechnique-of" and not edge.revoked and not edge.deprecated
        }
        if any(
            t.parent_id
            and not t.revoked
            and not t.deprecated
            and (
                t.stix_id not in active_parents
                or patterns[active_parents[t.stix_id]].id != t.parent_id
            )
            for t in techniques
        ):
            raise ValueError("Missing active parent provenance")


def normalize_context(objects, techniques):
    from aegis.catalog.document import boolean

    nodes, relationships = [], []
    for item in objects:
        kind = item.get("type")
        if kind in KINDS:
            logs = item.get("x_mitre_log_source_references", [])
            if not isinstance(logs, list) or any(not isinstance(log, dict) for log in logs):
                raise ValueError("Invalid log source references")
            refs = [
                r
                for r in item.get("external_references", [])
                if isinstance(r, dict) and r.get("source_name") == "mitre-attack"
            ]
            if (
                len(refs) != 1
                or "enterprise-attack" not in item.get("x_mitre_domains", [])
                or item.get("spec_version") != "2.1"
            ):
                raise ValueError("Context domain/reference mismatch")
            nodes.append(
                Reference(
                    stix_id=item["id"],
                    id=refs[0].get("external_id"),
                    kind=kind,
                    name=item.get("name"),
                    reference=refs[0].get("url"),
                    source_modified=item.get("modified"),
                    revoked=boolean(item, "revoked"),
                    deprecated=boolean(item, "x_mitre_deprecated"),
                    data_source_ref=item.get("x_mitre_data_source_ref"),
                    analytic_refs=item.get("x_mitre_analytic_refs", []),
                    log_sources=[
                        LogReference(
                            component_ref=log.get("x_mitre_data_component_ref"),
                            name=log.get("name"),
                            channel=log.get("channel"),
                        )
                        for log in logs
                    ],
                )
            )
        elif kind == "relationship" and item.get("relationship_type") in (
            "subtechnique-of",
            "detects",
        ):
            relationships.append(
                Relationship(
                    stix_id=item["id"],
                    kind=item["relationship_type"],
                    source_ref=item.get("source_ref"),
                    target_ref=item.get("target_ref"),
                    source_modified=item.get("modified"),
                    revoked=boolean(item, "revoked"),
                    deprecated=boolean(item, "x_mitre_deprecated"),
                )
            )
    context = Context(
        objects=sorted(nodes, key=lambda n: n.stix_id),
        relationships=sorted(relationships, key=lambda r: r.stix_id),
    )
    context.validate_graph(techniques)
    return context


def detail(document, technique_id):
    """Only relations in this release; never infer a parent by splitting an ID."""
    patterns = {t.stix_id: t for t in document.techniques}
    technique = next((t for t in patterns.values() if t.id == technique_id), None)
    status = (
        "technique_absent"
        if technique is None
        else "legacy_unavailable"
        if document.context is None
        else "available"
    )
    result = {"status": status, "parent": None, "children": [], "telemetry": []}
    if status != "available":
        # The legacy snapshot still records parent IDs, but has no edge provenance.
        if technique and technique.parent_id:
            parent = next(t for t in patterns.values() if t.id == technique.parent_id)
            result["parent"] = {"technique": parent.model_dump(), "relationship": None}
        if technique:
            result["children"] = [
                {"technique": t.model_dump(), "relationship": None}
                for t in document.techniques
                if t.parent_id == technique.id
            ]
        return result
    nodes = {n.stix_id: n for n in document.context.objects}
    for edge in document.context.relationships:
        if edge.kind == "subtechnique-of":
            if edge.source_ref == technique.stix_id:
                result["parent"] = {
                    "technique": patterns[edge.target_ref].model_dump(),
                    "relationship": edge.model_dump(),
                }
            if edge.target_ref == technique.stix_id:
                result["children"].append(
                    {
                        "technique": patterns[edge.source_ref].model_dump(),
                        "relationship": edge.model_dump(),
                    }
                )
        elif edge.target_ref == technique.stix_id:
            source = nodes[edge.source_ref]
            base = {"relationship": edge.model_dump()}
            if source.kind == "x-mitre-data-component":
                result["telemetry"].append(
                    {**base, "component": source.model_dump(), "data_source": None}
                )
                if source.data_source_ref:
                    result["telemetry"][-1]["data_source"] = nodes[
                        source.data_source_ref
                    ].model_dump()
            else:
                base["strategy"] = source.model_dump()
                if not source.analytic_refs:
                    result["telemetry"].append(base)
                for key in source.analytic_refs:
                    analytic = nodes[key]
                    row = {**base, "analytic": analytic.model_dump()}
                    if not analytic.log_sources:
                        result["telemetry"].append(row)
                    for log in analytic.log_sources:
                        component = nodes[log.component_ref]
                        result["telemetry"].append(
                            {
                                **row,
                                "component": component.model_dump(),
                                "data_source": nodes[component.data_source_ref].model_dump()
                                if component.data_source_ref
                                else None,
                                "log_source": log.model_dump(),
                            }
                        )
    result["children"].sort(key=lambda r: r["technique"]["id"])
    if not result["telemetry"]:
        result["status"] = "not_provided"
    return result
