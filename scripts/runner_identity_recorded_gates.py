"""Persist computed, normalized gate facts before returning admission to lifecycles."""

import runner_activation_identity_client_gates as client
import runner_activation_identity_gates as server
import runner_activation_network_gates as network
from aegis.domain.validation import digest
from runner_activation_metadata import ActivationError
from runner_activation_owned_probe import fresh
from runner_identity_artifacts import IdentityArtifacts


def _same_confirmation(records, confirmation):
    if not isinstance(records, IdentityArtifacts) or records.confirmation is not confirmation:
        raise ActivationError("identity_gate_artifacts_same_confirmation_required")


def _persist(records, c, name, gate, review, evidence):
    _same_confirmation(records, c)
    c._guard()
    before = c.store.review()
    if not isinstance(review, dict) or evidence["gate_sha256"] != digest(gate):
        raise ActivationError("identity_gate_computed_facts_required")
    records.write(name, {"gate": gate, "review": review, "evidence": evidence})
    # Disk IO must not refresh the observation or let an expired/changed lease
    # through. The retained record is evidence, never a reusable admission token.
    if c._guard() != before:
        raise ActivationError("identity_gate_intent_changed_during_persistence")
    fresh(gate)
    return gate


def before_network_create(confirmation, records, phase, spec):
    if not isinstance(confirmation, network.NetworkGates):
        raise ActivationError("identity_network_computed_gates_required")
    _same_confirmation(records, confirmation)
    value = confirmation.before_create(phase, spec)
    return _persist(
        records,
        confirmation,
        "network-create-gate",
        value,
        confirmation._last_review,
        confirmation.evidence[-1],
    )


class RecordedServerGates(server.IdentityGates):
    def __init__(self, confirmation, build_inputs, records, **providers):
        _same_confirmation(records, confirmation)
        self.records = records
        super().__init__(confirmation, build_inputs, **providers)

    def review(self, phase, spec):
        value = super().review(phase, spec)
        return _persist(
            self.records,
            self.confirmation,
            "server-" + phase + "-gate",
            value,
            self._last_review,
            self.evidence[-1],
        )


class RecordedClientGates(client.IdentityClientGates):
    def __init__(self, confirmation, build_inputs, payload, expected_sha256, records, **providers):
        _same_confirmation(records, confirmation)
        self.records = records
        super().__init__(confirmation, build_inputs, payload, expected_sha256, **providers)

    def review(self, phase, spec):
        try:
            value = super().review(phase, spec)
            return _persist(
                self.records,
                self.confirmation,
                "client-" + phase + "-gate",
                value,
                self._last_review,
                self.evidence[-1],
            )
        except BaseException:
            # A failed/stale disk write cannot leave usable client admission.
            self._last_gate = None
            self._last_review = None
            raise
