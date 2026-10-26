from datetime import UTC, datetime

import pytest
from aegis.analytics import Selection
from pydantic import ValidationError


def test_offsets_normalize_and_period_is_half_open():
    scope = Selection(
        requested_from="2026-10-26T09:00:00-03:00",
        requested_before="2026-10-26T14:00:00+01:00",
    )
    assert scope.requested_from == datetime(2026, 10, 26, 12, tzinfo=UTC)
    assert scope.requested_before == datetime(2026, 10, 26, 13, tzinfo=UTC)
    assert scope.catalog_release == "all"
    assert Selection(catalog_release="a" * 64).catalog_release == "a" * 64


@pytest.mark.parametrize(
    "value",
    [
        "2026-10-26",
        "2026-10-26T12:00:00",
        "1720000000",
        1720000000,
        True,
        "2026-99-99T12:00:00Z",
        "9999-12-31T23:59:59-14:00",
    ],
)
def test_timestamp_requires_explicit_offset_and_representable_utc(value):
    with pytest.raises(ValidationError):
        Selection(requested_from=value)


@pytest.mark.parametrize("end", ["2026-10-26T12:00:00Z", "2026-10-26T11:00:00Z"])
def test_equal_or_reversed_interval_is_invalid(end):
    with pytest.raises(ValidationError):
        Selection(requested_from="2026-10-26T12:00:00Z", requested_before=end)


@pytest.mark.parametrize("release", ["", "20.0", "../", "A" * 64, "a" * 63])
def test_selector_cannot_be_a_version_name_path_or_ambiguous_identity(release):
    with pytest.raises(ValidationError):
        Selection(catalog_release=release)
