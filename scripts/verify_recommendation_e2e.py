"""Verify actual browser downloads from the disposable Demo; no API calls."""

import hashlib
import html
import json
from pathlib import Path

from aegis.domain.validation import digest
from pypdf import PdfReader


def verify(directory: Path) -> dict:
    document = json.loads((directory / "recommendations.json").read_text(encoding="utf-8"))
    assert document["kind"] == "recommendations" and document["synthetic"] is True
    assert document["integrity_sha256"] == digest(
        {key: value for key, value in document.items() if key != "integrity_sha256"}
    )
    analysis = document["analysis"]
    assert analysis["synthetic"] is True
    assert analysis["input_sha256"] == digest(document["source_snapshot"])
    assert analysis["policy_sha256"] == digest(analysis["policy"])
    assert analysis["integrity_sha256"] == digest(
        {key: value for key, value in analysis.items() if key != "integrity_sha256"}
    )
    raw_html = (directory / "recommendations.html").read_text(encoding="utf-8")
    embedded = html.unescape(raw_html.rsplit("<pre>", 1)[1].split("</pre>", 1)[0])
    assert json.loads(embedded) == document
    pages = PdfReader(directory / "recommendations.pdf", strict=True).pages
    text = "\n".join(page.extract_text() for page in pages)
    assert all("DADOS SINTÉTICOS" in page.extract_text() for page in pages)
    for value in (
        document["integrity_sha256"],
        analysis["integrity_sha256"],
        analysis["policy_sha256"],
        analysis["input_sha256"],
    ):
        assert value in text
    assert {"detected", "observed_not_alerted", "no_telemetry", "inconclusive"} <= {
        item["code"] for item in analysis["items"]
    }
    for item in analysis["items"]:
        assert item["reason"] in text.replace("\n", " ")
    files = [directory / ("recommendations." + suffix) for suffix in ("json", "html", "pdf")]
    files += [
        directory / "screenshots" / (name + ".png")
        for name in ("recommendations", "recommendations-mobile")
    ]
    for path in files[-2:]:
        assert path.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
    return {
        "status": "VERIFIED",
        "synthetic": True,
        "policy": analysis["policy"]["version"],
        "analysis_sha256": analysis["integrity_sha256"],
        "pdf_pages": len(pages),
        "artifacts": {
            path.name: {
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "bytes": path.stat().st_size,
            }
            for path in files
        },
        "limits": "Disposable Demo/browser proof; no native collector, marker or deployment.",
    }


if __name__ == "__main__":
    print(json.dumps(verify(Path(".local/e2e")), ensure_ascii=False, indent=2))
