"""Explicit developer-only ATT&CK refresh. Never runs during startup."""
import argparse
import hashlib
import json
import re
import urllib.request
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--version", required=True)
args = parser.parse_args()
if not re.fullmatch(r"\d+\.\d+", args.version):
    parser.error("Version must be N.N")
base = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
url = base + f"enterprise-attack/enterprise-attack-{args.version}.json"
with urllib.request.urlopen(url, timeout=60) as response:
    raw = response.read(80_000_000)
bundle = json.loads(raw)
objects = bundle["objects"]
parents = {o["source_ref"]: o["target_ref"] for o in objects
           if o["type"] == "relationship" and o.get("relationship_type") == "subtechnique-of"}
ids = {o["id"]: ref["external_id"] for o in objects if o["type"] == "attack-pattern"
       for ref in o.get("external_references", []) if ref.get("source_name") == "mitre-attack"}
techniques = []
for item in objects:
    if item["type"] != "attack-pattern" or item.get("revoked") or item.get("x_mitre_deprecated"):
        continue
    reference = next(r for r in item["external_references"] if r["source_name"] == "mitre-attack")
    techniques.append({"id": reference["external_id"], "stix_id": item["id"],
        "name": item["name"], "description": item.get("description", ""),
        "tactics": [p["phase_name"] for p in item.get("kill_chain_phases", [])
                    if p["kill_chain_name"] == "mitre-attack"],
        "platforms": item.get("x_mitre_platforms", []),
        "parent_id": ids.get(parents.get(item["id"])),
        "reference": reference["url"], "dataset_version": args.version})
data = {"version": args.version, "source_url": url,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "techniques": sorted(techniques, key=lambda t: t["id"])}
output = Path("fixtures/attack/enterprise.json")
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
with urllib.request.urlopen(base + "LICENSE.txt", timeout=30) as response:
    (output.parent / "LICENSE.txt").write_bytes(response.read())
print(f"Cached {len(techniques)} official techniques, v{args.version}, source sha256={data['source_sha256']}")
