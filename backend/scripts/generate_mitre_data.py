"""
Script to generate the MITRE ATT&CK Enterprise Techniques lookup JSON file
from MITRE's public attack-stix-data repository (mitre-attack/attack-stix-data).
"""
import os
import json
import urllib.request
from pathlib import Path

STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
OUTPUT_FILE = Path(__file__).resolve().parent.parent / "data" / "mitre_techniques.json"

def fetch_and_generate():
    print(f"Fetching MITRE ATT&CK Enterprise STIX data from:\n  {STIX_URL}")
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    
    req = urllib.request.Request(STIX_URL, headers={"User-Agent": "CyberRange-AI/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        stix_bundle = json.loads(resp.read().decode("utf-8"))
    
    techniques = {}
    objects = stix_bundle.get("objects", [])
    print(f"Total STIX objects in bundle: {len(objects)}")
    
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        
        # Extract MITRE external ID (e.g. T1566 or T1566.002)
        technique_id = None
        for ext_ref in obj.get("external_references", []):
            if ext_ref.get("source_name") == "mitre-attack":
                technique_id = ext_ref.get("external_id")
                break
        
        if not technique_id or not technique_id.startswith("T"):
            continue
            
        technique_name = obj.get("name", "").strip()
        
        # Extract associated kill chain phases / tactics
        tactics = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                phase_name = phase.get("phase_name", "").replace("-", " ").title()
                tactics.append(phase_name)
        
        is_revoked = obj.get("revoked", False)
        is_deprecated = obj.get("x_mitre_deprecated", False)
        
        # If we already have this technique, only replace if the current object is active (not revoked/deprecated)
        if technique_id in techniques:
            if not is_revoked and not is_deprecated:
                techniques[technique_id] = {
                    "technique_id": technique_id,
                    "technique_name": technique_name,
                    "tactics": tactics if tactics else techniques[technique_id].get("tactics", []),
                    "is_subtechnique": obj.get("x_mitre_is_subtechnique", "." in technique_id)
                }
        else:
            techniques[technique_id] = {
                "technique_id": technique_id,
                "technique_name": technique_name,
                "tactics": tactics,
                "is_subtechnique": obj.get("x_mitre_is_subtechnique", "." in technique_id)
            }
    
    print(f"Extracted {len(techniques)} MITRE Enterprise techniques.")
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(techniques, f, indent=2, ensure_ascii=False)
        
    print(f"Saved MITRE techniques lookup to: {OUTPUT_FILE}")
    return techniques

if __name__ == "__main__":
    fetch_and_generate()
