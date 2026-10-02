import pytest
import asyncio
import json
from pathlib import Path
from unittest.mock import patch, AsyncMock
from httpx import AsyncClient, ASGITransport
from datetime import datetime, timezone
from pydantic import ValidationError

from backend.server import (
    app,
    AttackScenarioResponse,
    LLMAttackScenarioPayload,
    LLMAttackStage,
    Technique,
    fallback_generate_attack_scenario,
    assign_detection_likelihoods,
    MITRE_TECHNIQUES
)
from backend.config import settings


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def mock_db():
    """Mock MongoDB database operations."""
    with patch("backend.server.db") as mock_database:
        mock_database.attack_scenarios.insert_one = AsyncMock(return_value=None)
        yield mock_database


# Helper function to generate a valid 8-stage dummy payload
def create_valid_dummy_stages():
    return [
        {
            "stage": "Reconnaissance Phase",
            "time": "Day 0",
            "description": "Adversary scans perimeter IP addresses for vulnerabilities.",
            "impact": "Network layout mapped.",
            "tactic": "Reconnaissance",
            "techniques": [{"technique_id": "T1595.002", "technique_name": "Vulnerability Scanning"}],
            "detection_likelihood": "Low",
            "detection_hint": "Check firewall logs",
            "mitigation": "Block scanning IPs"
        },
        {
            "stage": "Initial Access via Phishing",
            "time": "Day 2",
            "description": "Adversary sends targeted spearphishing emails with malicious links.",
            "impact": "Employee credentials captured via reverse proxy.",
            "tactic": "Initial Access",
            "techniques": [{"technique_id": "T1566.002", "technique_name": "Spearphishing Link"}],
            "detection_likelihood": "Medium",
            "detection_hint": "Inspect email gateway logs",
            "mitigation": "Enable MFA and anti-phishing filters"
        },
        {
            "stage": "Command Execution",
            "time": "Day 3",
            "description": "PowerShell scripts execute in user context to download secondary stage payloads.",
            "impact": "Interactive shell established.",
            "tactic": "Execution",
            "techniques": [{"technique_id": "T1059.001", "technique_name": "PowerShell"}],
            "detection_likelihood": "Medium",
            "detection_hint": "Sysmon Event ID 1",
            "mitigation": "Constrained language mode"
        },
        {
            "stage": "Privilege Escalation",
            "time": "Day 4",
            "description": "Attacker leverages local exploit to elevate privileges to SYSTEM administrator.",
            "impact": "Full local host takeover.",
            "tactic": "Privilege Escalation",
            "techniques": [{"technique_id": "T1068", "technique_name": "Exploitation for Privilege Escalation"}],
            "detection_likelihood": "High",
            "detection_hint": "Audit privilege elevation",
            "mitigation": "Kernel patch updates"
        },
        {
            "stage": "Security Tool Tampering",
            "time": "Day 5",
            "description": "Attacker disables endpoint security telemetry and unhooks EDR drivers.",
            "impact": "Local security sensors blinded.",
            "tactic": "Defense Evasion",
            "techniques": [{"technique_id": "T1562.001", "technique_name": "Disable or Modify Tools"}],
            "detection_likelihood": "High",
            "detection_hint": "EDR heartbeat failures",
            "mitigation": "Sensor tamper protection"
        },
        {
            "stage": "Network Discovery",
            "time": "Day 6",
            "description": "Adversary scans internal subnets to enumerate file servers and domain controllers.",
            "impact": "Internal server landscape cataloged.",
            "tactic": "Discovery",
            "techniques": [{"technique_id": "T1046", "technique_name": "Network Service Discovery"}],
            "detection_likelihood": "Medium",
            "detection_hint": "Network IDS port scan alert",
            "mitigation": "Internal microsegmentation"
        },
        {
            "stage": "Data Staging and Collection",
            "time": "Day 7",
            "description": "Attacker identifies and aggregates sensitive internal financial databases into archives.",
            "impact": "Proprietary financial records collected.",
            "tactic": "Collection",
            "techniques": [{"technique_id": "T1005", "technique_name": "Data from Local System"}],
            "detection_likelihood": "High",
            "detection_hint": "File access volume alerts",
            "mitigation": "Data loss prevention controls"
        },
        {
            "stage": "Ransomware Encryption",
            "time": "Day 8",
            "description": "Adversary executes ransomware encrypting all file shares and SQL databases.",
            "impact": "Total operational stoppage across enterprise.",
            "tactic": "Impact",
            "techniques": [{"technique_id": "T1486", "technique_name": "Data Encrypted for Impact"}],
            "detection_likelihood": "High",
            "detection_hint": "Mass file renaming alerts",
            "mitigation": "Immutable offsite backups"
        }
    ]


# =========================================================================
# 1. Fallback output validates for EVERY organization type & maturity level
# =========================================================================
@pytest.mark.parametrize("org_type", [
    "Tech Startup", "Enterprise", "Government", "SMB",
    "Healthcare", "Financial", "Retail", "Unknown Corporate"
])
@pytest.mark.parametrize("maturity", ["Low", "Medium", "High"])
def test_fallback_validates_for_all_org_types_and_maturities(org_type, maturity):
    fallback_data = fallback_generate_attack_scenario(org_type, maturity)
    
    # Must validate cleanly against LLMAttackScenarioPayload (8-10 stages, complete kill chain)
    validated = LLMAttackScenarioPayload.model_validate(fallback_data)
    assert validated.title
    assert len(validated.summary) >= 20
    assert 8 <= len(validated.timeline) <= 10

    # Verify coverage
    tactics = [s.tactic for s in validated.timeline]
    assert "Initial Access" in tactics
    assert "Execution" in tactics
    assert any(t in tactics for t in ["Credential Access", "Privilege Escalation"])
    assert any(t in tactics for t in ["Lateral Movement", "Discovery"])
    assert any(t in tactics for t in ["Collection", "Exfiltration"])
    assert validated.timeline[-1].tactic in ["Impact", "Exfiltration"]


# =========================================================================
# 2. Every technique ID in fallback templates exists in MITRE lookup file
# =========================================================================
def test_all_fallback_technique_ids_exist_in_lookup():
    orgs = ["Tech Startup", "Enterprise", "Government", "SMB", "Healthcare"]
    maturities = ["Low", "Medium", "High"]
    
    lookup_file = Path(__file__).resolve().parent.parent / "backend" / "data" / "mitre_techniques.json"
    assert lookup_file.exists(), f"MITRE lookup file missing at {lookup_file}"
    
    with open(lookup_file, "r", encoding="utf-8") as f:
        lookup = json.load(f)
        
    assert len(lookup) > 500, "Lookup file contains too few techniques"

    for org in orgs:
        for mat in maturities:
            data = fallback_generate_attack_scenario(org, mat)
            for stage in data["timeline"]:
                for tech in stage.get("techniques", []):
                    tid = tech["technique_id"]
                    assert tid in lookup, f"Fallback technique ID '{tid}' not found in MITRE lookup file!"
                    assert len(lookup[tid]["technique_name"]) > 0


# =========================================================================
# 3. Truncated or short scenarios (< 8 stages or > 10 stages) are rejected
# =========================================================================
def test_truncated_or_short_scenario_rejected():
    base_stages = create_valid_dummy_stages()
    
    # Scenario with only 5 stages (too short)
    short_payload = {
        "title": "Short Scenario",
        "summary": "This scenario has only five stages and should be rejected.",
        "timeline": base_stages[:5]
    }
    with pytest.raises(ValidationError) as excinfo:
        LLMAttackScenarioPayload.model_validate(short_payload)
    err_str = str(excinfo.value).lower()
    assert "at least 8" in err_str or "too_short" in err_str or "between 8 and 10" in err_str

    # Scenario with 11 stages (too long)
    extra_stage = dict(base_stages[0])
    extra_stage["description"] = "Extra unique recon description for stage 9."
    extra_stage2 = dict(base_stages[0])
    extra_stage2["description"] = "Extra unique recon description for stage 10."
    extra_stage3 = dict(base_stages[0])
    extra_stage3["description"] = "Extra unique recon description for stage 11."
    
    long_payload = {
        "title": "Overly Long Scenario",
        "summary": "This scenario has eleven stages and should be rejected.",
        "timeline": base_stages + [extra_stage, extra_stage2, extra_stage3]
    }
    with pytest.raises(ValidationError) as excinfo:
        LLMAttackScenarioPayload.model_validate(long_payload)
    err_str = str(excinfo.value).lower()
    assert "at most 10" in err_str or "too_long" in err_str or "between 8 and 10" in err_str


# =========================================================================
# 4. Missing required tactics are rejected (Incomplete attack kill-chain)
# =========================================================================
def test_missing_required_tactic_rejected():
    # Missing Initial Access
    stages_no_initial_access = create_valid_dummy_stages()
    stages_no_initial_access[1]["tactic"] = "Reconnaissance"
    stages_no_initial_access[1]["techniques"] = [{"technique_id": "T1589.002", "technique_name": "Email Addresses"}]
    payload = {
        "title": "No Initial Access Scenario",
        "summary": "This scenario lacks an initial access stage.",
        "timeline": stages_no_initial_access
    }
    with pytest.raises(ValidationError) as excinfo:
        LLMAttackScenarioPayload.model_validate(payload)
    assert "Initial Access" in str(excinfo.value)


# =========================================================================
# 5. Scenario without Impact/Exfiltration final stage is rejected
# =========================================================================
def test_missing_impact_or_exfiltration_final_stage_rejected():
    stages_bad_final = create_valid_dummy_stages()
    # Replace final stage Impact with Command and Control (12), which follows Lateral Movement (10) but is NOT Impact/Exfiltration
    stages_bad_final[-1]["tactic"] = "Command and Control"
    stages_bad_final[-1]["techniques"] = [{"technique_id": "T1071.001", "technique_name": "Web Protocols"}]
    
    payload = {
        "title": "Bad Ending Scenario",
        "summary": "This scenario ends on C2 without Impact or Exfiltration.",
        "timeline": stages_bad_final
    }
    with pytest.raises(ValidationError) as excinfo:
        LLMAttackScenarioPayload.model_validate(payload)
    assert "Final stage must have tactic 'Impact' or 'Exfiltration'" in str(excinfo.value)


# =========================================================================
# 6. Unknown technique ID is rejected
# =========================================================================
def test_unknown_technique_id_rejected():
    with pytest.raises(ValidationError) as excinfo:
        Technique(technique_id="T9999", technique_name="Fake Non-Existent Technique")
    assert "Unknown or non-existent MITRE ATT&CK technique ID" in str(excinfo.value)

    with pytest.raises(ValidationError) as excinfo:
        Technique(technique_id="T1234.999", technique_name="Fictional Subtechnique")
    assert "Unknown or non-existent MITRE ATT&CK technique ID" in str(excinfo.value)


# =========================================================================
# 7. Known ID with wrong name gets its name corrected to official name
# =========================================================================
def test_known_technique_id_corrects_wrong_name():
    # Pass wrong/custom technique name for T1566.002 (Official: 'Spearphishing Link')
    t = Technique(technique_id="T1566.002", technique_name="Arbitrary Wrong Name From Model")
    assert t.technique_name == "Spearphishing Link"

    # Pass wrong name for T1059.001 (Official: 'PowerShell')
    t2 = Technique(technique_id="T1059.001", technique_name="Windows PowerShell Command Scripting Interpreter")
    assert t2.technique_name == "PowerShell"

    # Pass wrong name for T1486 (Official: 'Data Encrypted for Impact')
    t3 = Technique(technique_id="T1486", technique_name="Ransomware Disk Encryption")
    assert t3.technique_name == "Data Encrypted for Impact"


# =========================================================================
# 8. Malformed technique format is rejected (e.g. 'ABC', '1234')
# =========================================================================
def test_malformed_technique_format_rejected():
    with pytest.raises(ValidationError) as excinfo:
        Technique(technique_id="ABC", technique_name="Invalid Technique")
    assert "technique_id" in str(excinfo.value)

    with pytest.raises(ValidationError) as excinfo:
        Technique(technique_id="1234", technique_name="Missing T Prefix")
    assert "technique_id" in str(excinfo.value)


# =========================================================================
# 9. Invalid tactic is rejected
# =========================================================================
def test_invalid_tactic_rejected():
    with pytest.raises(ValidationError) as excinfo:
        LLMAttackStage(
            stage="Bad Stage",
            time="Day 0",
            description="Doing something malicious",
            impact="Bad impact",
            tactic="Unauthorized Hacking",  # Not in MITRE Enterprise tactics
            techniques=[Technique(technique_id="T1566.002", technique_name="Spearphishing Link")],
            detection_likelihood="Medium",
            detection_hint="Look at logs",
            mitigation="Block attacker"
        )
    assert "tactic" in str(excinfo.value)


# =========================================================================
# 10. Out-of-order kill chain is rejected
# =========================================================================
def test_out_of_order_kill_chain_rejected():
    stages = create_valid_dummy_stages()
    # Swap stage 0 (Reconnaissance, index 1) and stage 7 (Impact, index 14)
    stages[0], stages[7] = stages[7], stages[0]
    payload = {
        "title": "Broken Sequence Scenario",
        "summary": "This scenario has stages in the wrong chronological order.",
        "timeline": stages
    }
    with pytest.raises(ValidationError) as excinfo:
        LLMAttackScenarioPayload.model_validate(payload)
    assert "Tactics out of kill-chain order" in str(excinfo.value)


# =========================================================================
# 11. Duplicate stage descriptions are rejected
# =========================================================================
def test_duplicate_descriptions_rejected():
    stages = create_valid_dummy_stages()
    stages[1]["description"] = stages[0]["description"]  # Duplicate description
    payload = {
        "title": "Duplicate Description Scenario",
        "summary": "This scenario has repeated stage descriptions.",
        "timeline": stages
    }
    with pytest.raises(ValidationError) as excinfo:
        LLMAttackScenarioPayload.model_validate(payload)
    assert "Stages must not have duplicate descriptions" in str(excinfo.value)


# =========================================================================
# 12. Backward Compatibility: Old documents without new fields still load
# =========================================================================
def test_old_attack_scenario_documents_load():
    old_doc = {
        "id": "999e4567-e89b-12d3-a456-426614174999",
        "title": "Legacy Scenario Without MITRE Fields",
        "timeline": [
            {
                "stage": "Initial Access",
                "time": "Day 0",
                "description": "Phishing email received by employee.",
                "impact": "High - Undetected"
            },
            {
                "stage": "Execution",
                "time": "Day 1",
                "description": "Malware executed on workstation.",
                "impact": "High"
            }
        ],
        "created_at": datetime.now(timezone.utc)
    }
    model = AttackScenarioResponse.model_validate(old_doc)
    assert model.title == "Legacy Scenario Without MITRE Fields"
    assert model.summary is None
    assert len(model.timeline) == 2
    assert model.timeline[0]["stage"] == "Initial Access"
    assert "tactic" not in model.timeline[0]
    assert model.generation_source == "fallback"
    assert model.fallback_reason is None


# =========================================================================
# 13. Maturity rule holds for Low, Medium, and High
# =========================================================================
def test_maturity_detection_rules():
    # Low maturity: mostly "Low", at most one "Medium"
    low_levels = assign_detection_likelihoods("Low", 8)
    assert low_levels.count("Low") >= 7
    assert low_levels.count("Medium") <= 1
    assert low_levels.count("High") == 0

    # Medium maturity: mix of Low, Medium, and High
    med_levels = assign_detection_likelihoods("Medium", 8)
    assert "Low" in med_levels
    assert "Medium" in med_levels
    assert "High" in med_levels

    # High maturity: mostly "Medium" or "High", at most one "Low"
    high_levels = assign_detection_likelihoods("High", 8)
    assert high_levels.count("Low") <= 1
    assert (high_levels.count("Medium") + high_levels.count("High")) >= 7


# =========================================================================
# 14. API Endpoint POST /api/attack-scenario/generate
# =========================================================================
@pytest.mark.asyncio
async def test_api_generate_attack_scenario():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        res = await ac.post("/api/attack-scenario/generate", json={
            "organization_type": "Tech Startup",
            "security_maturity": "High"
        })
        assert res.status_code == 200
        data = res.json()
        assert "title" in data
        assert "summary" in data
        assert len(data["summary"]) >= 20
        assert "timeline" in data
        assert 8 <= len(data["timeline"]) <= 10
        first_stage = data["timeline"][0]
        assert "stage" in first_stage
        assert "time" in first_stage
        assert "impact" in first_stage
        assert "tactic" in first_stage
        assert "techniques" in first_stage
        assert "detection_likelihood" in first_stage
        assert "detection_hint" in first_stage
        assert "mitigation" in first_stage
