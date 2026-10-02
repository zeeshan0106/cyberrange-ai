"""
tests/test_ransomware.py
Phase 3 Ransomware Simulator – pytest test suite.

Covers:
- Fallback generator: validates for all attack vectors and org types
- Fallback: all technique IDs exist in MITRE_TECHNIQUES
- LLMRansomwareStep: rejects unknown technique ID
- LLMRansomwareStep: normalises technique name from MITRE lookup
- LLMRansomwareStep: strips 'Step N:' prefix from title / description
- LLMRansomwareStep: strips leading bullets from detection_hint / containment_action
- LLMRansomwarePayload: rejects scenario without T1486 Impact step
- LLMRansomwarePayload: rejects exfiltration step coming after encryption (double-extortion rule)
- LLMRansomwarePayload: rejects duplicate descriptions
- LLMRansomwarePayload: rejects missing required tactics
- LLMRansomwarePayload: rejects < 6 or > 8 steps
- ResponsePlan: strips leading bullets
- PreventionTip: strips leading bullets
- RansomwareResponse: legacy documents (no steps/response_plan/summary) load without error
- API endpoint: POST /api/ransomware/generate returns 200 with required fields
"""

import sys
import os
import copy
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

# ── make backend importable ──────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from server import (
    LLMRansomwareStep,
    LLMRansomwarePayload,
    ResponsePlan,
    PreventionTip,
    RansomwareResponse,
    fallback_generate_ransomware,
    MITRE_TECHNIQUES,
)
from pydantic import ValidationError

# ── helpers ──────────────────────────────────────────────────────────────────

def _make_valid_step(overrides: dict = None) -> dict:
    """Return a minimal valid step dict."""
    base = {
        "step_number": 1,
        "title": "Spearphishing Delivery",
        "description": "An employee receives a weaponized email attachment and opens it.",
        "tactic": "Initial Access",
        "technique_id": "T1566.001",
        "technique_name": "Spearphishing Attachment",
        "detection_hint": "Email gateway alert on macro-enabled attachment.",
        "containment_action": "Quarantine the email tenant-wide.",
    }
    if overrides:
        base.update(overrides)
    return base


def _make_valid_payload() -> dict:
    """
    Return a minimal valid 7-step LLMRansomwarePayload dict.

    Tactics covered (all required groups satisfied):
      Initial Access, Execution, Persistence, Discovery,
      Credential Access, Exfiltration, Impact (T1486)
    """
    steps = [
        {
            "step_number": 1,
            "title": "Spearphishing Email Delivery",
            "tactic": "Initial Access",
            "technique_id": "T1566.001",
            "technique_name": "Spearphishing Attachment",
            "description": "Attacker sends a targeted spearphishing email with a macro-enabled Office attachment to employees.",
            "detection_hint": "Email gateway alert on macro-enabled attachments from external senders.",
            "containment_action": "Quarantine the malicious email and block the sender domain tenant-wide.",
        },
        {
            "step_number": 2,
            "title": "VBA Macro Execution",
            "tactic": "Execution",
            "technique_id": "T1059.005",
            "technique_name": "Visual Basic",
            "description": "Victim enables macros in the malicious document, triggering a VBScript dropper that downloads secondary payloads.",
            "detection_hint": "Sysmon Event ID 1 showing excel.exe or winword.exe spawning powershell.exe.",
            "containment_action": "Isolate the infected endpoint from the network immediately.",
        },
        {
            "step_number": 3,
            "title": "Scheduled Task Persistence",
            "tactic": "Persistence",
            "technique_id": "T1053.005",
            "technique_name": "Scheduled Task",
            "description": "Ransomware payload registers a scheduled task disguised as a Windows system update to survive reboots.",
            "detection_hint": "Windows Event ID 4698 recording creation of a scheduled task pointing to AppData binaries.",
            "containment_action": "Delete the unauthorized scheduled task and revoke execution permissions in user directories.",
        },
        {
            "step_number": 4,
            "title": "Active Directory Domain Enumeration",
            "tactic": "Discovery",
            "technique_id": "T1087.002",
            "technique_name": "Domain Account",
            "description": "Attacker queries LDAP to enumerate domain controllers, administrative groups and high-value file servers.",
            "detection_hint": "SIEM alert on anomalous volume of LDAP queries originating from a standard workstation.",
            "containment_action": "Restrict LDAP queries from non-domain-controller hosts and lock compromised accounts.",
        },
        {
            "step_number": 5,
            "title": "LSASS Memory Credential Dumping",
            "tactic": "Credential Access",
            "technique_id": "T1003.001",
            "technique_name": "LSASS Memory",
            "description": "Attacker injects into the LSASS process to harvest plaintext domain credentials and Kerberos ticket hashes.",
            "detection_hint": "Windows Defender Credential Guard alert for unauthorized LSASS memory access by untrusted process.",
            "containment_action": "Force a domain-wide password reset for all harvested accounts and enable Credential Guard.",
        },
        {
            "step_number": 6,
            "title": "Cloud Storage Data Exfiltration",
            "tactic": "Exfiltration",
            "technique_id": "T1567.002",
            "technique_name": "Exfiltration to Cloud Storage",
            "description": "Sensitive customer records and financial databases are compressed and uploaded to an attacker-controlled cloud drop zone.",
            "detection_hint": "Firewall and proxy logs showing high-volume encrypted outbound uploads to external cloud storage endpoints.",
            "containment_action": "Block the exfiltration destination domain at the perimeter firewall and revoke exposed API credentials.",
        },
        {
            "step_number": 7,
            "title": "AES-256 Ransomware File Encryption",
            "tactic": "Impact",
            "technique_id": "T1486",
            "technique_name": "Data Encrypted for Impact",
            "description": "Ransomware payload executes multi-threaded AES-256 encryption across all locally mapped and network-shared drives.",
            "detection_hint": "Mass file renaming alerts and sudden spike in storage I/O throughput detected across file servers.",
            "containment_action": "Disconnect all storage appliances from the network and initiate restore from offline immutable backups.",
        },
    ]

    return {
        "summary": (
            "Threat actors deliver a ransomware payload via a spearphishing email with a macro-enabled attachment. "
            "After gaining execution and persistence, they harvest domain credentials via LSASS dumping, exfiltrate "
            "sensitive customer records to cloud storage, then deploy AES-256 encryption across all drives in a "
            "double-extortion campaign."
        ),
        "steps": steps,
        "response_plan": {
            "immediate_actions": [
                "Isolate infected endpoints and disconnect all network shares",
                "Revoke compromised Active Directory credentials and force domain-wide session resets",
                "Block C2 command domains and cloud exfiltration IPs at the perimeter firewall",
            ],
            "recovery_steps": [
                "Validate the integrity of air-gapped immutable backups before initiating restoration",
                "Reimage all affected systems from verified clean baseline OS images",
                "Restore encrypted databases and file shares into clean, segmented recovery networks",
            ],
            "lessons_learned": [
                "Enforce Attack Surface Reduction rules blocking Office apps from spawning child processes",
                "Implement strict egress filtering to prevent unapproved cloud storage uploads",
                "Conduct regular phishing simulation drills focused on macro and attachment awareness",
            ],
        },
        "prevention_tips": [
            {"text": "Block macro execution in Office documents received from the internet via Group Policy.", "addresses_step": 1},
            {"text": "Deploy PowerShell Constrained Language Mode and enforce Application Control policies.", "addresses_step": 2},
            {"text": "Maintain offline immutable 3-2-1 backup copies to mitigate ransomware impact.", "addresses_step": 7},
        ],
    }


# ── Fallback generator tests ─────────────────────────────────────────────────

VECTORS_AND_ORGS = [
    ("Email", "IT Company"),
    ("USB", "Healthcare"),
    ("RDP", "Financial"),
    ("Malicious Link", "Education"),
    ("Supply Chain", "Government"),  # unknown → falls back to email pool
]


@pytest.mark.parametrize("vector,org", VECTORS_AND_ORGS)
def test_fallback_generates_valid_structure(vector, org):
    """Fallback generator produces expected top-level keys for every vector+org combo."""
    data = fallback_generate_ransomware(vector, org)
    assert "summary" in data and isinstance(data["summary"], str) and len(data["summary"]) >= 20
    assert "infection_flow" in data and len(data["infection_flow"]) >= 6
    assert "mitre_mapping" in data and len(data["mitre_mapping"]) >= 1
    assert "steps" in data and len(data["steps"]) >= 6
    assert "response_plan" in data
    assert "prevention_tips" in data and len(data["prevention_tips"]) >= 3


@pytest.mark.parametrize("vector,org", VECTORS_AND_ORGS)
def test_fallback_technique_ids_exist_in_mitre(vector, org):
    """Every technique_id in the fallback steps must be a known MITRE ATT&CK technique."""
    if not MITRE_TECHNIQUES:
        pytest.skip("MITRE_TECHNIQUES lookup not loaded – skipping ID validation")
    data = fallback_generate_ransomware(vector, org)
    for step in data["steps"]:
        tid = step["technique_id"]
        assert tid in MITRE_TECHNIQUES, (
            f"Vector={vector!r}: technique_id {tid!r} not in MITRE lookup"
        )


@pytest.mark.parametrize("vector,org", VECTORS_AND_ORGS)
def test_fallback_contains_t1486_impact_step(vector, org):
    """Fallback must include T1486 in the final or near-final step."""
    data = fallback_generate_ransomware(vector, org)
    technique_ids = [s["technique_id"] for s in data["steps"]]
    assert "T1486" in technique_ids, f"Vector={vector!r}: T1486 not found in fallback steps"
    # T1486 should be in the last two steps
    assert "T1486" in technique_ids[-2:], (
        f"Vector={vector!r}: T1486 is not in the last two steps"
    )


@pytest.mark.parametrize("vector,org", VECTORS_AND_ORGS)
def test_fallback_exfiltration_before_encryption(vector, org):
    """Exfiltration step must precede T1486 encryption in double-extortion fallbacks."""
    data = fallback_generate_ransomware(vector, org)
    steps = data["steps"]
    technique_ids = [s["technique_id"] for s in steps]
    tactics = [s["tactic"] for s in steps]

    if "T1486" not in technique_ids:
        return  # nothing to check

    t1486_index = technique_ids.index("T1486")
    for idx, tactic in enumerate(tactics):
        if tactic == "Exfiltration":
            assert idx < t1486_index, (
                f"Vector={vector!r}: Exfiltration step (idx={idx}) is after T1486 (idx={t1486_index})"
            )


# ── LLMRansomwareStep validation tests ───────────────────────────────────────

def test_step_rejects_unknown_technique_id():
    """A step with an unknown technique ID must raise ValidationError."""
    if not MITRE_TECHNIQUES:
        pytest.skip("MITRE_TECHNIQUES lookup not loaded")
    bad = _make_valid_step({"technique_id": "T9999"})
    with pytest.raises(ValidationError, match="Unknown or non-existent MITRE"):
        LLMRansomwareStep(**bad)


def test_step_normalises_technique_name_from_lookup():
    """The technique_name must be overwritten with the official MITRE name."""
    if not MITRE_TECHNIQUES:
        pytest.skip("MITRE_TECHNIQUES lookup not loaded")
    step = LLMRansomwareStep(**_make_valid_step({
        "technique_id": "T1566.001",
        "technique_name": "Some Wrong Name"
    }))
    official = MITRE_TECHNIQUES["T1566.001"]["technique_name"]
    assert step.technique_name == official


def test_step_strips_step_prefix_from_title():
    """'Step 1: Title' should be cleaned to 'Title'."""
    step = LLMRansomwareStep(**_make_valid_step({"title": "Step 1: Spearphishing Delivery"}))
    assert not step.title.lower().startswith("step")


def test_step_strips_step_prefix_from_description():
    """'Step 2 - Description.' should be cleaned."""
    step = LLMRansomwareStep(**_make_valid_step({
        "description": "Step 2 - An employee opens the malicious attachment."
    }))
    assert not step.description.lower().startswith("step")


def test_step_strips_leading_bullet_from_detection_hint():
    """'* Monitor email logs' → 'Monitor email logs'."""
    step = LLMRansomwareStep(**_make_valid_step({"detection_hint": "* Monitor email gateway logs."}))
    assert not step.detection_hint.startswith("*")


def test_step_strips_leading_bullet_from_containment_action():
    """'- Isolate the host' → 'Isolate the host'."""
    step = LLMRansomwareStep(**_make_valid_step({"containment_action": "- Isolate the infected host."}))
    assert not step.containment_action.startswith("-")


# ── ResponsePlan validation tests ────────────────────────────────────────────

def test_response_plan_strips_bullets():
    plan = ResponsePlan(**{
        "immediate_actions": ["* Isolate endpoints", "- Reset credentials", "Block C2"],
        "recovery_steps": ["* Validate backups", "Reimage systems", "- Restore files"],
        "lessons_learned": ["- Enforce ASR", "Run drills", "* Update policies"],
    })
    for item in plan.immediate_actions + plan.recovery_steps + plan.lessons_learned:
        assert not item.startswith("*") and not item.startswith("-")


def test_response_plan_requires_minimum_items():
    with pytest.raises(ValidationError):
        ResponsePlan(**{
            "immediate_actions": ["Only one action"],  # < 3
            "recovery_steps": ["Step A", "Step B", "Step C"],
            "lessons_learned": ["Lesson 1", "Lesson 2", "Lesson 3"],
        })


# ── PreventionTip validation tests ───────────────────────────────────────────

def test_prevention_tip_strips_bullet():
    tip = PreventionTip(text="* Block macro execution.", addresses_step=1)
    assert not tip.text.startswith("*")


# ── LLMRansomwarePayload validation tests ────────────────────────────────────

def test_payload_accepts_valid_scenario():
    """A fully valid 7-step payload should parse without error."""
    LLMRansomwarePayload(**_make_valid_payload())


def test_payload_rejects_too_few_steps():
    data = _make_valid_payload()
    data["steps"] = data["steps"][:4]  # only 4 steps – below minimum 6
    with pytest.raises(ValidationError):
        LLMRansomwarePayload(**data)


def test_payload_rejects_too_many_steps():
    """9-step scenario should be rejected (max is 8)."""
    data = _make_valid_payload()
    # We already have 7 steps; add 2 more to get 9 (> 8 max)
    extra_base = {
        "title": "Lateral Movement Step",
        "tactic": "Lateral Movement",
        "technique_id": "T1021.001",
        "technique_name": "Remote Desktop Protocol",
        "detection_hint": "RDP logon event between server subnets during unusual hours.",
        "containment_action": "Disable internal RDP routing and require jump hosts.",
    }
    for i in range(2):
        s = dict(extra_base)
        s["step_number"] = len(data["steps"]) + 1
        s["description"] = f"Attacker pivots laterally to server {i + 1} via RDP using compromised administrator credentials."
        data["steps"].append(s)

    with pytest.raises(ValidationError):
        LLMRansomwarePayload(**data)


def test_payload_rejects_missing_t1486():
    """Scenario where T1486 is replaced with another Impact technique should be rejected."""
    data = _make_valid_payload()
    # Replace T1486 with T1531 (Account Access Removal) — valid MITRE ID, not T1486
    for s in data["steps"]:
        if s["technique_id"] == "T1486":
            s["technique_id"] = "T1531"
            s["technique_name"] = "Account Access Removal"
            s["tactic"] = "Impact"
    with pytest.raises(ValidationError, match="T1486"):
        LLMRansomwarePayload(**data)


def test_payload_rejects_missing_initial_access():
    data = _make_valid_payload()
    for s in data["steps"]:
        if s["tactic"] == "Initial Access":
            s["tactic"] = "Persistence"
    with pytest.raises(ValidationError, match="Initial Access"):
        LLMRansomwarePayload(**data)


def test_payload_rejects_missing_execution():
    data = _make_valid_payload()
    for s in data["steps"]:
        if s["tactic"] == "Execution":
            s["tactic"] = "Persistence"
    with pytest.raises(ValidationError, match="Execution"):
        LLMRansomwarePayload(**data)


def test_payload_rejects_duplicate_descriptions():
    data = _make_valid_payload()
    data["steps"][1]["description"] = data["steps"][0]["description"]
    with pytest.raises(ValidationError, match="duplicate"):
        LLMRansomwarePayload(**data)


def test_payload_rejects_exfiltration_after_encryption():
    """
    Build a 7-step scenario where the Exfiltration step is placed AFTER T1486.
    The validator's double-extortion check must reject this.
    We must put T1486 at step 6 and an Exfiltration step at step 7.
    """
    data = _make_valid_payload()
    steps = copy.deepcopy(data["steps"])

    # Rebuild step ordering: put T1486 at position 5 (0-indexed), exfiltration at position 6
    # Original order: 0=IA, 1=Exec, 2=Persist, 3=Discovery, 4=CredAccess, 5=Exfil, 6=Impact
    # New order:      0=IA, 1=Exec, 2=Persist, 3=Discovery, 4=CredAccess, 5=Impact, 6=Exfil
    # Swap steps at index 5 and 6
    steps[5], steps[6] = steps[6], steps[5]
    # Re-number so validation sees sequential step_numbers
    for i, s in enumerate(steps, start=1):
        s["step_number"] = i

    data["steps"] = steps

    with pytest.raises(ValidationError, match="[Ee]xfiltration"):
        LLMRansomwarePayload(**data)


# ── RansomwareResponse (legacy compat) tests ─────────────────────────────────

def test_legacy_response_loads_without_new_fields():
    """
    Old MongoDB documents that have infection_flow + mitre_mapping + prevention_tips
    (as plain strings) but lack steps, response_plan, and summary should load
    without a ValidationError.
    """
    legacy_doc = {
        "id": "test-legacy-id",
        "attack_vector": "Email",
        "infection_flow": [
            "Step 1: Employee opens malicious attachment.",
            "Step 2: Payload executes and establishes persistence.",
            "Step 3: Ransomware encrypts all files.",
        ],
        "mitre_mapping": [
            {"id": "T1566.001", "name": "Spearphishing Attachment"},
            {"id": "T1486", "name": "Data Encrypted for Impact"},
        ],
        "prevention_tips": [
            "Block macros in Office documents.",
            "Maintain offline backups.",
        ],
        "generation_source": "fallback",
        "fallback_reason": "no_api_key",
    }
    resp = RansomwareResponse(**legacy_doc)
    assert resp.attack_vector == "Email"
    assert resp.steps is None
    assert resp.response_plan is None
    assert resp.summary is None


def test_new_response_loads_with_all_fields():
    """A fully-populated response (from fallback path) should parse cleanly."""
    data = fallback_generate_ransomware("Email", "IT Company")
    resp = RansomwareResponse(
        attack_vector="Email",
        summary=data["summary"],
        infection_flow=data["infection_flow"],
        mitre_mapping=data["mitre_mapping"],
        steps=data["steps"],
        response_plan=data["response_plan"],
        prevention_tips=data["prevention_tips"],
        generation_source="fallback",
    )
    assert resp.steps is not None and len(resp.steps) >= 6
    assert resp.response_plan is not None
    assert resp.summary is not None


# ── API endpoint tests ────────────────────────────────────────────────────────

@pytest.fixture
def client():
    """
    Create a TestClient for the FastAPI app with MongoDB insert mocked out
    so tests do not require a running database.
    """
    from fastapi.testclient import TestClient
    import server

    mock_collection = MagicMock()
    mock_collection.insert_one = AsyncMock(return_value=MagicMock(inserted_id="test-id"))

    mock_db = MagicMock()
    mock_db.ransomware_simulations = mock_collection
    mock_db.phishing_simulations = mock_collection
    mock_db.attack_scenarios = mock_collection

    with patch.object(server, "db", mock_db):
        yield TestClient(server.app)


def test_api_ransomware_generate_returns_200(client):
    """POST /api/ransomware/generate should return HTTP 200."""
    response = client.post("/api/ransomware/generate", json={
        "attack_vector": "Email",
        "organization_type": "IT Company"
    })
    assert response.status_code == 200


def test_api_ransomware_generate_response_has_required_fields(client):
    """Response body must contain the Phase 3 fields."""
    response = client.post("/api/ransomware/generate", json={
        "attack_vector": "USB",
        "organization_type": "Healthcare"
    })
    assert response.status_code == 200
    body = response.json()
    assert "attack_vector" in body
    assert "infection_flow" in body
    assert "mitre_mapping" in body
    assert "prevention_tips" in body
    assert "generation_source" in body


def test_api_ransomware_generate_usb_vector(client):
    """USB vector should produce a valid scenario."""
    response = client.post("/api/ransomware/generate", json={
        "attack_vector": "USB",
        "organization_type": "Financial"
    })
    assert response.status_code == 200
    body = response.json()
    assert body["attack_vector"] == "USB"


def test_api_ransomware_generate_rdp_vector(client):
    """RDP vector should produce a valid scenario."""
    response = client.post("/api/ransomware/generate", json={
        "attack_vector": "RDP",
        "organization_type": "Education"
    })
    assert response.status_code == 200


def test_api_ransomware_generate_malicious_link_vector(client):
    """Malicious Link vector should produce a valid scenario."""
    response = client.post("/api/ransomware/generate", json={
        "attack_vector": "Malicious Link",
        "organization_type": "IT Company"
    })
    assert response.status_code == 200


def test_api_ransomware_generate_source_field(client):
    """generation_source must be 'llm' or 'fallback'."""
    response = client.post("/api/ransomware/generate", json={
        "attack_vector": "Email",
        "organization_type": "IT Company"
    })
    assert response.status_code == 200
    body = response.json()
    assert body["generation_source"] in ("llm", "fallback")
