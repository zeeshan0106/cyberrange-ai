"""
tests/test_phishing.py
Phase 4 Phishing Simulator – pytest test suite.

Covers:
- Fallback generator: validates for all role x difficulty x industry combinations
- Fallback: evidence strings in all red flags appear in the email content
- Fallback: red flag counts match difficulty rules (Easy: 4-5, Medium: 3-4, Hard/Advanced: 2-3)
- Fallback: sender email, reply-to, and links use reserved .example / .test domains
- Fallback: two consecutive generations for the same role with distinct templates are not identical
- LLMPhishingPayload: rejects red flag with evidence not found in email content
- LLMPhishingPayload: rejects domains that do not end in .example or .test
- LLMPhishingPayload: rejects inconsistent header analysis (SPF fail + DKIM fail + DMARC pass)
- LLMPhishingPayload: enforces difficulty-specific red flag counts
- PhishingResponse: legacy documents (without new fields and with string red flags) load cleanly
- API endpoint: POST /api/phishing/generate returns 200 with all Phase 4 fields
"""

import sys
import os
import copy
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

# ── make backend importable ──────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from server import (
    RedFlagItem,
    HeaderAnalysis,
    PsychologicalTrigger,
    LLMPhishingPayload,
    PhishingResponse,
    fallback_generate_phishing,
)
from pydantic import ValidationError

# ── helper test payload generator ────────────────────────────────────────────

def _make_valid_phishing_payload() -> dict:
    """Return a minimal valid LLMPhishingPayload dict for testing."""
    body = (
        "Dear Alex Rivera,\n\n"
        "Your corporate single sign-on credentials will expire in 12 hours. "
        "To maintain continuous access to your IT workspace, you must keep your current password now.\n\n"
        "Keep Current Password: https://identity-portal.internal-auth.example/keep-pwd\n\n"
        "Accounts that expire will require in-person identity verification at the helpdesk.\n\n"
        "Global Identity Team"
    )
    return {
        "subject": "Security Alert: Single Sign-On Password Expiration",
        "sender_name": "IT Identity Security",
        "sender_email": "security@internal-auth.example",
        "reply_to_email": "security@internal-auth.example",
        "recipient_name": "Alex Rivera",
        "date_sent": "Oct 02, 2026, 09:00 AM",
        "body": body,
        "link_display_text": "https://identity-portal.internal-auth.example/keep-pwd",
        "link_url": "http://auth-login-verify.test/login",
        "header_analysis": {
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "none",
            "notes": "Domain authentication passed on lookalike infrastructure."
        },
        "red_flags": [
            {
                "flag": "Lookalike Sender Domain",
                "evidence": "security@internal-auth.example",
                "explanation": "The email originates from an external lookalike domain."
            },
            {
                "flag": "Short Expiration Pressure",
                "evidence": "expire in 12 hours",
                "explanation": "Artificial urgency pushes victims into clicking without verification."
            },
            {
                "flag": "Inconvenience Threat",
                "evidence": "in-person identity verification",
                "explanation": "Threatening procedural burden induces compliance."
            }
        ],
        "psychological_triggers": [
            {"trigger": "Urgency", "where_used": "expire in 12 hours"},
            {"trigger": "Authority", "where_used": "Global Identity Team"}
        ],
        "safe_response": [
            "Do not click the password reset link.",
            "Verify password status directly in corporate system settings.",
            "Report the email to IT security operations."
        ],
        "analysis": "This email simulates an IT password expiration lure using urgency.",
        "difficulty": "Medium"
    }


# ── Fallback generator parameterized tests ───────────────────────────────────

ROLES = ["Employee", "HR", "Finance", "Student", "Admin"]
DIFFICULTIES = ["Easy", "Medium", "Advanced"]
INDUSTRIES = ["IT", "Banking", "Healthcare", "Education"]

@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("difficulty", DIFFICULTIES)
@pytest.mark.parametrize("industry", INDUSTRIES)
def test_fallback_generates_valid_structure_for_all_combinations(role, difficulty, industry):
    """Fallback generator produces all required fields for every role x difficulty x industry."""
    data = fallback_generate_phishing(role, difficulty, industry)
    
    assert "subject" in data and len(data["subject"]) > 5
    assert "sender_name" in data and len(data["sender_name"]) > 0
    assert "sender_email" in data and "@" in data["sender_email"]
    assert "reply_to_email" in data and "@" in data["reply_to_email"]
    assert "recipient_name" in data and len(data["recipient_name"]) > 0
    assert "date_sent" in data
    assert "body" in data and len(data["body"]) > 30
    assert "header_analysis" in data
    assert "red_flags" in data and len(data["red_flags"]) >= 2
    assert "psychological_triggers" in data and len(data["psychological_triggers"]) >= 1
    assert "safe_response" in data and len(data["safe_response"]) == 3
    assert "analysis" in data and len(data["analysis"]) > 10


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("difficulty", DIFFICULTIES)
def test_fallback_evidence_strings_appear_in_email(role, difficulty):
    """Every red flag evidence string must be an exact substring of the generated email."""
    data = fallback_generate_phishing(role, difficulty, "IT")
    
    searchable_content = " ".join([
        data["subject"],
        data["sender_name"],
        data["sender_email"],
        data["reply_to_email"],
        data["recipient_name"],
        data["body"],
        data.get("link_display_text") or "",
        data.get("link_url") or ""
    ]).lower()
    
    for rf in data["red_flags"]:
        evidence = rf["evidence"].strip().lower()
        assert evidence in searchable_content, (
            f"Role={role}, Difficulty={difficulty}: Red flag evidence '{rf['evidence']}' "
            f"not found in email content"
        )


@pytest.mark.parametrize("difficulty,min_flags,max_flags", [
    ("Easy", 4, 5),
    ("Medium", 3, 4),
    ("Advanced", 2, 3),
])
def test_fallback_red_flag_counts_match_difficulty(difficulty, min_flags, max_flags):
    """Red flag counts must respect the difficulty rule."""
    for role in ROLES:
        data = fallback_generate_phishing(role, difficulty, "Banking")
        count = len(data["red_flags"])
        assert min_flags <= count <= max_flags, (
            f"Role={role}, Difficulty={difficulty}: Expected {min_flags}-{max_flags} flags, got {count}"
        )


@pytest.mark.parametrize("role", ROLES)
def test_fallback_domains_use_reserved_tlds(role):
    """All generated email addresses and links must end in .example or .test."""
    data = fallback_generate_phishing(role, "Medium", "Healthcare")
    
    sender_domain = data["sender_email"].split("@")[-1].lower()
    reply_domain = data["reply_to_email"].split("@")[-1].lower()
    
    assert sender_domain.endswith(".example") or sender_domain.endswith(".test"), (
        f"Sender domain '{sender_domain}' is not .example or .test"
    )
    assert reply_domain.endswith(".example") or reply_domain.endswith(".test"), (
        f"Reply-to domain '{reply_domain}' is not .example or .test"
    )
    if data.get("link_url"):
        assert ".example" in data["link_url"].lower() or ".test" in data["link_url"].lower(), (
            f"Link URL '{data['link_url']}' does not use .example or .test"
        )


def test_fallback_generates_distinct_templates():
    """Generating multiple simulations for the same role should produce distinct templates."""
    results = [fallback_generate_phishing("Finance", "Medium", "IT") for _ in range(10)]
    subjects = {r["subject"] for r in results}
    # With 2 distinct templates, we expect at least 2 distinct subjects in 10 draws
    assert len(subjects) >= 2, "Fallback should produce different templates across calls"


# ── LLMPhishingPayload validation tests ──────────────────────────────────────

def test_payload_accepts_valid_data():
    """A valid phishing payload should validate cleanly."""
    LLMPhishingPayload(**_make_valid_phishing_payload())


def test_payload_rejects_evidence_not_in_email():
    """If a red flag's evidence string does not appear in the email, reject with ValidationError."""
    data = _make_valid_phishing_payload()
    data["red_flags"].append({
        "flag": "Non-existent Flag",
        "evidence": "this phrase is definitely not in the email anywhere 12345",
        "explanation": "Explaining a flag that has no evidence."
    })
    with pytest.raises(ValidationError, match="not found in the email content"):
        LLMPhishingPayload(**data)


def test_payload_rejects_non_reserved_sender_domain():
    """Sender email with a real domain (e.g., .com, .org) must be rejected for safety."""
    data = _make_valid_phishing_payload()
    data["sender_email"] = "security@real-corporate-domain.com"
    with pytest.raises(ValidationError, match="reserved fictional domain"):
        LLMPhishingPayload(**data)


def test_payload_rejects_non_reserved_link_url():
    """Link URL with a non-reserved domain must be rejected."""
    data = _make_valid_phishing_payload()
    data["link_url"] = "http://malicious-phishing-login.com/auth"
    with pytest.raises(ValidationError, match="host must end in .example or .test"):
        LLMPhishingPayload(**data)


def test_payload_rejects_inconsistent_headers():
    """If SPF and DKIM fail, DMARC cannot be 'pass'."""
    data = _make_valid_phishing_payload()
    data["header_analysis"] = {
        "spf": "fail",
        "dkim": "fail",
        "dmarc": "pass",
        "notes": "Inconsistent header analysis."
    }
    with pytest.raises(ValidationError, match="Inconsistent headers"):
        LLMPhishingPayload(**data)


def test_payload_enforces_difficulty_flag_count():
    """Easy difficulty must reject < 4 flags."""
    data = _make_valid_phishing_payload()
    data["difficulty"] = "Easy"
    data["red_flags"] = data["red_flags"][:2]  # Only 2 flags, easy requires 4-5
    with pytest.raises(ValidationError, match="Easy difficulty requires 4-5"):
        LLMPhishingPayload(**data)


def test_payload_rejects_missing_sender_flag():
    """Payload must reject when none of the red flags concern the sender domain or address."""
    data = _make_valid_phishing_payload()
    data["red_flags"] = [
        {"flag": "Short Expiration Pressure", "evidence": "expire in 12 hours", "explanation": "Urgency pressure."},
        {"flag": "Inconvenience Threat", "evidence": "in-person identity verification", "explanation": "Threatening procedural burden."}
    ]
    with pytest.raises(ValidationError, match="At least one red flag must concern the sender address"):
        LLMPhishingPayload(**data)


def test_payload_rejects_missing_recipient_greeting():
    """Payload must reject when greeting fails to address recipient_name in non-mass notice."""
    data = _make_valid_phishing_payload()
    data["recipient_name"] = "Dr. Zachary Williams"
    data["body"] = (
        "Dear Random Person,\n\n"
        "Your account at security@internal-auth.example will expire in 12 hours. "
        "Keep your current password now.\n\n"
        "Accounts that expire will require in-person identity verification at the helpdesk.\n\n"
        "IT Team"
    )
    with pytest.raises(ValidationError, match="The email greeting must address recipient_name"):
        LLMPhishingPayload(**data)


def test_payload_rejects_subpath_domain_deception():
    """Link with .example in path but .com in host must be rejected."""
    data = _make_valid_phishing_payload()
    data["link_url"] = "http://evil-attacker-server.com/portal.example"
    with pytest.raises(ValidationError, match="host must end in .example or .test"):
        LLMPhishingPayload(**data)


# ── PhishingResponse backward compatibility tests ────────────────────────────

def test_legacy_response_loads_without_new_fields():
    """Old MongoDB records (plain string red_flags, no sender/link fields) must load cleanly."""
    legacy_doc = {
        "id": "legacy-phish-id-001",
        "subject": "Urgent: Account Verification Required",
        "body": "Hello, please verify your account by clicking here.",
        "red_flags": ["Generic greeting", "Urgency", "Suspicious link"],
        "analysis": "This is a basic legacy simulation email.",
        "generation_source": "fallback",
        "fallback_reason": "no_api_key",
    }
    resp = PhishingResponse(**legacy_doc)
    assert resp.subject == "Urgent: Account Verification Required"
    assert resp.sender_name is None
    assert resp.sender_email is None
    assert resp.header_analysis is None
    assert isinstance(resp.red_flags, list)
    assert len(resp.red_flags) == 3


def test_new_response_loads_with_all_fields():
    """A fully-populated Phase 4 response should parse cleanly."""
    data = fallback_generate_phishing("HR", "Medium", "Education")
    resp = PhishingResponse(
        subject=data["subject"],
        sender_name=data["sender_name"],
        sender_email=data["sender_email"],
        reply_to_email=data["reply_to_email"],
        recipient_name=data["recipient_name"],
        date_sent=data["date_sent"],
        body=data["body"],
        link_display_text=data["link_display_text"],
        link_url=data["link_url"],
        header_analysis=data["header_analysis"],
        red_flags=data["red_flags"],
        psychological_triggers=data["psychological_triggers"],
        safe_response=data["safe_response"],
        analysis=data["analysis"],
        generation_source="fallback"
    )
    assert resp.sender_name is not None
    assert resp.sender_email is not None
    assert resp.header_analysis is not None
    assert resp.safe_response is not None and len(resp.safe_response) == 3


# ── API endpoint tests ────────────────────────────────────────────────────────

@pytest.fixture
def client():
    """TestClient with database insert mocked to prevent event loop issues."""
    from fastapi.testclient import TestClient
    import server

    mock_collection = MagicMock()
    mock_collection.insert_one = AsyncMock(return_value=MagicMock(inserted_id="test-id"))

    mock_db = MagicMock()
    mock_db.phishing_simulations = mock_collection
    mock_db.ransomware_simulations = mock_collection
    mock_db.attack_scenarios = mock_collection

    with patch.object(server, "db", mock_db):
        yield TestClient(server.app)


def test_api_phishing_generate_returns_200(client):
    """POST /api/phishing/generate returns 200 with all Phase 4 fields."""
    response = client.post("/api/phishing/generate", json={
        "target_role": "Finance",
        "difficulty": "Medium",
        "industry": "Banking"
    })
    assert response.status_code == 200
    body = response.json()
    assert "subject" in body
    assert "body" in body
    assert "sender_name" in body
    assert "sender_email" in body
    assert "header_analysis" in body
    assert "red_flags" in body
    assert "safe_response" in body
    assert "generation_source" in body


@pytest.mark.parametrize("role", ROLES)
def test_api_phishing_generate_all_roles(client, role):
    """All roles return 200 via the API."""
    response = client.post("/api/phishing/generate", json={
        "target_role": role,
        "difficulty": "Easy",
        "industry": "IT"
    })
    assert response.status_code == 200
    body = response.json()
    assert len(body["red_flags"]) >= 2
