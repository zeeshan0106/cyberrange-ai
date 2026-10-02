import pytest
import asyncio
from unittest.mock import patch, AsyncMock
from httpx import AsyncClient, ASGITransport
from datetime import datetime, timezone

from backend.server import (
    app,
    PhishingResponse,
    RansomwareResponse,
    AttackScenarioResponse,
    TrainingQuestionResponse
)
from backend.config import settings
from backend.llm_service import sanitize_llm_error


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def mock_db():
    """Mock MongoDB database operations so tests run in memory without live DB dependencies."""
    with patch("backend.server.db") as mock_database:
        mock_database.phishing_simulations.insert_one = AsyncMock(return_value=None)
        mock_database.ransomware_simulations.insert_one = AsyncMock(return_value=None)
        mock_database.attack_scenarios.insert_one = AsyncMock(return_value=None)
        mock_database.training_questions.insert_one = AsyncMock(return_value=None)
        mock_database.training_scores.insert_one = AsyncMock(return_value=None)
        yield mock_database


# =========================================================================
# 1. TEST: No API Key -> generation_source: "fallback", fallback_reason: "no_api_key"
# =========================================================================
@pytest.mark.asyncio
async def test_fallback_when_no_api_key():
    with patch.object(settings, "LLM_API_KEY", None):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.post("/api/phishing/generate", json={
                "target_role": "Employee",
                "difficulty": "Medium",
                "industry": "IT"
            })
            assert res.status_code == 200
            data = res.json()
            assert data["generation_source"] == "fallback"
            assert data["fallback_reason"] == "no_api_key"
            assert "subject" in data
            assert len(data["red_flags"]) > 0


# =========================================================================
# 2. TEST: Timeout -> generation_source: "fallback", fallback_reason: "timeout"
# =========================================================================
@pytest.mark.asyncio
async def test_fallback_when_timeout():
    async def slow_call(*args, **kwargs):
        raise asyncio.TimeoutError()

    with patch.object(settings, "LLM_API_KEY", "sk-mock-key"), \
         patch("backend.llm_service.acompletion", side_effect=slow_call):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.post("/api/ransomware/generate", json={
                "attack_vector": "Email",
                "organization_type": "Healthcare"
            })
            assert res.status_code == 200
            data = res.json()
            assert data["generation_source"] == "fallback"
            assert data["fallback_reason"] == "timeout"
            assert len(data["infection_flow"]) > 0


# =========================================================================
# 3. TEST: Invalid JSON -> retry once, then fallback with reason: "invalid_output"
# =========================================================================
@pytest.mark.asyncio
async def test_fallback_when_invalid_json_with_retry():
    mock_response = AsyncMock()
    mock_choice = AsyncMock()
    mock_choice.message.content = "This is not JSON at all! Just raw plain text."
    mock_response.choices = [mock_choice]

    mock_acompletion = AsyncMock(return_value=mock_response)

    with patch.object(settings, "LLM_API_KEY", "sk-mock-key"), \
         patch.object(settings, "LLM_MAX_RETRIES", 1), \
         patch("backend.llm_service.acompletion", mock_acompletion):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.post("/api/attack-scenario/generate", json={
                "organization_type": "Financial",
                "security_maturity": "High"
            })
            assert res.status_code == 200
            data = res.json()
            assert mock_acompletion.call_count == 2
            assert data["generation_source"] == "fallback"
            assert data["fallback_reason"] == "invalid_output"
            assert "title" in data
            assert len(data["timeline"]) > 0


# =========================================================================
# 4. TEST: Successful Mocked LLM Call -> generation_source: "llm", fallback_reason: None
# =========================================================================
@pytest.mark.asyncio
async def test_successful_llm_call():
    llm_json_output = (
        '{\n'
        '  "subject": "Urgent: Mandatory IT Security Update",\n'
        '  "sender_name": "IT Support Desk",\n'
        '  "sender_email": "support@security-update.example",\n'
        '  "reply_to_email": "support@security-update.example",\n'
        '  "recipient_name": "Jordan Taylor",\n'
        '  "date_sent": "Oct 02, 2026, 09:00 AM",\n'
        '  "body": "Dear Jordan Taylor,\\nPlease install the urgent security patch immediately.\\nIT Support",\n'
        '  "link_display_text": "https://patch.security-update.example/install",\n'
        '  "link_url": "http://patch-installer.test/download",\n'
        '  "header_analysis": {\n'
        '    "spf": "pass",\n'
        '    "dkim": "pass",\n'
        '    "dmarc": "none",\n'
        '    "notes": "Passed authentication on lookalike domain."\n'
        '  },\n'
        '  "red_flags": [\n'
        '    {"flag": "Urgent Coercion", "evidence": "urgent security patch immediately", "explanation": "Urgent tone creates panic."},\n'
        '    {"flag": "Lookalike Domain", "evidence": "support@security-update.example", "explanation": "Sender is an unverified external domain."}\n'
        '  ],\n'
        '  "psychological_triggers": [\n'
        '    {"trigger": "Urgency", "where_used": "urgent security patch immediately"}\n'
        '  ],\n'
        '  "safe_response": [\n'
        '    "Do not click the download link.",\n'
        '    "Verify patch status with IT helpdesk.",\n'
        '    "Report the email to security."\n'
        '  ],\n'
        '  "analysis": "Simulated spear-phishing attack attempting executable delivery."\n'
        '}'
    )
    mock_response = AsyncMock()
    mock_choice = AsyncMock()
    mock_choice.message.content = llm_json_output
    mock_response.choices = [mock_choice]

    mock_call = AsyncMock(return_value=mock_response)

    with patch.object(settings, "LLM_API_KEY", "sk-custom-provider-key"), \
         patch.object(settings, "LLM_MODEL", "custom-provider/custom-model"), \
         patch("backend.llm_service.acompletion", mock_call):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.post("/api/phishing/generate", json={
                "target_role": "Employee",
                "difficulty": "High",
                "industry": "Finance"
            })
            assert res.status_code == 200
            data = res.json()
            assert data["generation_source"] == "llm"
            assert data["fallback_reason"] is None
            assert data["subject"] == "Urgent: Mandatory IT Security Update"
            
            # Verify explicit key and configured model were passed
            assert mock_call.call_args.kwargs["model"] == "custom-provider/custom-model"
            assert mock_call.call_args.kwargs["api_key"] == "sk-custom-provider-key"


# =========================================================================
# 5. TEST: Backward Compatibility - Old documents without new fields still load
# =========================================================================
def test_old_documents_without_traceability_fields_load():
    old_phishing_doc = {
        "id": "123e4567-e89b-12d3-a456-426614174000",
        "subject": "Legacy Phishing Simulation",
        "body": "Legacy email body text without new fields.",
        "red_flags": ["Legacy flag"],
        "analysis": "Legacy analysis description",
        "created_at": datetime.now(timezone.utc)
    }
    model = PhishingResponse.model_validate(old_phishing_doc)
    assert model.subject == "Legacy Phishing Simulation"
    assert model.generation_source == "fallback"
    assert model.fallback_reason is None

    old_ransomware_doc = {
        "id": "123e4567-e89b-12d3-a456-426614174001",
        "attack_vector": "Email",
        "infection_flow": ["Step 1", "Step 2"],
        "mitre_mapping": [{"id": "T1566", "name": "Phishing"}],
        "prevention_tips": ["Tip 1"],
        "created_at": datetime.now(timezone.utc)
    }
    r_model = RansomwareResponse.model_validate(old_ransomware_doc)
    assert r_model.attack_vector == "Email"
    assert r_model.generation_source == "fallback"

    old_scenario_doc = {
        "id": "123e4567-e89b-12d3-a456-426614174002",
        "title": "Legacy Attack Scenario",
        "timeline": [{"stage": "Initial Access", "time": "Day 0", "description": "Phish", "impact": "Low"}],
        "created_at": datetime.now(timezone.utc)
    }
    s_model = AttackScenarioResponse.model_validate(old_scenario_doc)
    assert s_model.title == "Legacy Attack Scenario"
    assert s_model.generation_source == "fallback"

    old_question_doc = {
        "id": "123e4567-e89b-12d3-a456-426614174003",
        "question": "Legacy quiz question?",
        "options": ["A", "B", "C", "D"],
        "correct_answer": "B",
        "explanation": "Legacy explanation text"
    }
    q_model = TrainingQuestionResponse.model_validate(old_question_doc)
    assert q_model.correct_answer == "B"
    assert q_model.generation_source == "fallback"


# =========================================================================
# 6. TEST: Health endpoint - GET /api/health/llm & Error Categorization
# =========================================================================
@pytest.mark.asyncio
async def test_health_llm_endpoint_success():
    mock_response = AsyncMock()
    mock_choice = AsyncMock()
    mock_choice.message.content = "pong"
    mock_response.choices = [mock_choice]

    mock_call = AsyncMock(return_value=mock_response)

    with patch.object(settings, "LLM_API_KEY", "sk-test-key"), \
         patch.object(settings, "LLM_MODEL", "groq/llama-3.1-70b-versatile"), \
         patch("backend.server.acompletion", mock_call):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.get("/api/health/llm")
            assert res.status_code == 200
            data = res.json()
            assert data["llm_available"] is True
            assert data["model"] == "groq/llama-3.1-70b-versatile"
            assert data["error"] is None
            assert mock_call.call_args.kwargs["model"] == "groq/llama-3.1-70b-versatile"
            assert mock_call.call_args.kwargs["api_key"] == "sk-test-key"


@pytest.mark.asyncio
async def test_health_llm_endpoint_error_distinctions():
    transport = ASGITransport(app=app)

    # 1. Authentication failure
    class AuthenticationError(Exception): pass
    with patch.object(settings, "LLM_API_KEY", "sk-bad-key"), \
         patch("backend.server.acompletion", AsyncMock(side_effect=AuthenticationError("Incorrect API key provided"))):
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.get("/api/health/llm")
            data = res.json()
            assert data["llm_available"] is False
            assert "Authentication failed" in data["error"]
            assert "sk-bad-key" not in data["error"]

    # 2. Invalid model name
    class NotFoundError(Exception): pass
    with patch.object(settings, "LLM_API_KEY", "sk-good-key"), \
         patch("backend.server.acompletion", AsyncMock(side_effect=NotFoundError("The model `invalid-model-name` does not exist"))):
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.get("/api/health/llm")
            data = res.json()
            assert data["llm_available"] is False
            assert "Invalid model name" in data["error"]

    # 3. Rate limit exceeded
    class RateLimitError(Exception): pass
    with patch.object(settings, "LLM_API_KEY", "sk-good-key"), \
         patch("backend.server.acompletion", AsyncMock(side_effect=RateLimitError("Rate limit reached for requests"))):
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.get("/api/health/llm")
            data = res.json()
            assert data["llm_available"] is False
            assert "Rate limit" in data["error"]

    # 4. Timeout
    with patch.object(settings, "LLM_API_KEY", "sk-good-key"), \
         patch("backend.server.acompletion", AsyncMock(side_effect=asyncio.TimeoutError())):
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.get("/api/health/llm")
            data = res.json()
            assert data["llm_available"] is False
            assert "timed out" in data["error"].lower()
