"""
tests/test_training.py
Phase 5 Training Mode and Dashboard – pytest test suite.

Covers:
- Option labels ("A)", "A.", "(A)", "Option A:") and HTML tags are stripped during sanitization
- Literal "\\n" and "\\n" sequences are normalized
- Category is enforced from the request, not from LLM output
- Off-topic questions failing category keyword validation are rejected
- A correct option >1.8x longer than wrong options is rejected
- Option shuffle ensures correct answer position varies randomly
- Skip endpoint records skipped attempts with score 0 and skipped=True
- Training and Dashboard endpoints return identical total scores from the single source of truth
- Backward compatibility: old training questions and dashboard docs without new fields load cleanly
- Fallback question bank contains 8+ distinct questions per category without immediate repetition
"""

import sys
import os
import pytest
from unittest.mock import AsyncMock, patch
from datetime import datetime, timezone
from httpx import AsyncClient, ASGITransport

# ── make backend importable ──────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from server import (
    app,
    LLMTrainingQuestionPayload,
    TrainingQuestionResponse,
    TrainingAnswerResponse,
    TrainingStatsResponse,
    DashboardStats,
    sanitize_text,
    sanitize_option,
    shuffle_and_format_question,
    fallback_generate_training_question,
    compute_training_metrics,
    TRAINING_FALLBACK_BANK
)
from pydantic import ValidationError


# =========================================================================
# 1. Sanitization & HTML Stripping Tests
# =========================================================================

def test_sanitize_option_strips_prefixes_and_html():
    """Option labels like A), A., (A), Option A: and HTML tags must be stripped."""
    assert sanitize_option("A) Confidentiality") == "Confidentiality"
    assert sanitize_option("A. Integrity") == "Integrity"
    assert sanitize_option("(A) Availability") == "Availability"
    assert sanitize_option("A: Zero Trust") == "Zero Trust"
    assert sanitize_option("Option A: Least Privilege") == "Least Privilege"
    assert sanitize_option("<div>B) Multi-Factor Authentication</div>") == "Multi-Factor Authentication"
    assert sanitize_option("<b>C.</b> Eradication phase") == "Eradication phase"
    assert sanitize_option("A. A) Stacked prefix") == "Stacked prefix"


def test_sanitize_text_removes_newlines_and_html():
    """Literal \\n, real newlines, and HTML tags must be cleaned."""
    raw = "<div>What is the primary objective of Incident Response?\\n\\nPlease explain.</div>"
    clean = sanitize_text(raw)
    assert "<" not in clean
    assert ">" not in clean
    assert "\\n" not in clean
    assert "What is the primary objective of Incident Response? Please explain." == clean


# =========================================================================
# 2. LLMTrainingQuestionPayload Validation Tests
# =========================================================================

def test_payload_accepts_valid_balanced_question():
    """Valid payload with 4 balanced options and matching category passes."""
    data = {
        "question": "An employee receives a suspicious email containing an unverified link. What is this?",
        "options": [
            "A phishing credential harvesting attempt.",
            "A routine internal corporate network scan.",
            "A standard hardware maintenance notification.",
            "An authorized operating system software patch."
        ],
        "correct_answer": "A",
        "explanation": "Phishing emails frequently use unverified links to harvest user credentials.",
        "category": "Phishing"
    }
    payload = LLMTrainingQuestionPayload(**data)
    assert len(payload.options) == 4
    assert payload.options[0] == "A phishing credential harvesting attempt."


def test_payload_rejects_off_topic_category():
    """A question with no matching category keywords must be rejected."""
    data = {
        "question": "How do you calculate employee overtime compensation in accounting software?",
        "options": [
            "Multiply hourly wage by standard overtime factor.",
            "Deduct state payroll taxes from gross salary.",
            "Submit quarterly fiscal invoices to vendors.",
            "Reconcile annual bank statement accounts."
        ],
        "correct_answer": "A",
        "explanation": "Overtime calculations follow statutory labor rate formulas.",
        "category": "Ransomware"  # Completely off-topic for Ransomware
    }
    with pytest.raises(ValidationError, match="does not match any required topic keywords"):
        LLMTrainingQuestionPayload(**data)


def test_payload_rejects_imbalanced_correct_option_length():
    """A correct option more than 1.8x longer than the longest wrong option must be rejected."""
    data = {
        "question": "What is the primary indicator of an email phishing attack?",
        "options": [
            "A highly elaborate and conspicuously lengthy paragraph explaining every nuance of artificial urgency, lookalike domain spoofing, and forged headers designed to deceive victims into revealing credentials.",
            "Short link.",
            "Normal mail.",
            "Plain text."
        ],
        "correct_answer": "A",
        "explanation": "Detailed explanations help identify phishing.",
        "category": "Phishing"
    }
    with pytest.raises(ValidationError, match="more than 1.8x longer"):
        LLMTrainingQuestionPayload(**data)


def test_payload_rejects_duplicate_options():
    """Duplicate distractors must be rejected."""
    data = {
        "question": "What is the primary indicator of an email phishing attack?",
        "options": [
            "Suspicious link destination.",
            "Suspicious link destination.",
            "Authorized server update.",
            "Standard calendar invite."
        ],
        "correct_answer": "A",
        "explanation": "Duplicate options are invalid.",
        "category": "Phishing"
    }
    with pytest.raises(ValidationError, match="unique"):
        LLMTrainingQuestionPayload(**data)


def test_payload_rejects_non_four_options():
    """Questions with fewer or more than 4 options must be rejected."""
    data = {
        "question": "What is an email phish?",
        "options": [
            "Option one email lure.",
            "Option two email lure."
        ],
        "correct_answer": "A",
        "explanation": "Only 2 options provided.",
        "category": "Phishing"
    }
    with pytest.raises(ValidationError, match="exactly 4 options"):
        LLMTrainingQuestionPayload(**data)


# =========================================================================
# 3. Shuffle & Non-Repetition Tests
# =========================================================================

def test_shuffle_and_format_varies_correct_position():
    """Shuffling repeatedly ensures the correct answer is not stuck in a single position."""
    q_text = "What is Multi-Factor Authentication?"
    options = ["Correct: Two or more factors", "Wrong A", "Wrong B", "Wrong C"]
    
    positions = set()
    for _ in range(50):
        res = shuffle_and_format_question(
            question_text=q_text,
            options=options,
            correct_idx_or_text_or_letter=0,
            explanation="MFA requires multiple factors.",
            category="General Security"
        )
        positions.add(res["correct_answer"])
    
    # Must have appeared in more than 1 position across 50 runs
    assert len(positions) > 1, f"Correct position did not vary: {positions}"


def test_fallback_bank_has_at_least_8_questions_per_category():
    """Every category bank must contain at least 8 rich, distinct questions."""
    for cat in ["phishing", "ransomware", "general security", "incident response"]:
        bank = TRAINING_FALLBACK_BANK.get(cat, [])
        assert len(bank) >= 8, f"Category '{cat}' has {len(bank)} questions, expected >= 8"
        # Check all questions have required fields
        for q in bank:
            assert len(q["options"]) == 4
            assert 0 <= q["correct_idx"] <= 3
            assert len(q["explanation"]) > 10


def test_fallback_non_repetition():
    """Two consecutive fallback calls for the same category must return different questions."""
    q1 = fallback_generate_training_question("Ransomware")
    q2 = fallback_generate_training_question("Ransomware")
    assert q1["question"] != q2["question"], "Consecutive fallback calls returned identical questions"


# =========================================================================
# 4. Metrics & Single Source of Truth Tests
# =========================================================================

def test_compute_training_metrics():
    """Verify total_score, accuracy, streak, and category metrics calculation."""
    sample_scores = [
        {"category": "Phishing", "correct": True, "score": 10, "skipped": False, "timestamp": "2026-10-01T10:00:00"},
        {"category": "Phishing", "correct": True, "score": 10, "skipped": False, "timestamp": "2026-10-01T10:05:00"},
        {"category": "Ransomware", "correct": False, "score": 0, "skipped": False, "timestamp": "2026-10-01T10:10:00"},
        {"category": "Ransomware", "correct": True, "score": 10, "skipped": False, "timestamp": "2026-10-01T10:15:00"},
        {"category": "Incident Response", "correct": False, "score": 0, "skipped": True, "timestamp": "2026-10-01T10:20:00"},
        {"category": "General Security", "correct": True, "score": 10, "skipped": False, "timestamp": "2026-10-01T10:25:00"}
    ]
    metrics = compute_training_metrics(sample_scores)
    assert metrics["total_score"] == 40
    assert metrics["questions_answered"] == 6
    # Non-skipped = 5 attempts, correct = 4 -> 4/5 * 100 = 80.0%
    assert metrics["overall_accuracy"] == 80.0
    # Streak: last attempt was True -> streak is 1 (before that was skipped False)
    assert metrics["current_streak"] == 1


# =========================================================================
# 5. Backward Compatibility Tests
# =========================================================================

def test_old_documents_without_new_fields_load_cleanly():
    """Legacy question and dashboard objects without new fields must deserialize without error."""
    old_q = {
        "id": "legacy-q-001",
        "question": "Legacy cybersecurity question?",
        "options": ["Opt 1", "Opt 2", "Opt 3", "Opt 4"],
        "correct_answer": "B",
        "explanation": "Legacy explanation"
    }
    q_resp = TrainingQuestionResponse(**old_q)
    assert q_resp.correct_answer == "B"
    assert q_resp.category is None
    assert q_resp.option_explanations is None

    old_dash = {
        "total_simulations": 12,
        "phishing_sims": 5,
        "ransomware_sims": 4,
        "attack_scenarios": 3,
        "training_score": 150
    }
    d_resp = DashboardStats(**old_dash)
    assert d_resp.total_simulations == 12
    assert d_resp.total_score == 0
    assert d_resp.overall_accuracy == 0.0


# =========================================================================
# 6. End-to-End API Route Tests (Mocked DB & LLM)
# =========================================================================

@pytest.fixture
def anyio_backend():
    return "asyncio"

@pytest.mark.asyncio
async def test_api_training_and_dashboard_score_consistency():
    """Training answer submission and Dashboard stats must return consistent score data."""
    stored_questions = {}
    stored_scores = []

    async def mock_find_one(query):
        return stored_questions.get(query.get("id"))

    async def mock_insert_question(doc):
        stored_questions[doc["id"]] = doc
        return None

    async def mock_insert_score(doc):
        stored_scores.append(doc)
        return None

    def mock_find_scores(query=None):
        class MockCursor:
            async def to_list(self, limit):
                return list(stored_scores)
        return MockCursor()

    with patch("server.db") as mock_db:
        mock_db.training_questions.insert_one = AsyncMock(side_effect=mock_insert_question)
        mock_db.training_questions.find_one = AsyncMock(side_effect=mock_find_one)
        mock_db.training_scores.insert_one = AsyncMock(side_effect=mock_insert_score)
        mock_db.training_scores.find = mock_find_scores
        mock_db.phishing_simulations.count_documents = AsyncMock(return_value=2)
        mock_db.ransomware_simulations.count_documents = AsyncMock(return_value=1)
        mock_db.attack_scenarios.count_documents = AsyncMock(return_value=1)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            # 1. Generate a question
            q_res = await ac.post("/api/training/question", json={"scenario_type": "Phishing"})
            assert q_res.status_code == 200
            q_data = q_res.json()
            assert q_data["category"] == "Phishing"
            assert len(q_data["options"]) == 4

            # 2. Answer correctly
            ans_res = await ac.post("/api/training/answer", json={
                "question_id": q_data["id"],
                "user_answer": q_data["correct_answer"],
                "skipped": False
            })
            assert ans_res.status_code == 200
            ans_data = ans_res.json()
            assert ans_data["correct"] is True
            assert ans_data["score_gained"] == 10
            assert ans_data["total_score"] == 10

            # 3. Check Training Stats
            t_stats_res = await ac.get("/api/training/stats")
            assert t_stats_res.status_code == 200
            t_stats = t_stats_res.json()
            assert t_stats["total_score"] == 10

            # 4. Check Dashboard Stats -> Must return same total_score
            d_stats_res = await ac.get("/api/dashboard/stats")
            assert d_stats_res.status_code == 200
            d_stats = d_stats_res.json()
            assert d_stats["total_score"] == 10
            assert d_stats["training_score"] == 10
            assert d_stats["total_simulations"] == 4

            # 5. Skip a second question
            q_res2 = await ac.post("/api/training/question", json={"scenario_type": "Ransomware"})
            q_data2 = q_res2.json()
            skip_res = await ac.post("/api/training/answer", json={
                "question_id": q_data2["id"],
                "skipped": True
            })
            assert skip_res.status_code == 200
            skip_data = skip_res.json()
            assert skip_data["skipped"] is True
            assert skip_data["score_gained"] == 0
            assert skip_data["total_score"] == 10
