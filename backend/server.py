from fastapi import FastAPI, APIRouter, HTTPException
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import logging
from pydantic import BaseModel, Field, ConfigDict, field_validator, model_validator
from typing import List, Optional, Literal, Any, Union, Dict
from pathlib import Path
import uuid
from datetime import datetime, timezone
import json
import random
import time
import asyncio
import re
from litellm import acompletion

try:
    from backend.config import settings
    from backend.llm_service import execute_llm_with_validation, sanitize_llm_error
except ImportError:
    from config import settings
    from llm_service import execute_llm_with_validation, sanitize_llm_error

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("cyberrange.server")

# Database Connection
client = AsyncIOMotorClient(settings.MONGO_URL)
db = client[settings.DB_NAME]

# Create the main app
app = FastAPI(title="CyberRange AI API", version="1.0")
api_router = APIRouter(prefix="/api")


# ============= OUTPUT VALIDATION SCHEMAS (LLM Outputs) =============
MITRE_TACTIC_ORDER = {
    "Reconnaissance": 1,
    "Resource Development": 2,
    "Initial Access": 3,
    "Execution": 4,
    "Persistence": 5,
    "Privilege Escalation": 6,
    "Defense Evasion": 7,
    "Credential Access": 8,
    "Discovery": 9,
    "Lateral Movement": 10,
    "Collection": 11,
    "Command and Control": 12,
    "Exfiltration": 13,
    "Impact": 14
}

# Load official MITRE ATT&CK Enterprise techniques lookup
MITRE_LOOKUP_PATH = Path(__file__).resolve().parent / "data" / "mitre_techniques.json"
MITRE_TECHNIQUES = {}
if MITRE_LOOKUP_PATH.exists():
    try:
        with open(MITRE_LOOKUP_PATH, "r", encoding="utf-8") as f:
            MITRE_TECHNIQUES = json.load(f)
        logger.info("Loaded %d MITRE ATT&CK Enterprise techniques from lookup file", len(MITRE_TECHNIQUES))
    except Exception as e:
        logger.warning("Could not load MITRE techniques lookup from %s: %s", MITRE_LOOKUP_PATH, e)
else:
    logger.warning("MITRE techniques lookup file not found at %s", MITRE_LOOKUP_PATH)


class Technique(BaseModel):
    model_config = ConfigDict(extra="ignore")
    technique_id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    technique_name: str

    @model_validator(mode="after")
    def validate_and_normalize_technique(self):
        tid = self.technique_id.strip()
        if MITRE_TECHNIQUES:
            if tid not in MITRE_TECHNIQUES:
                raise ValueError(f"Unknown or non-existent MITRE ATT&CK technique ID: {tid}")
            # Replace technique_name with the official name from MITRE lookup
            self.technique_name = MITRE_TECHNIQUES[tid]["technique_name"]
        return self


class LLMAttackStage(BaseModel):
    model_config = ConfigDict(extra="ignore")
    stage: str
    time: str
    description: str
    impact: str
    tactic: Literal[
        "Reconnaissance", "Resource Development", "Initial Access",
        "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery",
        "Lateral Movement", "Collection", "Command and Control",
        "Exfiltration", "Impact"
    ]
    techniques: List[Technique] = Field(min_length=1, max_length=2)
    detection_likelihood: Literal["Low", "Medium", "High"]
    detection_hint: str
    mitigation: str


class LLMAttackScenarioPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")
    title: str
    summary: str
    timeline: List[LLMAttackStage] = Field(min_length=8, max_length=10)

    @field_validator("summary")
    @classmethod
    def validate_summary(cls, v: str):
        cleaned = v.strip()
        if len(cleaned) < 20:
            raise ValueError("Summary must be a descriptive summary of at least 20 characters")
        return cleaned

    @field_validator("timeline")
    @classmethod
    def validate_timeline(cls, stages: List[LLMAttackStage]):
        # 1. Check length (8 to 10 stages)
        if len(stages) < 8 or len(stages) > 10:
            raise ValueError(f"Scenario must contain between 8 and 10 stages, got {len(stages)}")

        # 2. Duplicate descriptions check
        descriptions = [s.description.strip().lower() for s in stages]
        if len(set(descriptions)) != len(descriptions):
            raise ValueError("Stages must not have duplicate descriptions")
        
        # 3. Kill-chain forward order check
        order_values = [MITRE_TACTIC_ORDER.get(s.tactic, 0) for s in stages]
        for idx in range(1, len(order_values)):
            if order_values[idx] < order_values[idx - 1]:
                raise ValueError(f"Tactics out of kill-chain order: {stages[idx-1].tactic} -> {stages[idx].tactic}")
        
        # 4. Attack coverage check
        tactics = [s.tactic for s in stages]
        tactics_set = set(tactics)

        if "Initial Access" not in tactics_set:
            raise ValueError("Scenario must include at least one 'Initial Access' stage")
        
        if "Execution" not in tactics_set:
            raise ValueError("Scenario must include at least one 'Execution' stage")
        
        if not (tactics_set & {"Credential Access", "Privilege Escalation"}):
            raise ValueError("Scenario must include at least one stage for 'Credential Access' or 'Privilege Escalation'")
            
        if not (tactics_set & {"Lateral Movement", "Discovery"}):
            raise ValueError("Scenario must include at least one stage for 'Lateral Movement' or 'Discovery'")
            
        if not (tactics_set & {"Collection", "Exfiltration"}):
            raise ValueError("Scenario must include at least one stage for 'Collection' or 'Exfiltration'")
            
        # 5. Final stage check
        final_tactic = stages[-1].tactic
        if final_tactic not in {"Impact", "Exfiltration"}:
            raise ValueError(f"Final stage must have tactic 'Impact' or 'Exfiltration', got '{final_tactic}'")

        return stages


class ConsistencyReviewPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")
    consistent: bool
    issues: List[str] = Field(default_factory=list)


class RedFlagItem(BaseModel):
    model_config = ConfigDict(extra="ignore")
    flag: str
    evidence: str
    explanation: str

    @model_validator(mode="after")
    def clean_text(self):
        self.flag = re.sub(r'^[\*\-\•\s]+', '', self.flag).strip()
        self.evidence = self.evidence.strip()
        self.explanation = re.sub(r'^[\*\-\•\s]+', '', self.explanation).strip()
        return self


class HeaderAnalysis(BaseModel):
    model_config = ConfigDict(extra="ignore")
    spf: Literal["pass", "fail", "softfail", "none"]
    dkim: Literal["pass", "fail", "softfail", "none"]
    dmarc: Literal["pass", "fail", "softfail", "none"]
    notes: str

    @model_validator(mode="after")
    def clean_notes(self):
        self.notes = re.sub(r'^[\*\-\•\s]+', '', self.notes).strip()
        return self


class PsychologicalTrigger(BaseModel):
    model_config = ConfigDict(extra="ignore")
    trigger: Literal["Urgency", "Authority", "Fear", "Curiosity", "Reward", "Familiarity"]
    where_used: str

    @model_validator(mode="after")
    def clean_trigger(self):
        self.where_used = self.where_used.strip()
        return self


class LLMPhishingPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")
    subject: str
    sender_name: str
    sender_email: str
    reply_to_email: str
    recipient_name: str
    date_sent: str
    body: str
    link_display_text: Optional[str] = None
    link_url: Optional[str] = None
    header_analysis: HeaderAnalysis
    red_flags: List[RedFlagItem] = Field(min_length=2, max_length=6)
    psychological_triggers: List[PsychologicalTrigger] = Field(default_factory=list)
    safe_response: List[str] = Field(min_length=3, max_length=5)
    analysis: str
    difficulty: Optional[str] = None

    @model_validator(mode="after")
    def validate_phishing_payload(self):
        # 1. Clean bullets from safe_response and analysis
        self.safe_response = [re.sub(r'^[\*\-\•\s]+', '', x).strip() for x in self.safe_response]
        self.analysis = re.sub(r'^[\*\-\•\s]+', '', self.analysis).strip()

        # 2. Fictional domains validation (.example or .test strictly)
        sender_domain = self.sender_email.split('@')[-1].lower() if '@' in self.sender_email else self.sender_email.lower()
        if not (sender_domain.endswith('.example') or sender_domain.endswith('.test')):
            raise ValueError(f"sender_email '{self.sender_email}' must use a reserved fictional domain ending in .example or .test")

        reply_domain = self.reply_to_email.split('@')[-1].lower() if '@' in self.reply_to_email else self.reply_to_email.lower()
        if not (reply_domain.endswith('.example') or reply_domain.endswith('.test')):
            raise ValueError(f"reply_to_email '{self.reply_to_email}' must use a reserved fictional domain ending in .example or .test")

        if self.link_url:
            from urllib.parse import urlparse
            parsed = urlparse(self.link_url)
            host = (parsed.hostname or "").lower()
            if not (host.endswith('.example') or host.endswith('.test')):
                raise ValueError(f"link_url '{self.link_url}' host must end in .example or .test (rejects .com, .net, .org)")

        # 3. Check every red_flag.evidence actually appears in the email content
        searchable_content = " ".join([
            self.subject,
            self.sender_name,
            self.sender_email,
            self.reply_to_email,
            self.recipient_name,
            self.body,
            self.link_display_text or "",
            self.link_url or ""
        ]).lower()

        for rf in self.red_flags:
            ev = rf.evidence.strip().lower()
            if not ev:
                raise ValueError(f"Red flag '{rf.flag}' has empty evidence")
            if ev not in searchable_content:
                ev_norm = re.sub(r'\s+', ' ', ev)
                content_norm = re.sub(r'\s+', ' ', searchable_content)
                if ev_norm not in content_norm:
                    raise ValueError(f"Red flag evidence '{rf.evidence}' was not found in the email content")

        # 4. At least one red flag must concern the sender address, reply-to, or domain
        has_sender_flag = any(
            sender_domain in rf.evidence.lower()
            or reply_domain in rf.evidence.lower()
            or self.sender_email.lower() in rf.evidence.lower()
            or self.reply_to_email.lower() in rf.evidence.lower()
            or any(w in rf.flag.lower() for w in ["sender", "domain", "address", "reply-to", "from", "source", "spoof", "impersonat", "lookalike", "unverified"])
            or any(w in rf.explanation.lower() for w in ["sender", "domain", "address", "reply-to", "from"])
            for rf in self.red_flags
        )
        if not has_sender_flag:
            raise ValueError("At least one red flag must concern the sender address, reply-to, or domain")

        # 5. Greeting must address recipient_name unless it is a clear mass notice
        first_name = self.recipient_name.split()[0].lower() if self.recipient_name else ""
        full_name = self.recipient_name.lower() if self.recipient_name else ""
        body_header = "\n".join(self.body.splitlines()[:4]).lower()
        is_mass_notice = any(w in body_header for w in ["all staff", "all employees", "all team", "team,", "colleagues,", "everyone,", "attention staff", "all members"])
        if not is_mass_notice and first_name:
            if first_name not in body_header and full_name not in self.body.lower():
                raise ValueError(f"The email greeting must address recipient_name '{self.recipient_name}'")

        # 6. Validate difficulty-specific red flag counts if difficulty is present
        if self.difficulty:
            d = self.difficulty.lower()
            count = len(self.red_flags)
            if "easy" in d and not (4 <= count <= 5):
                raise ValueError(f"Easy difficulty requires 4-5 red flags, got {count}")
            elif "medium" in d and not (3 <= count <= 4):
                raise ValueError(f"Medium difficulty requires 3-4 red flags, got {count}")
            elif ("hard" in d or "advanced" in d) and not (2 <= count <= 3):
                raise ValueError(f"Hard/Advanced difficulty requires 2-3 red flags, got {count}")

        # 7. Header consistency validation
        h = self.header_analysis
        if h.spf == "fail" and h.dkim == "fail" and h.dmarc == "pass":
            raise ValueError("Inconsistent headers: DMARC cannot pass when both SPF and DKIM fail")

        return self

class LLMRansomwareStep(BaseModel):
    model_config = ConfigDict(extra="ignore")
    step_number: int
    title: str
    description: str
    tactic: Literal[
        "Reconnaissance", "Resource Development", "Initial Access",
        "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery",
        "Lateral Movement", "Collection", "Command and Control",
        "Exfiltration", "Impact"
    ]
    technique_id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    technique_name: str
    detection_hint: str
    containment_action: str

    @model_validator(mode="after")
    def validate_and_normalize_step(self):
        # 1. Clean "Step N:" prefix from title and description
        self.title = re.sub(r'^(?:step\s*\d+\s*[:.-]\s*)', '', self.title, flags=re.IGNORECASE).strip()
        self.description = re.sub(r'^(?:step\s*\d+\s*[:.-]\s*)', '', self.description, flags=re.IGNORECASE).strip()
        
        # 2. Validate technique_id against MITRE lookup and normalize technique_name
        tid = self.technique_id.strip()
        if MITRE_TECHNIQUES:
            if tid not in MITRE_TECHNIQUES:
                raise ValueError(f"Unknown or non-existent MITRE ATT&CK technique ID: {tid}")
            self.technique_name = MITRE_TECHNIQUES[tid]["technique_name"]
            
        # 3. Clean leading bullets from text
        self.detection_hint = re.sub(r'^[\*\-\•\s]+', '', self.detection_hint).strip()
        self.containment_action = re.sub(r'^[\*\-\•\s]+', '', self.containment_action).strip()
        return self


class ResponsePlan(BaseModel):
    model_config = ConfigDict(extra="ignore")
    immediate_actions: List[str] = Field(min_length=3)
    recovery_steps: List[str] = Field(min_length=3)
    lessons_learned: List[str] = Field(min_length=3)

    @model_validator(mode="after")
    def clean_bullets(self):
        self.immediate_actions = [re.sub(r'^[\*\-\•\s]+', '', x).strip() for x in self.immediate_actions]
        self.recovery_steps = [re.sub(r'^[\*\-\•\s]+', '', x).strip() for x in self.recovery_steps]
        self.lessons_learned = [re.sub(r'^[\*\-\•\s]+', '', x).strip() for x in self.lessons_learned]
        return self


class PreventionTip(BaseModel):
    model_config = ConfigDict(extra="ignore")
    text: str
    addresses_step: int

    @model_validator(mode="after")
    def clean_text(self):
        self.text = re.sub(r'^[\*\-\•\s]+', '', self.text).strip()
        return self


class LLMRansomwarePayload(BaseModel):
    model_config = ConfigDict(extra="ignore")
    summary: str
    steps: List[LLMRansomwareStep] = Field(min_length=6, max_length=8)
    response_plan: ResponsePlan
    prevention_tips: List[PreventionTip] = Field(min_length=3)

    @field_validator("summary")
    @classmethod
    def validate_summary(cls, v: str):
        cleaned = re.sub(r'^[\*\-\•\s]+', '', v).strip()
        if len(cleaned) < 20:
            raise ValueError("Summary must be a descriptive string of at least 20 characters")
        return cleaned

    @field_validator("steps")
    @classmethod
    def validate_steps(cls, steps: List[LLMRansomwareStep]):
        # 1. Check length (6 to 8 steps)
        if len(steps) < 6 or len(steps) > 8:
            raise ValueError(f"Ransomware scenario must contain 6 to 8 steps, got {len(steps)}")

        # 2. Check sequential step numbers
        for i, s in enumerate(steps, start=1):
            s.step_number = i

        # 3. Duplicate descriptions check
        descriptions = [s.description.strip().lower() for s in steps]
        if len(set(descriptions)) != len(descriptions):
            raise ValueError("Steps must not have duplicate descriptions")

        # 4. Mandatory tactics check:
        # - Initial Access
        # - Execution
        # - Discovery or Command and Control
        # - Credential Access or Lateral Movement
        # - Exfiltration or Collection
        # - Impact (T1486) as final or near-final step
        tactics = [s.tactic for s in steps]
        tactics_set = set(tactics)
        technique_ids = [s.technique_id for s in steps]

        if "Initial Access" not in tactics_set:
            raise ValueError("Scenario must include at least one 'Initial Access' step")

        if "Execution" not in tactics_set:
            raise ValueError("Scenario must include at least one 'Execution' step")

        if not (tactics_set & {"Discovery", "Command and Control"}):
            raise ValueError("Scenario must include at least one step for 'Discovery' or 'Command and Control'")

        if not (tactics_set & {"Credential Access", "Lateral Movement"}):
            raise ValueError("Scenario must include at least one step for 'Credential Access' or 'Lateral Movement'")

        if not (tactics_set & {"Exfiltration", "Collection"}):
            raise ValueError("Scenario must include at least one step for 'Exfiltration' or 'Collection'")

        # Check Impact with T1486 in final or near-final step
        last_two_tactics = tactics[-2:] if len(tactics) >= 2 else tactics
        last_two_techniques = technique_ids[-2:] if len(technique_ids) >= 2 else technique_ids
        if "T1486" not in technique_ids:
            raise ValueError("Scenario must include 'T1486' (Data Encrypted for Impact)")
        if "T1486" not in last_two_techniques or not any(t == "Impact" for t in last_two_tactics):
            raise ValueError("Impact step with technique T1486 must be the final or near-final step")

        # 5. Double extortion check: If exfiltration is present or mentioned, exfiltration step must come BEFORE T1486 encryption step
        if "T1486" in technique_ids:
            t1486_index = technique_ids.index("T1486")
            for idx, s in enumerate(steps):
                if s.tactic == "Exfiltration" or "exfiltration" in s.description.lower() or "stolen" in s.description.lower() or "data leak" in s.description.lower():
                    if idx > t1486_index:
                        raise ValueError("Exfiltration step must come before encryption in double-extortion scenarios")

        return steps


def sanitize_text(text: str) -> str:
    if not isinstance(text, str):
        return ""
    clean = re.sub(r'<[^>]+>', '', text)
    clean = clean.replace('\\n', ' ').replace('\n', ' ')
    clean = re.sub(r'^[\*\-\•\s]+', '', clean)
    clean = re.sub(r'\s+', ' ', clean).strip()
    return clean

def sanitize_option(text: str) -> str:
    if not isinstance(text, str):
        return ""
    clean = sanitize_text(text)
    prev = ""
    while prev != clean:
        prev = clean
        clean = re.sub(
            r'^(?:[oO]ption\s*[a-dA-D1-4]?[\.\:\)\-\]\s]*|\(?[a-dA-D1-4]\)[\.\:\)\-\]\s]*|\[?[a-dA-D1-4]\][\.\:\)\-\]\s]*|[a-dA-D1-4][\.\:\)\-][\s]*)\s*',
            '',
            clean
        ).strip()
    return clean

TRAINING_CATEGORY_KEYWORDS = {
    "phishing": [
        "email", "link", "sender", "attachment", "credentials", "spoof", "spear",
        "domain", "pretext", "urgent", "malicious", "phish", "lookalike", "inbox",
        "subject", "wire", "lure", "dkim", "spf", "dmarc", "harvest"
    ],
    "ransomware": [
        "encrypt", "ransom", "backup", "files", "decrypt", "extortion", "payload",
        "rdp", "locker", "t1486", "shadow copy", "vssadmin", "bitcoin", "payment",
        "lockbit", "c2", "crypto", "double-extortion", "exfiltration"
    ],
    "general security": [
        "password", "update", "mfa", "network", "data", "firewall", "zero trust",
        "access", "authentication", "vulnerability", "patch", "privilege",
        "cia triad", "least privilege", "encryption", "vpn", "authorization",
        "2fa", "security policy", "brute force", "malware", "endpoint", "waf", "symmetric"
    ],
    "general cyber": [
        "password", "update", "mfa", "network", "data", "firewall", "zero trust",
        "access", "authentication", "vulnerability", "patch", "privilege",
        "cia triad", "least privilege", "encryption", "vpn", "authorization",
        "2fa", "security policy", "brute force", "malware", "endpoint", "waf", "symmetric"
    ],
    "incident response": [
        "containment", "eradication", "recovery", "identification", "preparation",
        "lessons learned", "incident", "picerl", "triage", "forensic", "breach",
        "nist", "isolate", "chain of custody", "post-incident", "ioc", "csirt",
        "soc", "playbook", "remediation", "post-mortem"
    ]
}

class LLMTrainingQuestionPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")
    question: str
    options: List[str]
    correct_answer: str
    explanation: str
    category: Optional[str] = None
    option_explanations: Optional[Dict[str, str]] = None

    @model_validator(mode="after")
    def validate_and_sanitize(self):
        # 1. Sanitize fields
        self.question = sanitize_text(self.question)
        self.options = [sanitize_option(opt) for opt in self.options]
        self.explanation = sanitize_text(self.explanation)
        if self.option_explanations:
            self.option_explanations = {
                sanitize_text(k): sanitize_text(v) for k, v in self.option_explanations.items()
            }

        # 2. Check option count and non-empty
        if len(self.options) != 4:
            raise ValueError(f"Training question must have exactly 4 options, got {len(self.options)}")
        if any(not opt for opt in self.options):
            raise ValueError("All 4 options must be non-empty strings")

        # 3. Check for duplicates
        lower_opts = [opt.lower() for opt in self.options]
        if len(set(lower_opts)) != 4:
            raise ValueError("All 4 options must be unique (no duplicate distractors)")

        # 4. Resolve correct option
        correct_text = ""
        ca_upper = str(self.correct_answer).strip().upper()
        if ca_upper in ["A", "B", "C", "D"]:
            idx = ord(ca_upper) - 65
            if idx < len(self.options):
                correct_text = self.options[idx]
        else:
            clean_ca = sanitize_option(str(self.correct_answer))
            for opt in self.options:
                if opt.lower() == clean_ca.lower():
                    correct_text = opt
                    break

        if not correct_text:
            raise ValueError(f"Could not resolve correct_answer '{self.correct_answer}' to one of the 4 options")

        # 5. Check Option Balance (1.8x length rule)
        wrong_options = [opt for opt in self.options if opt != correct_text]
        correct_len = len(correct_text)
        max_wrong_len = max(len(opt) for opt in wrong_options) if wrong_options else 1

        if correct_len > 1.8 * max_wrong_len:
            raise ValueError(
                f"Correct option length ({correct_len}) is more than 1.8x longer than longest wrong option ({max_wrong_len})"
            )

        # 6. Category keyword matching check
        if self.category:
            cat_key = self.category.lower().strip()
            keywords = []
            for k, kw_list in TRAINING_CATEGORY_KEYWORDS.items():
                if k in cat_key or cat_key in k:
                    keywords = kw_list
                    break
            if not keywords:
                keywords = TRAINING_CATEGORY_KEYWORDS["general security"]

            search_text = (self.question + " " + " ".join(self.options)).lower()
            if not any(kw in search_text for kw in keywords):
                raise ValueError(
                    f"Question text does not match any required topic keywords for category '{self.category}'"
                )

        return self


# ============= API REQUEST / RESPONSE MODELS =============
class PhishingRequest(BaseModel):
    target_role: str
    difficulty: str
    industry: str

class PhishingResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    subject: str
    sender_name: Optional[str] = None
    sender_email: Optional[str] = None
    reply_to_email: Optional[str] = None
    recipient_name: Optional[str] = None
    date_sent: Optional[str] = None
    body: str
    link_display_text: Optional[str] = None
    link_url: Optional[str] = None
    header_analysis: Optional[dict] = None
    red_flags: List[Any]
    psychological_triggers: Optional[List[dict]] = None
    safe_response: Optional[List[str]] = None
    analysis: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    # Traceability fields
    generation_source: Literal["llm", "fallback"] = "fallback"
    fallback_reason: Optional[Literal["no_api_key", "timeout", "llm_error", "invalid_output"]] = None

class RansomwareRequest(BaseModel):
    attack_vector: str
    organization_type: str

class RansomwareResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    attack_vector: str
    summary: Optional[str] = None
    infection_flow: List[str]
    mitre_mapping: List[dict]
    steps: Optional[List[dict]] = None
    response_plan: Optional[dict] = None
    prevention_tips: List[Any]
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    # Traceability fields
    generation_source: Literal["llm", "fallback"] = "fallback"
    fallback_reason: Optional[Literal["no_api_key", "timeout", "llm_error", "invalid_output"]] = None

class AttackScenarioRequest(BaseModel):
    organization_type: str
    security_maturity: str

class AttackScenarioResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    summary: Optional[str] = None
    timeline: List[dict]
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    # Traceability fields
    generation_source: Literal["llm", "fallback"] = "fallback"
    fallback_reason: Optional[Literal["no_api_key", "timeout", "llm_error", "invalid_output"]] = None

class TrainingQuestionRequest(BaseModel):
    scenario_type: str

class TrainingQuestionResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    question: str
    options: List[str]
    correct_answer: str
    explanation: str
    category: Optional[str] = None
    option_explanations: Optional[Dict[str, str]] = None
    # Traceability fields
    generation_source: Literal["llm", "fallback"] = "fallback"
    fallback_reason: Optional[Literal["no_api_key", "timeout", "llm_error", "invalid_output"]] = None

class TrainingAnswerRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")
    question_id: str
    user_answer: Optional[str] = None
    skipped: Optional[bool] = False

class TrainingAnswerResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    correct: bool
    explanation: str
    score_gained: int
    option_explanations: Optional[Dict[str, str]] = None
    correct_answer: Optional[str] = None
    user_answer: Optional[str] = None
    skipped: bool = False
    total_score: Optional[int] = None
    accuracy: Optional[float] = None
    streak: Optional[int] = None

class TrainingStatsResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    total_score: int
    questions_answered: int
    overall_accuracy: float
    current_streak: int
    category_accuracy: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    weakest_area: Optional[str] = None
    recommended_next: Optional[str] = None

class DashboardStats(BaseModel):
    model_config = ConfigDict(extra="ignore")
    total_simulations: int
    phishing_sims: int
    ransomware_sims: int
    attack_scenarios: int
    training_score: int
    # Phase 5 enriched statistics
    total_score: int = 0
    questions_answered: int = 0
    overall_accuracy: float = 0.0
    current_streak: int = 0
    category_accuracy: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    score_over_time: List[Dict[str, Any]] = Field(default_factory=list)
    simulations_by_type: List[Dict[str, Any]] = Field(default_factory=list)
    weakest_area: Optional[str] = None
    recommended_next: Optional[str] = None

class LLMHealthResponse(BaseModel):
    llm_available: bool
    model: str
    error: Optional[str] = None


# ============= FALLBACK GENERATOR FUNCTIONS & TRAINING BANK =============

TRAINING_FALLBACK_BANK = {
    "phishing": [
        {
            "question": "An employee receives an email from 'it-support@corp-update.example' demanding they verify their VPN password within 15 minutes or lose network access. What is the primary red flag in this communication?",
            "options": [
                "A manufactured high-pressure deadline combined with an unverified lookalike sender domain.",
                "The email was transmitted during regular corporate business hours.",
                "The message mentions the organization's standard corporate VPN system.",
                "The request was delivered directly to the employee's corporate inbox."
            ],
            "correct_idx": 0,
            "explanation": "Phishing attacks frequently combine artificial urgency (15-minute deadline) with lookalike or external domains to coerce users into hasty credential disclosure.",
            "option_explanations": {
                "A": "Correct: Artificial urgency combined with an external or lookalike domain is a definitive phishing indicator.",
                "B": "Incorrect: Legitimate business emails regularly arrive during standard corporate working hours.",
                "C": "Incorrect: Referencing real corporate tools is standard in spear-phishing pretexts, but the threat and domain are the true red flags.",
                "D": "Incorrect: Receiving mail in an inbox is standard email behavior, not in itself an anomaly."
            },
            "category": "Phishing"
        },
        {
            "question": "You receive an email claiming company leadership has awarded you an unexpected $500 gift card, directing you to click 'claim-rewards-portal.example'. What social engineering vector is being leveraged?",
            "options": [
                "Reward appeal (greed/curiosity) combined with an untrusted external hyperlink.",
                "A distributed denial-of-service attack against the corporate email gateway.",
                "A cryptographic man-in-the-middle interception of active browser sessions.",
                "A physical hardware keylogger injection into the local USB interface."
            ],
            "correct_idx": 0,
            "explanation": "Reward-based lures exploit positive emotions and curiosity to lower defense vigilance and trick employees into clicking credential harvesting portals.",
            "option_explanations": {
                "A": "Correct: Reward appeals exploit curiosity and greed to lure users to malicious landing pages.",
                "B": "Incorrect: DDoS attacks overwhelm network services and do not involve gift card deception emails.",
                "C": "Incorrect: Session interception is an active network eavesdropping attack, not an email lure.",
                "D": "Incorrect: Keylogger injection requires physical or malware presence, not just an incoming message."
            },
            "category": "Phishing"
        },
        {
            "question": "What is the most secure operational protocol when receiving an unexpected email from a regular vendor requesting an urgent modification to their bank wire routing details?",
            "options": [
                "Authenticate the request by calling the vendor using a pre-established, verified phone number on file.",
                "Reply directly to the email asking the sender to re-confirm their new bank account numbers.",
                "Follow the link in the email to inspect the digital certificates on the new vendor portal.",
                "Forward the message to department colleagues to ask if anyone else authorized the change."
            ],
            "correct_idx": 0,
            "explanation": "Out-of-band verification via known, independently verified telephone numbers is the required defense against Business Email Compromise (BEC) and wire fraud.",
            "option_explanations": {
                "A": "Correct: Out-of-band verification using known contact info defeats email compromise attempts.",
                "B": "Incorrect: Replying directly routes back to the attacker if the account or thread is spoofed.",
                "C": "Incorrect: Clicking links exposes systems to credential harvesting and drive-by malware.",
                "D": "Incorrect: Internal coworkers cannot confirm whether the external vendor genuinely modified their banking."
            },
            "category": "Phishing"
        },
        {
            "question": "An inbound email contains an attachment labeled 'Q4_Executive_Bonus_Plan.pdf.exe'. Why does this file present a severe security risk?",
            "options": [
                "It employs a double file extension to camouflage an executable application as a PDF document.",
                "Standard corporate mail transfer agents are technically incapable of transmitting PDF files.",
                "The file name exceeds the maximum character length supported by the host operating system.",
                "Executable files inherently disable endpoint detection and response (EDR) agents automatically."
            ],
            "correct_idx": 0,
            "explanation": "Attackers append '.pdf.exe' so that systems hiding known extensions display only '.pdf', deceiving the user into executing malicious binary code.",
            "option_explanations": {
                "A": "Correct: Double extensions exploit default OS file extension hiding to trick users into running binaries.",
                "B": "Incorrect: Mail servers routinely transmit standard PDF document attachments.",
                "C": "Incorrect: Modern operating systems support filenames well over 250 characters.",
                "D": "Incorrect: Executable files do not automatically disable EDR agents without privilege escalation."
            },
            "category": "Phishing"
        },
        {
            "question": "What does a Sender Policy Framework (SPF) 'fail' result in an email header signify to the receiving mail security gateway?",
            "options": [
                "The sending IP address is not authorized to deliver messages for the domain specified in the envelope sender.",
                "The recipient user mailbox storage quota is exhausted and cannot accept incoming messages.",
                "The email body contains an encrypted or password-protected archive that cannot be inspected.",
                "The authoritative Domain Name System (DNS) records for the recipient company have expired."
            ],
            "correct_idx": 0,
            "explanation": "SPF publishes authorized sending IP addresses in DNS TXT records. An SPF fail indicates the sending host is not permitted to transmit mail for that domain.",
            "option_explanations": {
                "A": "Correct: SPF verifies whether the connecting mail server IP is authorized by the sender domain's DNS SPF record.",
                "B": "Incorrect: Mailbox quotas generate 552/554 storage bounce codes, not SPF validation failures.",
                "C": "Incorrect: Encrypted attachments trigger AV gateway quarantine rules, not SPF record failures.",
                "D": "Incorrect: Expired DNS records cause MX resolution lookup failures rather than SPF policy evaluation."
            },
            "category": "Phishing"
        },
        {
            "question": "An adversary registers 'secure-paypa1-login.example' (using the number '1' instead of the letter 'l') to harvest financial credentials. What attack methodology is this?",
            "options": [
                "Typosquatting / Visual lookalike domain spoofing (homoglyph deception).",
                "Structured Query Language (SQL) injection database manipulation.",
                "Cross-Site Request Forgery (CSRF) authenticated state modification.",
                "Stack-based buffer overflow memory corruption on the endpoint host."
            ],
            "correct_idx": 0,
            "explanation": "Typosquatting and homoglyph attacks register visually indistinguishable domain names to deceive victims during authentication workflows.",
            "option_explanations": {
                "A": "Correct: Typosquatting relies on subtle visual character substitutions to deceive users.",
                "B": "Incorrect: SQL injection targets backend database queries through unsanitized input fields.",
                "C": "Incorrect: CSRF tricks a victim browser into executing unwanted actions on an authenticated site.",
                "D": "Incorrect: Buffer overflows exploit memory management flaws in application binary execution."
            },
            "category": "Phishing"
        },
        {
            "question": "A spear-phishing email addresses you by your full name, cites your current project code name, and references your team supervisor. Why is this significantly more dangerous than generic bulk phishing?",
            "options": [
                "Pre-attack reconnaissance creates targeted credibility that substantially lowers psychological suspicion.",
                "Targeted spear-phishing messages inherently bypass all network firewall packet filtering rules.",
                "Spear-phishing emails execute malicious payloads automatically without requiring any recipient interaction.",
                "Targeted emails automatically encrypt the local hard drive as soon as the message arrives in the inbox."
            ],
            "correct_idx": 0,
            "explanation": "Spear-phishing incorporates reconnaissance details (OSINT) to establish immediate trust and bypass employee suspicion.",
            "option_explanations": {
                "A": "Correct: Contextual personalization creates false trust, making social engineering lures much harder to detect.",
                "B": "Incorrect: Firewalls inspect network layers; email content is evaluated by email security gateways.",
                "C": "Incorrect: Standard spear-phishing still requires user interaction (clicking links or opening files).",
                "D": "Incorrect: Encryption requires malicious binary execution, which does not happen from passive inbox delivery."
            },
            "category": "Phishing"
        },
        {
            "question": "Which email authentication standard enables domain owners to instruct receiving mail servers on how to enforce policy when messages fail SPF or DKIM checks?",
            "options": [
                "DMARC (Domain-based Message Authentication, Reporting, and Conformance).",
                "Opportunistic Transport Layer Security (STARTTLS) encryption.",
                "Internet Message Access Protocol (IMAP4) mailbox synchronization.",
                "Border Gateway Protocol (BGP) autonomous system routing policy."
            ],
            "correct_idx": 0,
            "explanation": "DMARC allows domain owners to publish policies (none, quarantine, reject) instructing receivers on handling authentication failures.",
            "option_explanations": {
                "A": "Correct: DMARC specifies policy enforcement (quarantine/reject) and reporting for SPF/DKIM alignment.",
                "B": "Incorrect: STARTTLS encrypts the SMTP transport channel in transit, but does not provide sender policy enforcement.",
                "C": "Incorrect: IMAP4 is a client-server protocol used to retrieve emails from a mail server.",
                "D": "Incorrect: BGP routes IP packets across internet autonomous systems, having no role in email header validation."
            },
            "category": "Phishing"
        }
    ],
    "ransomware": [
        {
            "question": "In a modern double-extortion ransomware campaign, what offensive action do threat actors execute prior to encrypting local files?",
            "options": [
                "Exfiltrating sensitive corporate files to threaten public publication if the extortion fee is unpaid.",
                "Overclocking server hardware processors to induce permanent physical thermal breakdown.",
                "Reformatting operating system disks to deploy open-source operating system alternatives.",
                "Replacing internal network Ethernet cables with unshielded patch cabling across data centers."
            ],
            "correct_idx": 0,
            "explanation": "Double extortion involves exfiltrating confidential data before deploying ransomware encryption, giving attackers leverage even if backups are restored.",
            "option_explanations": {
                "A": "Correct: Exfiltrating data prior to encryption provides dual extortion leverage (recovery fee + leak prevention).",
                "B": "Incorrect: Ransomware operators seek financial gain, not physical hardware destruction.",
                "C": "Incorrect: Attackers encrypt existing files in place rather than re-installing alternative operating systems.",
                "D": "Incorrect: Cyber extortion is a software/network attack and does not involve physical cabling tampering."
            },
            "category": "Ransomware"
        },
        {
            "question": "Why is the 3-2-1 backup methodology an essential foundational control against enterprise ransomware disruption?",
            "options": [
                "Maintaining 3 copies on 2 distinct media types with 1 copy offline/immutable ensures recovery if online systems are encrypted.",
                "It provides an absolute guarantee that ransomware binaries will fail to execute on protected endpoints.",
                "It enables automated decryption of files encrypted by modern asymmetric cryptographic algorithms without private keys.",
                "It eliminates the possibility of threat actors brute-forcing remote administrative credentials."
            ],
            "correct_idx": 0,
            "explanation": "Keeping an offline or immutable backup copy guarantees that ransomware spreading across network shares cannot delete or encrypt the recovery images.",
            "option_explanations": {
                "A": "Correct: An offline or immutable copy ensures clean recovery even when the entire connected network is encrypted.",
                "B": "Incorrect: Backups provide resilience for recovery, not preventative endpoint execution blocking.",
                "C": "Incorrect: Secure asymmetric ciphers cannot be mathematically reversed without the private key.",
                "D": "Incorrect: Backups do not prevent credential brute-forcing; authentication controls protect credentials."
            },
            "category": "Ransomware"
        },
        {
            "question": "Ransomware payloads frequently execute 'vssadmin.exe delete shadows /all /quiet'. What is the tactical objective of this command?",
            "options": [
                "Inhibit system recovery by deleting Volume Shadow Copies of the local file system.",
                "Establish an encrypted persistent reverse shell to the attacker command-and-control server.",
                "Extract plain-text user authentication credentials from the Windows LSASS memory space.",
                "Scan the local Class C subnet for open Remote Desktop Protocol (RDP) listening ports."
            ],
            "correct_idx": 0,
            "explanation": "Deleting shadow copies prevents system administrators from using Windows native Volume Shadow Copy Service to restore encrypted files.",
            "option_explanations": {
                "A": "Correct: Deleting shadow copies is a Defense Evasion / Impact tactic (T1490) to block local snapshot recovery.",
                "B": "Incorrect: C2 persistence uses registry keys, scheduled tasks, or services, not shadow copy deletion.",
                "C": "Incorrect: Credential dumping from LSASS utilizes tools like Mimikatz or ProcDump.",
                "D": "Incorrect: Port scanning uses network sockets or tools like Nmap, not vssadmin."
            },
            "category": "Ransomware"
        },
        {
            "question": "Which internet-facing service represents one of the most prevalent initial access vectors exploited by ransomware syndicates?",
            "options": [
                "Internet-exposed Remote Desktop Protocol (RDP) instances secured with weak or compromised credentials.",
                "Recursive DNS lookup queries originating from internal workstation operating systems.",
                "Standard outbound HTTPS connections to legitimate software distribution content delivery networks.",
                "Internal ICMP echo requests exchanged between neighboring cluster hypervisors."
            ],
            "correct_idx": 0,
            "explanation": "Publicly exposed RDP ports without MFA or rate-limiting are systematically brute-forced by ransomware access brokers.",
            "option_explanations": {
                "A": "Correct: Exposed RDP endpoints without MFA are primary targets for credential stuffing and initial intrusion.",
                "B": "Incorrect: Standard recursive DNS lookups are normal network operations, not exposed access listening services.",
                "C": "Incorrect: Outbound HTTPS to legitimate CDNs is standard web traffic.",
                "D": "Incorrect: Internal ICMP traffic is ping connectivity diagnostics within private local subnets."
            },
            "category": "Ransomware"
        },
        {
            "question": "Why do ransomware developers utilize hybrid encryption (asymmetric public/private key pairs combined with symmetric AES)?",
            "options": [
                "AES rapidly encrypts large volumes of files locally, while the embedded public key secures the AES key so only the attacker's private key can decrypt.",
                "Asymmetric encryption requires zero CPU processing resources on target host hardware.",
                "Symmetric encryption keys can be derived mathematically from residual computer volatile RAM artifacts.",
                "Hybrid encryption guarantees that the ransomware payload will never be flagged by signature-based antivirus."
            ],
            "correct_idx": 0,
            "explanation": "Symmetric encryption (AES) is fast for bulk file encryption. Encrypting the AES key with an asymmetric public key ensures only the holder of the private key can restore files.",
            "option_explanations": {
                "A": "Correct: Hybrid cryptography combines the high speed of symmetric ciphers with the key secrecy of asymmetric cryptography.",
                "B": "Incorrect: Asymmetric ciphers are computationally heavy, which is why symmetric ciphers are used for bulk data.",
                "C": "Incorrect: RAM wiping during execution prevents trivial symmetric key recovery.",
                "D": "Incorrect: Cryptographic design does not inherently evade behavioral EDR or heuristic antivirus scanners."
            },
            "category": "Ransomware"
        },
        {
            "question": "If active ransomware encryption is detected underway on a critical enterprise server, what is the immediate containment step?",
            "options": [
                "Isolate the host from the network immediately (disconnect Ethernet / disable Wi-Fi) without powering off the machine.",
                "Immediately format all storage volumes and reinstall the operating system from scratch.",
                "Initiate communication with threat actors via the dark web negotiation link to request a trial decryption.",
                "Copy all currently encrypted files to the primary corporate cloud storage repository."
            ],
            "correct_idx": 0,
            "explanation": "Network isolation prevents lateral movement and file share encryption while preserving volatile memory (RAM) for forensic investigation.",
            "option_explanations": {
                "A": "Correct: Network isolation stops lateral spread while preserving volatile memory artifacts for incident responders.",
                "B": "Incorrect: Immediate formatting destroys critical forensic evidence and unencrypted data that might be saved.",
                "C": "Incorrect: Negotiation is a high-level management decision, not an immediate technical containment action.",
                "D": "Incorrect: Copying files can spread ransomware binaries or overwrite clean cloud backup revisions."
            },
            "category": "Ransomware"
        },
        {
            "question": "What MITRE ATT&CK technique specifically describes the action of adversaries encrypting data on target systems to interrupt availability?",
            "options": [
                "T1486 (Data Encrypted for Impact).",
                "T1059 (Command and Scripting Interpreter).",
                "T1078 (Valid Accounts).",
                "T1566 (Phishing).",
            ],
            "correct_idx": 0,
            "explanation": "MITRE ATT&CK T1486 is the official enterprise technique ID for Data Encrypted for Impact, under the Impact tactic.",
            "option_explanations": {
                "A": "Correct: T1486 specifically represents adversary encryption of target data to interrupt availability.",
                "B": "Incorrect: T1059 describes the Execution tactic for running scripts (PowerShell, Bash, CMD).",
                "C": "Incorrect: T1078 describes Defense Evasion / Initial Access through legitimate credentials.",
                "D": "Incorrect: T1566 describes Initial Access vectors through malicious email messages."
            },
            "category": "Ransomware"
        },
        {
            "question": "Why do cybersecurity authorities strongly advise organizations against paying extortion ransoms to cybercrime groups?",
            "options": [
                "Payment provides no guarantee of data decryption, finances criminal enterprises, and marks the company as a vulnerable recurring target.",
                "Paying a ransom automatically revokes all enterprise hardware warranties across data center servers.",
                "Decryption keys delivered by attackers invariably contain physical malware that damages computer motherboards.",
                "International network routing protocols automatically block internet connectivity for organizations that make payments."
            ],
            "correct_idx": 0,
            "explanation": "Ransom payments fund criminal operations, offer zero legal or operational guarantee of decryption, and encourage future extortion targeting.",
            "option_explanations": {
                "A": "Correct: Ransom payments incentivize future attacks, violate potential sanctions, and frequently fail to yield working decryptors.",
                "B": "Incorrect: Hardware manufacturer warranties are unaffected by cyber incident financial settlements.",
                "C": "Incorrect: Decryptors are software utilities; software does not cause motherboard physical damage.",
                "D": "Incorrect: BGP/IP routing does not monitor or block organizational financial transactions."
            },
            "category": "Ransomware"
        }
    ],
    "general security": [
        {
            "question": "What is the core principle of the 'Principle of Least Privilege' (PoLP) in enterprise identity and access management?",
            "options": [
                "Users, applications, and services are granted only the minimum access rights necessary to perform their legitimate job duties.",
                "All domain users are assigned local administrator rights to decrease IT helpdesk operational workload.",
                "System permissions are reassigned randomly each week to prevent predictable privilege abuse.",
                "User account credentials and directories are purged and recreated at the beginning of each business quarter."
            ],
            "correct_idx": 0,
            "explanation": "Least Privilege limits the potential damage from compromised accounts or insider threats by restricting permissions strictly to required duties.",
            "option_explanations": {
                "A": "Correct: PoLP restricts access privileges strictly to the minimum required for authorized tasks.",
                "B": "Incorrect: Granting universal admin rights violates foundational security and dramatically increases breach impact.",
                "C": "Incorrect: Random permission assignment creates chaos and policy violations rather than controlled access.",
                "D": "Incorrect: Purging accounts quarterly is disruptive and unrelated to granular permission boundaries."
            },
            "category": "General Security"
        },
        {
            "question": "Which three foundational security principles constitute the classic 'CIA Triad' of information security?",
            "options": [
                "Confidentiality, Integrity, and Availability.",
                "Control, Identification, and Authorization.",
                "Compliance, Inspection, and Auditing.",
                "Cryptography, Interoperability, and Authentication."
            ],
            "correct_idx": 0,
            "explanation": "The CIA Triad (Confidentiality, Integrity, Availability) represents the universal framework for evaluating and designing information security controls.",
            "option_explanations": {
                "A": "Correct: The CIA Triad stands for Confidentiality, Integrity, and Availability.",
                "B": "Incorrect: Control, Identification, and Authorization are access control concepts, not the core triad.",
                "C": "Incorrect: Compliance and auditing relate to regulatory governance.",
                "D": "Incorrect: Cryptography is a technical tool used to support the triad principles."
            },
            "category": "General Security"
        },
        {
            "question": "What architectural attribute makes Multi-Factor Authentication (MFA) substantially more resilient against credential theft than passwords alone?",
            "options": [
                "It mandates verification across two or more independent factor categories (something you know, have, or are).",
                "It automatically enforces 64-character complex entropy requirements on all internal user passwords.",
                "It applies continuous symmetric AES-256 encryption to all outbound network socket connections.",
                "It eliminates the necessity of applying security patches to host operating system kernels."
            ],
            "correct_idx": 0,
            "explanation": "MFA requires factors from different categories (knowledge, possession, inherence), ensuring compromised passwords alone cannot grant access.",
            "option_explanations": {
                "A": "Correct: MFA requires independent factors, preventing account takeover from single stolen credentials.",
                "B": "Incorrect: Password length policies govern password complexity, which is only a single factor (knowledge).",
                "C": "Incorrect: Transport encryption (TLS) secures traffic in transit and is distinct from user authentication.",
                "D": "Incorrect: Software patching is mandatory regardless of the authentication mechanisms in place."
            },
            "category": "General Security"
        },
        {
            "question": "In a Zero Trust Architecture (ZTA), what is the foundational paradigm regarding internal network perimeter trust?",
            "options": [
                "Never trust, always verify every access request regardless of user location or network origin.",
                "Implicitly trust all network packets and connections originating inside the internal corporate firewall perimeter.",
                "Disable all outbound internet access for all devices across the enterprise network permanently.",
                "Allow unrestricted access to internal data repositories as long as the device has an approved MAC address."
            ],
            "correct_idx": 0,
            "explanation": "Zero Trust operates on the principle that threat actors may already reside inside the network; therefore, all requests must be continuously authenticated and authorized.",
            "option_explanations": {
                "A": "Correct: Zero Trust removes implicit trust and enforces continuous validation on every access attempt.",
                "B": "Incorrect: Implicit internal trust is the legacy perimeter model that Zero Trust explicitly replaces.",
                "C": "Incorrect: Zero Trust enables secure business operations rather than disconnecting the network from the internet.",
                "D": "Incorrect: MAC addresses are easily spoofed and do not provide cryptographic identity verification."
            },
            "category": "General Security"
        },
        {
            "question": "Why is structured vulnerability and patch management critical to maintaining enterprise cybersecurity posture?",
            "options": [
                "It remediates known security flaws and code vulnerabilities before threat actors can exploit them in the wild.",
                "It increases total available bandwidth and network throughput across internal corporate switches.",
                "It permanently prevents end users from accidentally modifying or deleting their own local files.",
                "It automatically converts all compiled binary executable files into plain text documentation."
            ],
            "correct_idx": 0,
            "explanation": "Patch management fixes security flaws documented in CVE databases, eliminating known attack vectors before exploitation occurs.",
            "option_explanations": {
                "A": "Correct: Patch management closes documented software vulnerabilities to prevent threat actor exploitation.",
                "B": "Incorrect: Software security updates are designed for vulnerability remediation, not network speed enhancement.",
                "C": "Incorrect: File permission and backup controls protect user data integrity, not security patches.",
                "D": "Incorrect: Patching updates executable code libraries rather than changing binaries into text."
            },
            "category": "General Security"
        },
        {
            "question": "What is a Brute Force authentication attack, and which combination of defensive controls provides the most robust mitigation?",
            "options": [
                "Systematically attempting all possible password permutations; mitigated by account lockout policies, rate limiting, and MFA.",
                "Physical burglary of server room hard drives; mitigated by biometric facility doors and security guards.",
                "Sending fraudulent emails to corporate executives; mitigated by SPF, DKIM, and DMARC DNS records.",
                "Overwhelming core network edge routers with SYN packets; mitigated by CDN DDoS scrubbers."
            ],
            "correct_idx": 0,
            "explanation": "Brute force attacks systematically guess credentials. Account lockouts, progressive rate limiting, and MFA render brute forcing mathematically ineffective.",
            "option_explanations": {
                "A": "Correct: Brute force involves computational password guessing; rate limiting and MFA stop it effectively.",
                "B": "Incorrect: Physical hardware theft describes physical security threats, not brute force authentication attacks.",
                "C": "Incorrect: Deceptive email attacks describe phishing, not computational credential guessing.",
                "D": "Incorrect: SYN packet floods describe Denial of Service (DoS) network volumetric attacks."
            },
            "category": "General Security"
        },
        {
            "question": "What is the fundamental architectural difference between symmetric encryption and asymmetric encryption?",
            "options": [
                "Symmetric uses a single shared secret key for encryption and decryption; asymmetric uses a mathematically linked public/private key pair.",
                "Symmetric algorithms process only plain text data; asymmetric algorithms process only compressed binary media.",
                "Symmetric encryption keys cannot be decrypted; asymmetric encryption keys are freely decipherable without credentials.",
                "Symmetric ciphers operate exclusively over Bluetooth; asymmetric ciphers operate exclusively over Ethernet."
            ],
            "correct_idx": 0,
            "explanation": "Symmetric ciphers (e.g., AES) share one key between sender and receiver. Asymmetric ciphers (e.g., RSA, ECC) use public keys for encryption and private keys for decryption.",
            "option_explanations": {
                "A": "Correct: Symmetric encryption relies on a shared secret; asymmetric utilizes public/private key pairs.",
                "B": "Incorrect: Both cryptographic types can encrypt arbitrary digital data (text, binaries, streams).",
                "C": "Incorrect: Both symmetric and asymmetric ciphers are designed to be decrypted with the appropriate authorized key.",
                "D": "Incorrect: Cryptographic algorithms are transport-independent and function across any network media."
            },
            "category": "General Security"
        },
        {
            "question": "What is the primary operational function of a Web Application Firewall (WAF) deployed in front of web services?",
            "options": [
                "Inspect and filter incoming HTTP/HTTPS traffic to block web application layer attacks like SQL injection and Cross-Site Scripting (XSS).",
                "Monitor physical environmental temperatures and humidity levels inside enterprise server racks.",
                "Automatically archive database transaction logs to physical magnetic tape drives on an hourly basis.",
                "Calculate and process corporate employee monthly payroll deductions and direct deposit disbursements."
            ],
            "correct_idx": 0,
            "explanation": "A WAF inspects Layer 7 web traffic, analyzing HTTP requests and responses to detect and block malicious payloads like SQLi, XSS, and command injection.",
            "option_explanations": {
                "A": "Correct: WAFs protect web applications by filtering Layer 7 traffic against OWASP Top 10 web vulnerabilities.",
                "B": "Incorrect: Environmental sensors monitor physical server room climate conditions.",
                "C": "Incorrect: Database backup utilities and storage appliances manage tape archiving.",
                "D": "Incorrect: Enterprise Resource Planning (ERP) software manages payroll accounting."
            },
            "category": "General Security"
        }
    ],
    "incident response": [
        {
            "question": "According to the PICERL Incident Response lifecycle, what is the core objective of the 'Preparation' phase?",
            "options": [
                "Establishing policies, playbooks, security tooling, communication plans, and team training before an incident occurs.",
                "Formatting infected production server disks to eradicate dormant rootkits during an ongoing breach.",
                "Rebuilding corrupted corporate database clusters from off-site cold storage backup images.",
                "Drafting the comprehensive executive post-mortem review presentation for the board of directors."
            ],
            "correct_idx": 0,
            "explanation": "Preparation establishes the policies, tools, access controls, and training necessary to detect and respond effectively when an incident strikes.",
            "option_explanations": {
                "A": "Correct: The Preparation phase of PICERL focuses on readiness, tools, documentation, and training prior to security events.",
                "B": "Incorrect: Disk formatting and malware removal occur in the Eradication phase.",
                "C": "Incorrect: Rebuilding production systems from backups occurs in the Recovery phase.",
                "D": "Incorrect: Post-mortem executive briefings occur in the Lessons Learned phase."
            },
            "category": "Incident Response"
        },
        {
            "question": "During which phase of the PICERL Incident Response framework do analysts detect anomalies, evaluate alerts, and determine the scope of a potential security breach?",
            "options": [
                "Identification (Detection & Analysis).",
                "Eradication.",
                "Lessons Learned.",
                "Preparation."
            ],
            "correct_idx": 0,
            "explanation": "Identification involves correlating alerts from SIEM/EDR, validating true positives, determining incident severity, and defining the scope of compromise.",
            "option_explanations": {
                "A": "Correct: Identification is the PICERL phase where responders detect, analyze, and scope security incidents.",
                "B": "Incorrect: Eradication removes the root cause and artifacts after identification and containment.",
                "C": "Incorrect: Lessons Learned analyzes post-incident findings after recovery is complete.",
                "D": "Incorrect: Preparation builds response readiness before incidents occur."
            },
            "category": "Incident Response"
        },
        {
            "question": "An incident responder isolates a compromised endpoint from the corporate subnet and revokes the active session tokens of the compromised user account. Which PICERL phase is being executed?",
            "options": [
                "Containment (limiting the spread and preventing further damage).",
                "Preparation.",
                "Recovery.",
                "Lessons Learned."
            ],
            "correct_idx": 0,
            "explanation": "Containment stops the adversary from moving laterally, exfiltrating more data, or expanding damage while the incident is investigated.",
            "option_explanations": {
                "A": "Correct: Isolating hosts and disabling accounts are direct Containment actions to halt attack spread.",
                "B": "Incorrect: Preparation establishes controls and plans before an incident takes place.",
                "C": "Incorrect: Recovery restores systems back into production operation after threats are removed.",
                "D": "Incorrect: Lessons Learned documents post-incident analysis after the event concludes."
            },
            "category": "Incident Response"
        },
        {
            "question": "What is the primary focus of the 'Eradication' phase in the PICERL Incident Response methodology?",
            "options": [
                "Completely removing malware binaries, disabling adversary persistence mechanisms, and closing exploited entry vulnerabilities.",
                "Restoring operational database services back to business-as-usual production capacity.",
                "Conducting a post-incident retrospective meeting with executive stakeholders and department heads.",
                "Monitoring real-time security alerts in the SIEM to discover the initial suspicious login attempt."
            ],
            "correct_idx": 0,
            "explanation": "Eradication cleanses the environment of all threat actor presence, persistence mechanisms (scheduled tasks, backdoors), and patches the initial vulnerability.",
            "option_explanations": {
                "A": "Correct: Eradication removes malware, persistence, backdoors, and remediates the exploited vulnerability.",
                "B": "Incorrect: Restoring services back into production is the objective of the Recovery phase.",
                "C": "Incorrect: Stakeholder retrospective meetings take place during the Lessons Learned phase.",
                "D": "Incorrect: Initial alert monitoring and triage belong to the Identification phase."
            },
            "category": "Incident Response"
        },
        {
            "question": "Validating system integrity, restoring services from verified clean backups, and implementing enhanced monitoring as systems return to production occurs in which PICERL phase?",
            "options": [
                "Recovery.",
                "Containment.",
                "Identification.",
                "Eradication."
            ],
            "correct_idx": 0,
            "explanation": "Recovery brings affected systems safely back into production operations with rigorous validation and testing to ensure normal functionality.",
            "option_explanations": {
                "A": "Correct: Recovery focuses on restoring, testing, and monitoring systems returning to production.",
                "B": "Incorrect: Containment prevents the active spread of the security event.",
                "C": "Incorrect: Identification discovers and determines the scope of the attack.",
                "D": "Incorrect: Eradication removes adversary components and closes vulnerabilities."
            },
            "category": "Incident Response"
        },
        {
            "question": "Why is the 'Lessons Learned' (Post-Incident Review) phase indispensable to an organization's continuous security improvement?",
            "options": [
                "It documents incident timelines, analyzes response efficacy, identifies gaps, and updates playbooks to prevent future recurrence.",
                "It provides an opportunity to publicly attribute disciplinary blame to specific staff members.",
                "It is the phase where active malware binaries are quarantined and deleted from production servers.",
                "It authorizes corporate legal teams to issue immediate financial penalties against external vendors."
            ],
            "correct_idx": 0,
            "explanation": "Lessons Learned analyzes what happened, what went well, and what failed, translating real-world breach data into concrete security enhancements.",
            "option_explanations": {
                "A": "Correct: Lessons Learned identifies procedural and technical gaps to improve defenses and update playbooks.",
                "B": "Incorrect: Effective incident response emphasizes blameless post-mortems focused on systemic root causes.",
                "C": "Incorrect: Malware deletion and remediation occur during the Eradication phase.",
                "D": "Incorrect: Lessons Learned is an engineering and governance review, not a vendor punitive process."
            },
            "category": "Incident Response"
        },
        {
            "question": "During forensic evidence collection in an incident investigation, what is the critical purpose of maintaining a strict 'Chain of Custody'?",
            "options": [
                "Documenting every individual who handled, transferred, and stored digital evidence to verify integrity and legal admissibility.",
                "Permitting multiple system administrators to modify raw disk images concurrently during active triage.",
                "Encrypting forensic disk images so other authorized investigators on the CSIRT cannot inspect the files.",
                "Automatically purging security event log entries older than 24 hours to conserve storage capacity."
            ],
            "correct_idx": 0,
            "explanation": "Chain of custody tracks evidence handling chronologically, proving evidence was unaltered and maintaining admissibility in legal proceedings.",
            "option_explanations": {
                "A": "Correct: Chain of custody preserves evidence provenance and cryptographic hashes for legal and regulatory validity.",
                "B": "Incorrect: Forensic evidence must never be modified; analysts work exclusively on read-only forensic copies.",
                "C": "Incorrect: Evidence should be securely accessible to authorized forensic team members.",
                "D": "Incorrect: Deleting logs destroys critical evidence and violates evidentiary preservation requirements."
            },
            "category": "Incident Response"
        },
        {
            "question": "What is the critical distinction between the 'Containment' and 'Eradication' phases of the PICERL Incident Response model?",
            "options": [
                "Containment isolates the incident to prevent lateral expansion; Eradication eliminates the root cause and adversary foothold.",
                "Containment restores business systems to production; Eradication evaluates initial SIEM alerts.",
                "Containment is conducted exclusively by legal counsel; Eradication is performed exclusively by human resources.",
                "Containment involves procurement of hardware assets; Eradication involves renewing software licenses."
            ],
            "correct_idx": 0,
            "explanation": "Containment buys time by stopping the bleed (isolating systems), while Eradication performs the deep surgery (removing malware, backdoors, and compromised accounts).",
            "option_explanations": {
                "A": "Correct: Containment halts the attack spread, while Eradication completely removes the adversary's artifacts and vulnerabilities.",
                "B": "Incorrect: Restoring systems is Recovery; evaluating alerts is Identification.",
                "C": "Incorrect: Technical containment and eradication are executed primarily by the SOC and CSIRT engineering teams.",
                "D": "Incorrect: Neither phase is defined by asset procurement or software license renewals."
            },
            "category": "Incident Response"
        }
    ]
}

_last_training_indices = {}

def shuffle_and_format_question(
    question_text: str,
    options: List[str],
    correct_idx_or_text_or_letter: Any,
    explanation: str,
    option_explanations: Optional[Dict[str, str]] = None,
    category: Optional[str] = None
) -> dict:
    q_clean = sanitize_text(question_text)
    opts_clean = [sanitize_option(opt) for opt in options]
    expl_clean = sanitize_text(explanation)

    correct_text = ""
    if isinstance(correct_idx_or_text_or_letter, int):
        if 0 <= correct_idx_or_text_or_letter < len(opts_clean):
            correct_text = opts_clean[correct_idx_or_text_or_letter]
    elif str(correct_idx_or_text_or_letter).strip().upper() in ["A", "B", "C", "D"]:
        idx = ord(str(correct_idx_or_text_or_letter).strip().upper()) - 65
        if 0 <= idx < len(opts_clean):
            correct_text = opts_clean[idx]

    if not correct_text:
        sanitized_input = sanitize_option(str(correct_idx_or_text_or_letter))
        for opt in opts_clean:
            if opt.lower() == sanitized_input.lower():
                correct_text = opt
                break
    if not correct_text:
        correct_text = opts_clean[0]

    labels = ["A", "B", "C", "D"]
    paired = []
    for i, opt in enumerate(opts_clean):
        old_letter = labels[i] if i < len(labels) else "A"
        opt_expl = ""
        if isinstance(option_explanations, dict):
            opt_expl = option_explanations.get(old_letter) or option_explanations.get(opt) or ""
        elif isinstance(option_explanations, list) and i < len(option_explanations):
            opt_expl = option_explanations[i]

        is_corr = (opt == correct_text)
        if not opt_expl:
            if is_corr:
                opt_expl = expl_clean or "Correct: This is the technically accurate principle."
            else:
                opt_expl = "Incorrect: This does not accurately describe the target concept."

        paired.append({
            "text": opt,
            "is_correct": is_corr,
            "explanation": sanitize_text(opt_expl)
        })

    # Shuffle paired list so correct answer position varies randomly
    random.shuffle(paired)

    new_options = [p["text"] for p in paired]
    new_correct_idx = next((i for i, p in enumerate(paired) if p["is_correct"]), 0)
    new_correct_letter = labels[new_correct_idx]

    new_option_explanations = {
        labels[i]: p["explanation"] for i, p in enumerate(paired)
    }

    return {
        "question": q_clean,
        "options": new_options,
        "correct_answer": new_correct_letter,
        "explanation": expl_clean,
        "option_explanations": new_option_explanations,
        "category": category or "General Security"
    }

def fallback_generate_training_question(scenario_type: str) -> dict:
    cat_key = "general security"
    st = (scenario_type or "").lower().strip()
    if "phish" in st:
        cat_key = "phishing"
    elif "ransom" in st:
        cat_key = "ransomware"
    elif "incident" in st or "ir" in st:
        cat_key = "incident response"

    bank = TRAINING_FALLBACK_BANK.get(cat_key, TRAINING_FALLBACK_BANK["general security"])
    available = [i for i in range(len(bank)) if i != _last_training_indices.get(cat_key, -1)]
    idx = random.choice(available) if available else 0
    _last_training_indices[cat_key] = idx
    chosen = bank[idx]

    return shuffle_and_format_question(
        question_text=chosen["question"],
        options=chosen["options"],
        correct_idx_or_text_or_letter=chosen["correct_idx"],
        explanation=chosen["explanation"],
        option_explanations=chosen.get("option_explanations"),
        category=chosen.get("category", scenario_type)
    )

def compute_training_metrics(scores: List[dict]) -> dict:
    total_score = sum(s.get('score', 0) for s in scores)
    questions_answered = len(scores)
    non_skipped = [s for s in scores if not s.get('skipped', False)]
    correct_count = sum(1 for s in scores if s.get('correct') is True)
    overall_accuracy = round((correct_count / len(non_skipped) * 100), 1) if non_skipped else 0.0

    # Streak: consecutive correct answers from most recent backwards
    streak = 0
    for s in reversed(scores):
        if s.get('correct') is True:
            streak += 1
        else:
            break

    # Category accuracy breakdown
    categories = ["Phishing", "Ransomware", "General Security", "Incident Response"]
    cat_accuracy = {}
    for cat in categories:
        cat_scores = [
            s for s in scores
            if (s.get('category') or "").lower() == cat.lower()
            or (not s.get('category') and cat == "General Security")
        ]
        c_non_skip = [s for s in cat_scores if not s.get('skipped', False)]
        c_correct = sum(1 for s in cat_scores if s.get('correct') is True)
        c_acc = round((c_correct / len(c_non_skip) * 100), 1) if c_non_skip else 0.0
        cat_accuracy[cat] = {
            "total": len(cat_scores),
            "answered": len(c_non_skip),
            "correct": c_correct,
            "accuracy": c_acc
        }

    # Weakest area: category with at least 3 attempts and lowest accuracy
    qualified = [
        (cat, data["accuracy"])
        for cat, data in cat_accuracy.items()
        if data["answered"] >= 3 or data["total"] >= 3
    ]
    weakest_area = None
    if qualified:
        qualified.sort(key=lambda x: x[1])
        weakest_area = qualified[0][0]

    # Recommended next action
    if weakest_area:
        recommended_next = f"Practice {weakest_area} in Training Mode to improve your lowest scoring domain."
    elif questions_answered == 0:
        recommended_next = "Start with Phishing or General Security in Training Mode to build your baseline score."
    else:
        recommended_next = "Try an Advanced Phishing simulation or an Attack Scenario to test real-world readiness."

    # Score over time
    date_map = {}
    cumulative = 0
    for s in scores:
        ts = s.get('timestamp', '')
        date_str = ts[:10] if len(ts) >= 10 else "Initial"
        score_val = s.get('score', 0)
        cumulative += score_val
        date_map[date_str] = cumulative
    score_over_time = [{"date": d, "score": score_val} for d, score_val in date_map.items()]

    return {
        "total_score": total_score,
        "questions_answered": questions_answered,
        "overall_accuracy": overall_accuracy,
        "current_streak": streak,
        "category_accuracy": cat_accuracy,
        "weakest_area": weakest_area,
        "recommended_next": recommended_next,
        "score_over_time": score_over_time
    }

def fallback_generate_phishing(role: str, difficulty: str, industry: str) -> dict:
    role_clean = role.strip().title() if role else "Employee"
    diff_clean = difficulty.strip().title() if difficulty else "Medium"
    ind_clean = industry.strip().title() if industry else "IT"

    # Normalize difficulty bucket: easy, medium, hard
    diff_key = "medium"
    if "easy" in diff_clean.lower():
        diff_key = "easy"
    elif "hard" in diff_clean.lower() or "advanced" in diff_clean.lower():
        diff_key = "hard"

    # Fictional recipient names by role
    recipients = {
        "Finance": ["Morgan Blake", "Cameron Diaz", "Taylor Vance", "Jordan Reed"],
        "HR": ["Rachel Green", "Samantha Miller", "David Kim", "Elena Rostova"],
        "Student": ["Alex Rivera", "Maya Patel", "Lucas Silva", "Chloe Bennett"],
        "Admin": ["Devon Vance", "Marcus Brody", "Sarah Connor", "Ethan Hunt"],
        "Employee": ["Jordan Taylor", "Chris Evans", "Pat Morgan", "Samira Khan"]
    }
    recipient_name = random.choice(recipients.get(role_clean, recipients["Employee"]))

    # Role-specific template generators
    # Each role has at least 2 distinct templates
    templates = []

    if role_clean == "Finance":
        # Template 1: Vendor Wire & Banking Detail Update
        if diff_key == "easy":
            sender_name = "Global Vendor Accounts Payable"
            sender_email = "billing-dept@acme-vendor-invoices.example"
            reply_to = "urgent-support@free-mail-service.example"
            link_display = "http://verify-bank-details.example/portal"
            link_url = "http://secure-payment-routing.test/login"
            body = (
                f"ATTN: {recipient_name},\n\n"
                f"We noticed an URGENT error with our pending disbursement for the {ind_clean} infrastructure project. "
                "Our banking coordinates have changed effective immediately. Please update our ACH routing number to avoid immediate service cancellation. "
                "Click the verification link below within 2 hours to confirm the update.\n\n"
                f"Portal: {link_display}\n\n"
                "Failure to act immediately will result in an administrative fee.\n\n"
                "Regards,\n"
                f"{sender_name}"
            )
            red_flags = [
                {"flag": "Mismatched Reply-To Address", "evidence": reply_to, "explanation": "The reply-to address routes to an external mail service rather than the vendor domain."},
                {"flag": "Manufactured Artificial Urgency", "evidence": "within 2 hours", "explanation": "Attackers impose unrealistic short deadlines to force hasty actions."},
                {"flag": "Mismatched Link Destination", "evidence": link_display, "explanation": "The visible link text does not match the actual destination host."},
                {"flag": "Coercive Penalty Threat", "evidence": "immediate service cancellation", "explanation": "Threatening service disruption is a social engineering tactic to bypass standard verification."}
            ]
            psychological_triggers = [
                {"trigger": "Urgency", "where_used": "within 2 hours"},
                {"trigger": "Fear", "where_used": "immediate service cancellation"}
            ]
            header = {"spf": "fail", "dkim": "fail", "dmarc": "fail", "notes": "SPF and DMARC failed because the sending server is not authorized for the claimed vendor domain."}
        elif diff_key == "medium":
            sender_name = "Apex Technology Billing Department"
            sender_email = "invoicing@apex-tech-vendor.example"
            reply_to = "ap-updates@apex-tech-vendor.example"
            link_display = "https://apex-tech-vendor.example/vendor/remittance"
            link_url = "http://portal-apex-remittance.test/auth"
            body = (
                f"Dear {recipient_name},\n\n"
                f"In accordance with our quarterly audit for the {ind_clean} service agreement, "
                "our accounts receivable team has transitioned to a new remittance processing portal. "
                "Please review and approve the attached revised payment schedule before the next billing cycle on Friday.\n\n"
                f"Access Secure Portal: {link_display}\n\n"
                "Thank you for your ongoing partnership.\n\n"
                "Sincerely,\n"
                f"{sender_name}\n"
                "Apex Vendor Services Inc."
            )
            red_flags = [
                {"flag": "Lookalike Domain Destination", "evidence": link_url, "explanation": "The actual link destination directs to an unverified secondary portal domain."},
                {"flag": "External Routing Change Request", "evidence": "revised payment schedule", "explanation": "Unsolicited changes to financial routing details require out-of-band phone verification."},
                {"flag": "Subtle Link Discrepancy", "evidence": link_display, "explanation": "The displayed HTTPS link masks a different backend destination URL."}
            ]
            psychological_triggers = [
                {"trigger": "Authority", "where_used": "quarterly audit"},
                {"trigger": "Familiarity", "where_used": "ongoing partnership"}
            ]
            header = {"spf": "pass", "dkim": "pass", "dmarc": "none", "notes": "SPF and DKIM pass for the attacker-registered lookalike domain, but DMARC policy is not enforced."}
        else: # hard
            sender_name = "Evelyn Reed, Corporate Controller"
            sender_email = "evelyn.reed@executive-office-finance.example"
            reply_to = "evelyn.reed@executive-office-finance.example"
            link_display = "https://finance-portal.company-internal.example/secure-auth"
            link_url = "https://finance-portal.company-internal.test/secure-auth"
            body = (
                f"Hi {recipient_name},\n\n"
                f"Please review the confidential wire transfer reconciliation for our {ind_clean} quarterly closing. "
                "I am currently in an executive briefing and need this authorization confirmed prior to the 4:00 PM wire cutoff.\n\n"
                f"Secure Approval Workspace: {link_display}\n\n"
                "Please reach out on Teams if you have any questions.\n\n"
                f"{sender_name}\n"
                "Corporate Controller"
            )
            red_flags = [
                {"flag": "Lookalike Executive Sender Domain", "evidence": "evelyn.reed@executive-office-finance.example", "explanation": "The sender domain mimics internal corporate executive offices but is hosted on external lookalike infrastructure."},
                {"flag": "Subtle Cutoff Pressure", "evidence": "prior to the 4:00 PM wire cutoff", "explanation": "Time-sensitive deadlines create cognitive load to rush procedural compliance."}
            ]
            psychological_triggers = [
                {"trigger": "Authority", "where_used": "Corporate Controller"},
                {"trigger": "Urgency", "where_used": "prior to the 4:00 PM wire cutoff"}
            ]
            header = {"spf": "pass", "dkim": "pass", "dmarc": "pass", "notes": "SPF, DKIM, and DMARC pass because the adversary configured authenticated lookalike infrastructure."}

        templates.append({
            "subject": "Action Required: Revised Vendor Remittance & Bank Detail Confirmation" if diff_key != "easy" else "URGENT: Immediate Vendor Payment Account Change Notice",
            "sender_name": sender_name,
            "sender_email": sender_email,
            "reply_to_email": reply_to,
            "recipient_name": recipient_name,
            "date_sent": "Oct 02, 2026, 09:15 AM",
            "body": body,
            "link_display_text": link_display,
            "link_url": link_url,
            "header_analysis": header,
            "red_flags": red_flags,
            "psychological_triggers": psychological_triggers,
            "safe_response": [
                "Do not click any embedded links or approve payment changes via email.",
                "Call the vendor finance department using the verified phone number on file.",
                "Forward the suspicious message to the internal cybersecurity operations mailbox."
            ],
            "analysis": f"This simulation targets the {role_clean} team using {diff_clean} tactics tailored to the {ind_clean} sector. It manipulates trust in accounts payable workflows to attempt financial diversion."
        })

        # Template 2: Overdue Software Licensing Invoice
        t2_flags = [
            {"flag": "Unsolicited Overdue Invoice", "evidence": "Invoice #INV-98231", "explanation": "Receiving invoices without prior purchase orders is a common phishing indicator."},
            {"flag": "Service Suspension Threat", "evidence": "prevent automatic account suspension", "explanation": "Fear of business interruption induces hasty payments without purchase verification."},
            {"flag": "Deceptive URL Redirection", "evidence": "https://cloudsync-software-renewals.example/invoices/INV-98231", "explanation": "The visible HTTPS link masks an unverified test destination."},
            {"flag": "Lookalike Renewal Domain", "evidence": "notifications@cloudsync-software-renewals.example", "explanation": "The sender domain is a lookalike not registered to the authentic vendor."}
        ]
        if diff_key == "easy":
            t2_active_flags = t2_flags
        elif diff_key == "medium":
            t2_active_flags = t2_flags[:3]
        else:
            t2_active_flags = t2_flags[:2]

        templates.append({
            "subject": f"Notice of Overdue Invoice - {ind_clean} Enterprise License Agreement",
            "sender_name": "CloudSync Licensing Operations",
            "sender_email": "notifications@cloudsync-software-renewals.example",
            "reply_to_email": "support@cloudsync-software-renewals.example",
            "recipient_name": recipient_name,
            "date_sent": "Oct 02, 2026, 11:30 AM",
            "body": (
                f"Hello {recipient_name},\n\n"
                f"Our records indicate that Invoice #INV-98231 for your organization's {ind_clean} software subscription is currently overdue. "
                "To maintain uninterrupted service access and prevent automatic account suspension, please review the outstanding balance.\n\n"
                "Payment Portal: https://cloudsync-software-renewals.example/invoices/INV-98231\n\n"
                "Thank you for your prompt attention.\n\n"
                "Accounts Receivable Team\n"
                "CloudSync Solutions Inc."
            ),
            "link_display_text": "https://cloudsync-software-renewals.example/invoices/INV-98231",
            "link_url": "http://billing-portal-auth.test/pay",
            "header_analysis": {"spf": "pass", "dkim": "pass", "dmarc": "none", "notes": "Authentication passed on the third-party domain, but the site is a phishing gateway."},
            "red_flags": t2_active_flags,
            "psychological_triggers": [
                {"trigger": "Fear", "where_used": "automatic account suspension"},
                {"trigger": "Urgency", "where_used": "prompt attention"}
            ],
            "safe_response": [
                "Verify the invoice number against the company's internal ERP procurement system.",
                "Contact the official vendor representative directly through established channels.",
                "Report the message as a phishing attempt using the corporate email reporting tool."
            ],
            "analysis": f"This scenario tests {role_clean} employees on vendor verification procedures in the {ind_clean} industry."
        })

    elif role_clean == "HR":
        # Template 1: Executive Candidate Resume / Portfolio
        hr_t1_flags = [
            {"flag": "External Candidate Link", "evidence": "https://talent-executive-search.example/candidates/vance-resume", "explanation": "External links claiming to be resumes often lead to credential harvesters or malware droppers."},
            {"flag": "Unvetted Application Channel", "evidence": f"Senior {ind_clean} Director opening", "explanation": "Applications bypassing the official Applicant Tracking System (ATS) should be treated with caution."},
            {"flag": "Hidden URL Redirection", "evidence": "View Candidate Portfolio", "explanation": "The call-to-action redirects to an external test server."},
            {"flag": "Lookalike Executive Search Domain", "evidence": "m.vance.careers@talent-executive-search.example", "explanation": "Sender address uses an external unverified domain."}
        ]
        if diff_key == "easy":
            hr_t1_active = hr_t1_flags
        elif diff_key == "medium":
            hr_t1_active = hr_t1_flags[:3]
        else:
            hr_t1_active = hr_t1_flags[:2]

        templates.append({
            "subject": f"Application for Senior {ind_clean} Leadership Role - Portfolio Review",
            "sender_name": "Marcus Vance",
            "sender_email": "m.vance.careers@talent-executive-search.example",
            "reply_to_email": "m.vance.careers@talent-executive-search.example",
            "recipient_name": recipient_name,
            "date_sent": "Oct 02, 2026, 08:45 AM",
            "body": (
                f"Dear {recipient_name},\n\n"
                f"I am writing to express my interest in the Senior {ind_clean} Director opening at your company. "
                "Per the job listing requirements, I have uploaded my executive portfolio and references to the secure repository link below.\n\n"
                "View Candidate Portfolio: https://talent-executive-search.example/candidates/vance-resume\n\n"
                "I look forward to discussing how my background aligns with your strategic initiatives.\n\n"
                "Best regards,\n"
                "Marcus Vance\n"
                "Executive Candidate"
            ),
            "link_display_text": "https://talent-executive-search.example/candidates/vance-resume",
            "link_url": "http://candidate-document-viewer.test/payload",
            "header_analysis": {"spf": "pass", "dkim": "pass", "dmarc": "none", "notes": "Email passes basic domain authentication but routes candidates to an unvetted hosting platform."},
            "red_flags": hr_t1_active,
            "psychological_triggers": [
                {"trigger": "Curiosity", "where_used": "executive portfolio and references"},
                {"trigger": "Familiarity", "where_used": "strategic initiatives"}
            ],
            "safe_response": [
                "Instruct the applicant to submit all materials strictly through the official corporate career portal.",
                "Do not download files or input credentials on third-party candidate links.",
                "Submit the email to the security team for sandbox analysis."
            ],
            "analysis": f"This simulation evaluates {role_clean} staff resilience against weaponized resume lure files in the {ind_clean} vertical."
        })

        # Template 2: Mandatory Annual Benefits Enrollment Audit
        hr_t2_flags = [
            {"flag": "Lookalike Internal HR Domain", "evidence": "hr-benefits-portal@internal-benefits-review.example", "explanation": "The sender address uses an external lookalike domain rather than the authentic corporate intranet."},
            {"flag": "Time-Sensitive Enrollment Pressure", "evidence": "closes this Friday", "explanation": "Strict deadlines encourage employees to click without verifying the site authenticity."},
            {"flag": "Credential Harvesting Redirect", "evidence": "https://internal-benefits-review.example/enrollment", "explanation": "The link masks a fraudulent single-sign-on credential harvesting destination."},
            {"flag": "Coverage Loss Threat", "evidence": "ensure coverage continuity", "explanation": "Threatening loss of benefits creates emotional pressure to bypass verification."}
        ]
        if diff_key == "easy":
            hr_t2_active = hr_t2_flags
        elif diff_key == "medium":
            hr_t2_active = hr_t2_flags[:3]
        else:
            hr_t2_active = hr_t2_flags[:2]

        templates.append({
            "subject": f"Action Required: Annual {ind_clean} Employee Benefits & Policy Confirmation",
            "sender_name": "Corporate Benefits Team",
            "sender_email": "hr-benefits-portal@internal-benefits-review.example",
            "reply_to_email": "hr-benefits-portal@internal-benefits-review.example",
            "recipient_name": recipient_name,
            "date_sent": "Oct 02, 2026, 01:10 PM",
            "body": (
                f"Hello {recipient_name},\n\n"
                f"The open enrollment window for {ind_clean} health and retirement benefits closes this Friday. "
                "All staff members must log in to the benefits portal to verify their dependent information and acknowledge updated compliance disclosures.\n\n"
                "Benefits Portal: https://internal-benefits-review.example/enrollment\n\n"
                "Please complete this confirmation before the deadline to ensure coverage continuity.\n\n"
                "People Operations Team"
            ),
            "link_display_text": "https://internal-benefits-review.example/enrollment",
            "link_url": "http://sso-benefits-login.test/auth",
            "header_analysis": {"spf": "pass", "dkim": "none", "dmarc": "none", "notes": "Originates from a lookalike domain with partial authentication headers."},
            "red_flags": hr_t2_active,
            "psychological_triggers": [
                {"trigger": "Authority", "where_used": "People Operations Team"},
                {"trigger": "Urgency", "where_used": "closes this Friday"}
            ],
            "safe_response": [
                "Navigate to the benefits portal by typing the verified corporate URL directly in the browser.",
                "Check the sender domain carefully against official company communication channels.",
                "Report the email to the security operations center."
            ],
            "analysis": f"A realistic HR simulation testing compliance and benefits phishing awareness for {ind_clean} organizations."
        })

    elif role_clean in ("Admin", "IT"):
        # Template 1: Critical VPN / SSL Certificate Expiry
        admin_t1_flags = [
            {"flag": "Administrative Credential Solicitation", "evidence": "authenticate with your administrative credentials", "explanation": "Legitimate certificate managers never solicit root or admin credentials via email links."},
            {"flag": "Extreme Operational Urgency", "evidence": "expire in 24 hours", "explanation": "Creating panic about production outages pushes administrators to bypass change management."},
            {"flag": "External Monitoring Domain", "evidence": "alerts@infrastructure-monitoring-service.example", "explanation": "The domain is not part of the internal enterprise monitoring infrastructure."},
            {"flag": "Disruption Coercion", "evidence": "disrupt production authentication", "explanation": "Fear of downtime induces hasty actions without peer review."}
        ]
        if diff_key == "easy":
            admin_t1_active = admin_t1_flags
        elif diff_key == "medium":
            admin_t1_active = admin_t1_flags[:3]
        else:
            admin_t1_active = admin_t1_flags[:2]

        templates.append({
            "subject": f"URGENT: SSL/TLS Certificate Expiration on {ind_clean} Edge Gateway",
            "sender_name": "Cloud Infrastructure Alert",
            "sender_email": "alerts@infrastructure-monitoring-service.example",
            "reply_to_email": "alerts@infrastructure-monitoring-service.example",
            "recipient_name": recipient_name,
            "date_sent": "Oct 02, 2026, 07:30 AM",
            "body": (
                f"Admin Alert for {recipient_name}:\n\n"
                f"The primary wildcard certificate (*.{ind_clean.lower()}-corp.example) for your edge VPN gateway is scheduled to expire in 24 hours. "
                "Failure to rotate the private key will disrupt production authentication for all remote personnel.\n\n"
                "Renew Certificate: https://infrastructure-monitoring-service.example/cert-renew\n\n"
                "Please authenticate with your administrative credentials to trigger automated renewal.\n\n"
                "Infrastructure Automation Service"
            ),
            "link_display_text": "https://infrastructure-monitoring-service.example/cert-renew",
            "link_url": "http://admin-cert-portal.test/login",
            "header_analysis": {"spf": "pass", "dkim": "pass", "dmarc": "pass", "notes": "Valid authentication from an attacker-controlled monitoring lookalike domain."},
            "red_flags": admin_t1_active,
            "psychological_triggers": [
                {"trigger": "Fear", "where_used": "disrupt production authentication"},
                {"trigger": "Urgency", "where_used": "expire in 24 hours"}
            ],
            "safe_response": [
                "Access the internal certificate management dashboard directly through the corporate bastion host.",
                "Never enter privileged credentials on web pages reached through email links.",
                "Review the certificate expiration schedule in the authoritative secrets manager."
            ],
            "analysis": f"Tests {role_clean} personnel against credential-harvesting lures imitating infrastructure monitoring alerts."
        })

        # Template 2: Cloud Storage Quota Exceeded & Purge Warning
        admin_t2_flags = [
            {"flag": "Data Loss Threat", "evidence": "prevent data loss", "explanation": "Threatening irreversible data deletion forces hurried administrative action."},
            {"flag": "External Storage Gateway", "evidence": "storage-admin@cloud-repository-services.example", "explanation": "Storage notifications should originate from verified enterprise cloud tenants."},
            {"flag": "Deceptive Management URL", "evidence": "https://cloud-repository-services.example/quota-management", "explanation": "The visible URL masks an unverified test server destination."},
            {"flag": "Short Purge Deadline", "evidence": "automated purge within 48 hours", "explanation": "Short purge deadlines rush administrators into clicking fake management consoles."}
        ]
        if diff_key == "easy":
            admin_t2_active = admin_t2_flags
        elif diff_key == "medium":
            admin_t2_active = admin_t2_flags[:3]
        else:
            admin_t2_active = admin_t2_flags[:2]

        templates.append({
            "subject": f"Notice: {ind_clean} Cloud Storage Quota Exceeded - Automated Archival Pending",
            "sender_name": "Cloud Storage Administration",
            "sender_email": "storage-admin@cloud-repository-services.example",
            "reply_to_email": "storage-admin@cloud-repository-services.example",
            "recipient_name": recipient_name,
            "date_sent": "Oct 02, 2026, 02:15 PM",
            "body": (
                f"Attention {recipient_name},\n\n"
                f"Your primary {ind_clean} project storage bucket has reached 98.7% capacity. "
                "Per corporate data retention policies, inactive data partitions will be queued for automated purge within 48 hours unless storage tiers are upgraded.\n\n"
                "Manage Quota Allocation: https://cloud-repository-services.example/quota-management\n\n"
                "Review active partitions immediately to prevent data loss.\n\n"
                "Cloud Systems Engineering"
            ),
            "link_display_text": "https://cloud-repository-services.example/quota-management",
            "link_url": "http://cloud-auth-storage.test/upgrade",
            "header_analysis": {"spf": "pass", "dkim": "none", "dmarc": "none", "notes": "Sender domain is not affiliated with the enterprise cloud provider."},
            "red_flags": admin_t2_active,
            "psychological_triggers": [
                {"trigger": "Fear", "where_used": "automated purge within 48 hours"},
                {"trigger": "Authority", "where_used": "Cloud Systems Engineering"}
            ],
            "safe_response": [
                "Log into the official cloud provider management console independently.",
                "Verify actual bucket storage utilization before taking any action.",
                "Alert the security team to block the phishing domain."
            ],
            "analysis": f"Evaluates {role_clean} readiness against storage and infrastructure capacity phishes in {ind_clean} contexts."
        })

    elif role_clean == "Student":
        # Template 1: Financial Aid / Scholarship Disbursement
        student_t1_flags = [
            {"flag": "Unsolicited Financial Award", "evidence": "Achievement Grant of $1,500", "explanation": "Unexpected financial grants designed to evoke excitement and bypass skepticism."},
            {"flag": "Forfeiture Urgency Pressure", "evidence": "forfeited and redistributed after 72 hours", "explanation": "Arbitrary deadlines pressure students into entering sensitive banking details."},
            {"flag": "Non-University Sender Domain", "evidence": "financial-aid@campus-student-awards.example", "explanation": "Official university notices originate from the authoritative .edu domain."},
            {"flag": "Direct Deposit Credential Harvesting", "evidence": "confirm your banking details", "explanation": "Financial aid offices do not ask for bank credentials over email links."}
        ]
        if diff_key == "easy":
            student_t1_active = student_t1_flags
        elif diff_key == "medium":
            student_t1_active = student_t1_flags[:3]
        else:
            student_t1_active = student_t1_flags[:2]

        templates.append({
            "subject": f"Important: {ind_clean} Academic Scholarship Disbursement - Action Required",
            "sender_name": "University Financial Aid Office",
            "sender_email": "financial-aid@campus-student-awards.example",
            "reply_to_email": "financial-aid@campus-student-awards.example",
            "recipient_name": recipient_name,
            "date_sent": "Oct 02, 2026, 10:05 AM",
            "body": (
                f"Dear {recipient_name},\n\n"
                f"You have been selected to receive a supplementary {ind_clean} Academic Achievement Grant of $1,500 for the current semester. "
                "To release the direct deposit disbursement to your student account, please confirm your banking details through the secure student portal.\n\n"
                "Claim Grant Disbursement: https://campus-student-awards.example/claim-aid\n\n"
                "Unclaimed funds will be forfeited and redistributed after 72 hours.\n\n"
                "Office of Student Financial Assistance"
            ),
            "link_display_text": "https://campus-student-awards.example/claim-aid",
            "link_url": "http://student-aid-deposit.test/auth",
            "header_analysis": {"spf": "pass", "dkim": "pass", "dmarc": "none", "notes": "Sent from an external lookalike domain impersonating the university bursar."},
            "red_flags": student_t1_active,
            "psychological_triggers": [
                {"trigger": "Reward", "where_used": "Achievement Grant of $1,500"},
                {"trigger": "Urgency", "where_used": "redistributed after 72 hours"}
            ],
            "safe_response": [
                "Check financial aid status directly in the official campus student information portal.",
                "Never enter banking or login credentials on external links.",
                "Forward the email to the university IT security helpdesk."
            ],
            "analysis": f"Tests student awareness against financial grant and tuition refund lures prevalent in higher education."
        })

        # Template 2: Student Portal Account Suspension
        student_t2_flags = [
            {"flag": "Threat of Schedule Cancellation", "evidence": "cancellation of your current term schedule", "explanation": "Fear of losing enrolled classes induces panic and hasty compliance."},
            {"flag": "External Registrar Address", "evidence": "registrar@academic-records-portal.example", "explanation": "Legitimate university registrars do not operate from external commercial domains."},
            {"flag": "Credential Harvesting Call to Action", "evidence": "Resolve Account Hold", "explanation": "Directs student to a credential-capturing fake portal."},
            {"flag": "Prerequisite Hold Pressure", "evidence": "pending prerequisite verification", "explanation": "Fictional prerequisite blocks create confusion to force instant link clicking."}
        ]
        if diff_key == "easy":
            student_t2_active = student_t2_flags
        elif diff_key == "medium":
            student_t2_active = student_t2_flags[:3]
        else:
            student_t2_active = student_t2_flags[:2]

        templates.append({
            "subject": f"Notice: Incomplete {ind_clean} Course Registration & Student Account Hold",
            "sender_name": "Campus Registrar Support",
            "sender_email": "registrar@academic-records-portal.example",
            "reply_to_email": "registrar@academic-records-portal.example",
            "recipient_name": recipient_name,
            "date_sent": "Oct 02, 2026, 03:40 PM",
            "body": (
                f"Hello {recipient_name},\n\n"
                f"An administrative hold has been placed on your {ind_clean} course enrollment due to pending prerequisite verification. "
                "Failure to clear this hold will result in automated cancellation of your current term schedule.\n\n"
                "Resolve Account Hold: https://academic-records-portal.example/clear-hold\n\n"
                "Please verify your student identity immediately.\n\n"
                "Office of the Registrar"
            ),
            "link_display_text": "https://academic-records-portal.example/clear-hold",
            "link_url": "http://campus-portal-login.test/verify",
            "header_analysis": {"spf": "pass", "dkim": "none", "dmarc": "none", "notes": "Email mimics campus registrar using lookalike domains."},
            "red_flags": student_t2_active,
            "psychological_triggers": [
                {"trigger": "Fear", "where_used": "cancellation of your current term schedule"},
                {"trigger": "Authority", "where_used": "Office of the Registrar"}
            ],
            "safe_response": [
                "Log into the student portal directly by bookmark or official university homepage.",
                "Contact your academic advisor to verify if any real holds exist.",
                "Report the message as a phishing lure to campus cybersecurity."
            ],
            "analysis": f"Simulates academic account hold phishing targeting students in {ind_clean} studies."
        })

    else:
        # Default / Employee Role
        # Template 1: SSO Password Expiration
        emp_t1_flags = [
            {"flag": "Keep Password Social Engineering", "evidence": "Keep your current password", "explanation": "Security policies require setting new passwords rather than keeping existing ones."},
            {"flag": "Urgent Password Expiry Threat", "evidence": "expire in 12 hours", "explanation": "Short expiration windows rush users into entering credentials on fake login portals."},
            {"flag": "In-Person Inconvenience Threat", "evidence": "in-person identity verification", "explanation": "Threatening administrative inconvenience encourages bypassing standard security precautions."},
            {"flag": "Lookalike IAM Security Domain", "evidence": "security-identity@identity-access-management.example", "explanation": "Sender uses an unverified lookalike domain rather than corporate IAM."}
        ]
        if diff_key == "easy":
            emp_t1_active = emp_t1_flags
        elif diff_key == "medium":
            emp_t1_active = emp_t1_flags[:3]
        else:
            emp_t1_active = emp_t1_flags[:2]

        templates.append({
            "subject": f"Security Alert: Your {ind_clean} Enterprise Single Sign-On Password Expires Today",
            "sender_name": "IT Identity Security",
            "sender_email": "security-identity@identity-access-management.example",
            "reply_to_email": "security-identity@identity-access-management.example",
            "recipient_name": recipient_name,
            "date_sent": "Oct 02, 2026, 08:00 AM",
            "body": (
                f"Hello {recipient_name},\n\n"
                f"Your corporate single sign-on password for {ind_clean} enterprise applications will expire in 12 hours. "
                "To maintain continuous access to your email, VPN, and files, you must keep your current password or reset it now.\n\n"
                "Keep Current Password: https://identity-access-management.example/keep-password\n\n"
                "Accounts that expire will require in-person identity verification at the IT helpdesk.\n\n"
                "Global Identity & Access Operations"
            ),
            "link_display_text": "https://identity-access-management.example/keep-password",
            "link_url": "http://sso-auth-login.test/pwd",
            "header_analysis": {"spf": "pass", "dkim": "pass", "dmarc": "none", "notes": "Attacker configured valid SPF/DKIM on lookalike IAM domain."},
            "red_flags": emp_t1_active,
            "psychological_triggers": [
                {"trigger": "Urgency", "where_used": "expire in 12 hours"},
                {"trigger": "Authority", "where_used": "Global Identity & Access Operations"}
            ],
            "safe_response": [
                "Do not click the password reset link in the email.",
                "Change passwords exclusively via Windows Ctrl+Alt+Del or the official internal SSO portal.",
                "Notify the corporate IT helpdesk of the fraudulent notification."
            ],
            "analysis": f"Tests general {role_clean} awareness against ubiquitous IT password expiration phishes in the {ind_clean} industry."
        })

        # Template 2: Payroll Tax Form (W-2) Verification
        emp_t2_flags = [
            {"flag": "Sensitive Payroll Solicitation", "evidence": "direct deposit account details", "explanation": "Financial forms should only be accessed through verified HR self-service portals."},
            {"flag": "Lookalike Payroll Gateway", "evidence": "payroll-disbursements@payroll-management-portal.example", "explanation": "The domain is not part of the official corporate human resources infrastructure."},
            {"flag": "Deceptive Portal Destination", "evidence": "https://payroll-management-portal.example/tax-forms", "explanation": "The link redirects to an unverified test server credential harvester."},
            {"flag": "Tax Filing Discrepancy Coercion", "evidence": "avoid tax filing discrepancies", "explanation": "Inducing anxiety about tax penalties forces employees to act quickly."}
        ]
        if diff_key == "easy":
            emp_t2_active = emp_t2_flags
        elif diff_key == "medium":
            emp_t2_active = emp_t2_flags[:3]
        else:
            emp_t2_active = emp_t2_flags[:2]

        templates.append({
            "subject": f"Action Required: Electronic Tax Form & Payroll Verification for {ind_clean} Personnel",
            "sender_name": "Corporate Payroll Services",
            "sender_email": "payroll-disbursements@payroll-management-portal.example",
            "reply_to_email": "payroll-disbursements@payroll-management-portal.example",
            "recipient_name": recipient_name,
            "date_sent": "Oct 02, 2026, 11:45 AM",
            "body": (
                f"Dear {recipient_name},\n\n"
                f"Your updated electronic wage and tax statement for the {ind_clean} division is now available for review. "
                "Please verify your current residential address and direct deposit account details to avoid tax filing discrepancies.\n\n"
                "Access Payroll Documents: https://payroll-management-portal.example/tax-forms\n\n"
                "Thank you for your prompt cooperation.\n\n"
                "Corporate Payroll & Benefits Team"
            ),
            "link_display_text": "https://payroll-management-portal.example/tax-forms",
            "link_url": "http://payroll-auth-portal.test/login",
            "header_analysis": {"spf": "pass", "dkim": "pass", "dmarc": "none", "notes": "Originates from a registered lookalike domain mimicking payroll software."},
            "red_flags": emp_t2_active,
            "psychological_triggers": [
                {"trigger": "Curiosity", "where_used": "electronic wage and tax statement"},
                {"trigger": "Familiarity", "where_used": "Corporate Payroll & Benefits Team"}
            ],
            "safe_response": [
                "Access payroll documents only by navigating directly to the company's verified HR portal.",
                "Never provide banking or address updates through links received via email.",
                "Report the message to your security operations team."
            ],
            "analysis": f"Tests employee vigilance against tax and payroll lures tailored to the {ind_clean} sector."
        })

    # Pick a template randomly to ensure diversity across repeated calls
    chosen = random.choice(templates)
    return chosen

def fallback_generate_ransomware(attack_vector: str, organization_type: str) -> dict:
    vector = attack_vector.lower()
    org = organization_type.lower()
    
    # 2 distinct 7-step templates per attack vector matching all MITRE and double-extortion rules
    vector_templates = {
        "email": [
            {
                "summary": f"Threat actors send a targeted spearphishing email with a weaponized macro attachment to {organization_type} staff. Upon execution, the malware establishes persistence, harvests credentials, exfiltrates sensitive records, and deploys ransomware encrypting network shares.",
                "steps": [
                    {
                        "step_number": 1,
                        "title": "Weaponized Spearphishing Attachment Ingestion",
                        "description": f"An employee in {organization_type} receives an email with an invoice attachment containing embedded VBA macros.",
                        "tactic": "Initial Access",
                        "technique_id": "T1566.001",
                        "technique_name": "Spearphishing Attachment",
                        "detection_hint": "Email gateway alert for suspicious macro-enabled Office attachments and spoofed sender domain.",
                        "containment_action": "Quarantine email message tenant-wide and purge attachment from mailboxes."
                    },
                    {
                        "step_number": 2,
                        "title": "VBScript Dropper & PowerShell Execution",
                        "description": "The macro executes VBA code to invoke encoded PowerShell and download secondary ransomware payload binaries.",
                        "tactic": "Execution",
                        "technique_id": "T1059.005",
                        "technique_name": "Visual Basic",
                        "detection_hint": "Sysmon Event ID 1 showing excel.exe spawning powershell.exe with Base64 encoded commands.",
                        "containment_action": "Isolate the infected endpoint from the corporate subnet and terminate rogue PowerShell processes."
                    },
                    {
                        "step_number": 3,
                        "title": "Scheduled Task Persistence Establishment",
                        "description": "The payload registers a scheduled task disguised as a system update service to ensure persistence.",
                        "tactic": "Persistence",
                        "technique_id": "T1053.005",
                        "technique_name": "Scheduled Task",
                        "detection_hint": "Windows Security Event ID 4698 recording creation of a scheduled task pointing to AppData binaries.",
                        "containment_action": "Delete the unauthorized scheduled task and revoke execution permissions in user directories."
                    },
                    {
                        "step_number": 4,
                        "title": "EDR Sensor Evasion & Tampering",
                        "description": "The payload modifies local registry settings to unhook antivirus drivers and disable security sensor telemetry.",
                        "tactic": "Defense Evasion",
                        "technique_id": "T1562.001",
                        "technique_name": "Disable or Modify Tools",
                        "detection_hint": "EDR sensor heartbeat timeout and Event ID 7036 showing unexpected security service termination.",
                        "containment_action": "Re-enable tamper protection and force remote reinstall of endpoint security agents."
                    },
                    {
                        "step_number": 5,
                        "title": "Active Directory Domain Enumeration",
                        "description": "Attacker queries LDAP and network shares to catalog connected domain controllers and critical file repositories.",
                        "tactic": "Discovery",
                        "technique_id": "T1087.002",
                        "technique_name": "Domain Account",
                        "detection_hint": "SIEM alert on anomalous volume of LDAP queries originating from a standard workstation.",
                        "containment_action": "Restrict LDAP queries from non-domain controllers and lock compromised user accounts."
                    },
                    {
                        "step_number": 6,
                        "title": "Confidential Data Staging & Exfiltration",
                        "description": "Sensitive customer PII and database archives are compressed and uploaded to an external cloud storage drop.",
                        "tactic": "Exfiltration",
                        "technique_id": "T1567.002",
                        "technique_name": "Exfiltration to Cloud Storage",
                        "detection_hint": "Firewall and proxy logs showing high-volume encrypted uploads to external mega/cloud services.",
                        "containment_action": "Block external storage destination IP/domain at perimeter firewall and revoke API access."
                    },
                    {
                        "step_number": 7,
                        "title": "High-Speed Cryptographic File Encryption",
                        "description": "The ransomware payload executes multi-threaded AES-256 encryption across all mapped drives, displaying a ransom note.",
                        "tactic": "Impact",
                        "technique_id": "T1486",
                        "technique_name": "Data Encrypted for Impact",
                        "detection_hint": "Mass file renaming alerts and sudden spike in storage I/O throughput across file servers.",
                        "containment_action": "Sever network share connections and initiate automated failover to immutable offline backups."
                    }
                ],
                "response_plan": {
                    "immediate_actions": [
                        "Isolate affected workstations and disconnect all network shares immediately",
                        "Revoke compromised Active Directory user credentials and force tenant-wide session resets",
                        "Block C2 command domains and cloud exfiltration IP addresses at the perimeter firewall"
                    ],
                    "recovery_steps": [
                        "Validate the integrity of air-gapped, immutable backups before initiating restoration",
                        "Reimage affected systems from verified golden baseline OS images",
                        "Restore encrypted databases and file shares into clean, segmented recovery networks"
                    ],
                    "lessons_learned": [
                        "Enforce Attack Surface Reduction (ASR) rules blocking Office applications from spawning child processes",
                        "Implement strict egress filtering to prevent unapproved cloud storage uploads",
                        "Conduct regular phishing simulation drills focused on macro and attachment awareness"
                    ]
                },
                "prevention_tips": [
                    {"text": "Block macro execution in Office documents received from the internet via Group Policy", "addresses_step": 1},
                    {"text": "Deploy PowerShell Constrained Language Mode and enforce Application Control policies", "addresses_step": 2},
                    {"text": "Enable endpoint tamper protection to prevent unauthorized stopping of security services", "addresses_step": 4},
                    {"text": "Maintain offline, immutable 3-2-1 backup copies to mitigate ransomware impact", "addresses_step": 7}
                ]
            },
            {
                "summary": f"Adversaries target {organization_type} employees with malicious PDF resumes. Exploiting PDF reader vulnerabilities, they dump memory credentials, exfiltrate business plans, and trigger network-wide ransomware.",
                "steps": [
                    {
                        "step_number": 1,
                        "title": "Targeted HR PDF Attachment Delivery",
                        "description": f"HR personnel in {organization_type} receive a weaponized PDF document claiming to be an executive resume.",
                        "tactic": "Initial Access",
                        "technique_id": "T1566.001",
                        "technique_name": "Spearphishing Attachment",
                        "detection_hint": "Email filter sandbox detonation flags malicious JavaScript embedded in PDF attachment.",
                        "containment_action": "Block sender domain and quarantine inbound emails matching the malicious attachment hash."
                    },
                    {
                        "step_number": 2,
                        "title": "PDF Exploit Payload Execution",
                        "description": "Opening the document exploits a vulnerability in the document reader to execute an embedded shellcode loader.",
                        "tactic": "Execution",
                        "technique_id": "T1204.002",
                        "technique_name": "Malicious File",
                        "detection_hint": "EDR alert on AcroRd32.exe spawning cmd.exe or rundll32.exe.",
                        "containment_action": "Terminate document viewer processes and isolate host from local area network."
                    },
                    {
                        "step_number": 3,
                        "title": "Local Kernel Privilege Escalation",
                        "description": "Payload leverages an unpatched Windows kernel vulnerability to elevate privileges to NT AUTHORITY\\SYSTEM.",
                        "tactic": "Privilege Escalation",
                        "technique_id": "T1068",
                        "technique_name": "Exploitation for Privilege Escalation",
                        "detection_hint": "Sysmon Event ID 10 showing unauthorized memory handle creation targeting privileged processes.",
                        "containment_action": "Deploy emergency kernel patch and quarantine elevated process token."
                    },
                    {
                        "step_number": 4,
                        "title": "Memory Credential Dumping via LSASS",
                        "description": "Attacker injects into LSASS memory space to dump plaintext domain credentials and Kerberos tickets.",
                        "tactic": "Credential Access",
                        "technique_id": "T1003.001",
                        "technique_name": "LSASS Memory",
                        "detection_hint": "Windows Defender Credential Guard alert for unauthorized LSASS memory reading.",
                        "containment_action": "Force password reset for all dumped service accounts and enable Credential Guard."
                    },
                    {
                        "step_number": 5,
                        "title": "Internal Network Service Discovery",
                        "description": "Adversary performs rapid TCP port scanning across private subnets to identify database servers.",
                        "tactic": "Discovery",
                        "technique_id": "T1046",
                        "technique_name": "Network Service Discovery",
                        "detection_hint": "Network IDS alert on SYN sweep across port 445 and 3389.",
                        "containment_action": "Apply dynamic firewall rules to block lateral port scanning from the compromised host."
                    },
                    {
                        "step_number": 6,
                        "title": "Proprietary Data Exfiltration via C2",
                        "description": "Attacker exfiltrates proprietary internal design documents and financial sheets over encrypted HTTPS C2 tunnels.",
                        "tactic": "Exfiltration",
                        "technique_id": "T1041",
                        "technique_name": "Exfiltration Over C2 Channel",
                        "detection_hint": "Network traffic analysis alerting on sustained high-volume TLS sessions to unknown external IP.",
                        "containment_action": "Sever external C2 IP connections at perimeter gateway and capture forensic packet dumps."
                    },
                    {
                        "step_number": 7,
                        "title": "Distributed Ransomware Encryption & Volume Wiping",
                        "description": "Ransomware payload encrypts local and network storage volumes and deletes volume shadow copies.",
                        "tactic": "Impact",
                        "technique_id": "T1486",
                        "technique_name": "Data Encrypted for Impact",
                        "detection_hint": "Windows Event ID showing vssadmin.exe delete shadows execution followed by mass file modification.",
                        "containment_action": "Shut down shared storage nodes and isolate virtual machine hypervisors."
                    }
                ],
                "response_plan": {
                    "immediate_actions": [
                        "Isolate affected subnet segments and cut off C2 communication channels",
                        "Engage incident response retainers and preserve volatile memory for digital forensics",
                        "Notify key stakeholders and activate out-of-band communication protocols"
                    ],
                    "recovery_steps": [
                        "Scan offline backups with updated signatures to ensure no dormant loader implants exist",
                        "Restore core business applications on newly provisioned, hardened servers",
                        "Verify full data consistency and test critical business workflows before bringing online"
                    ],
                    "lessons_learned": [
                        "Enable Windows Defender Credential Guard to prevent memory dumping from LSASS",
                        "Keep PDF and document viewer applications automatically updated and sandboxed",
                        "Enforce network segmentation restricting workstation-to-workstation communication"
                    ]
                },
                "prevention_tips": [
                    {"text": "Deploy automated email sandbox analysis for all incoming PDF attachments", "addresses_step": 1},
                    {"text": "Enable Windows Credential Guard to protect memory credentials from dumping", "addresses_step": 4},
                    {"text": "Enforce strict network microsegmentation to block internal reconnaissance sweeps", "addresses_step": 5},
                    {"text": "Maintain offline immutable backups and restrict vssadmin deletion privileges", "addresses_step": 7}
                ]
            }
        ],
        "usb": [
            {
                "summary": f"Attackers drop trojanized USB flash drives outside {organization_type} facilities. When an employee plugs the device in, malware executes, bypasses UAC, exfiltrates local files, and encrypts network-attached storage.",
                "steps": [
                    {
                        "step_number": 1,
                        "title": "Infected Removable Media Insertion",
                        "description": f"An employee at {organization_type} connects an infected USB drive found on site to a workstation.",
                        "tactic": "Initial Access",
                        "technique_id": "T1091",
                        "technique_name": "Replication Through Removable Media",
                        "detection_hint": "Endpoint event log recording USB storage mount with executable files in root directory.",
                        "containment_action": "Eject and physically secure the USB drive; isolate the host from the internal network."
                    },
                    {
                        "step_number": 2,
                        "title": "Windows Command Shell Dropper Execution",
                        "description": "The USB payload executes a hidden batch script that launches a staged ransomware binary into memory.",
                        "tactic": "Execution",
                        "technique_id": "T1059.003",
                        "technique_name": "Windows Command Shell",
                        "detection_hint": "Process execution alert for cmd.exe running automated scripts from removable drive path.",
                        "containment_action": "Kill parent command shell processes and quarantine dropped temporary binaries."
                    },
                    {
                        "step_number": 3,
                        "title": "User Account Control (UAC) Bypass",
                        "description": "The binary exploits a Windows elevation mechanism to execute with elevated administrative privileges.",
                        "tactic": "Privilege Escalation",
                        "technique_id": "T1548.002",
                        "technique_name": "Bypass User Account Control",
                        "detection_hint": "Sysmon Event ID 1 showing process elevating token without triggering standard UAC prompt.",
                        "containment_action": "Downgrade user account privileges and enforce AlwaysNotify UAC policy."
                    },
                    {
                        "step_number": 4,
                        "title": "Payload Obfuscation & Memory Injection",
                        "description": "Ransomware decrypts its core payload in memory to bypass static antivirus file system scanning.",
                        "tactic": "Defense Evasion",
                        "technique_id": "T1027",
                        "technique_name": "Obfuscated Files or Information",
                        "detection_hint": "EDR memory scan detects unbacked executable memory region in svchost.exe.",
                        "containment_action": "Terminate corrupted system process and initiate full EDR memory cleanup."
                    },
                    {
                        "step_number": 5,
                        "title": "Network Share Discovery & Mapping",
                        "description": "Malware discovers accessible Windows SMB shares and network-attached storage (NAS) devices.",
                        "tactic": "Discovery",
                        "technique_id": "T1135",
                        "technique_name": "Network Share Discovery",
                        "detection_hint": "Anomalous NetShareEnum queries originating from an unprivileged client workstation.",
                        "containment_action": "Disable administrative SMB shares and restrict NAS access control lists."
                    },
                    {
                        "step_number": 6,
                        "title": "Staged Document Exfiltration",
                        "description": "Confidential customer contracts and payroll spreadsheets are collected and uploaded via alternative protocol.",
                        "tactic": "Exfiltration",
                        "technique_id": "T1048.003",
                        "technique_name": "Exfiltration Over Alternative Protocol",
                        "detection_hint": "Firewall logs showing abnormal outbound FTP/HTTPS traffic to untrusted IP address.",
                        "containment_action": "Block outbound connections to destination IP and revoke exposed user credentials."
                    },
                    {
                        "step_number": 7,
                        "title": "Network Share File Encryption",
                        "description": "Ransomware locks business files across all accessible network shares, leaving ransom notes on user desktops.",
                        "tactic": "Impact",
                        "technique_id": "T1486",
                        "technique_name": "Data Encrypted for Impact",
                        "detection_hint": "Storage activity spike and mass generation of '.locked' file extensions on file server.",
                        "containment_action": "Halt storage services immediately to prevent further encryption propagation."
                    }
                ],
                "response_plan": {
                    "immediate_actions": [
                        "Physically confiscate all unauthorized USB devices across the facility",
                        "Disconnect infected endpoints and network storage from the corporate LAN",
                        "Implement emergency Group Policy blocking USB storage devices company-wide"
                    ],
                    "recovery_steps": [
                        "Perform full hardware and firmware scans on affected endpoints",
                        "Restore encrypted file shares from immutable offline snapshot backups",
                        "Verify operating system integrity on all systems mounted to during the incident"
                    ],
                    "lessons_learned": [
                        "Enforce strict USB port blocking via Group Policy and endpoint management tools",
                        "Implement physical security controls and clear employee guidelines on lost media",
                        "Deploy automated device control policies restricting removable media execution"
                    ]
                },
                "prevention_tips": [
                    {"text": "Disable AutoRun and enforce USB mass storage device blocking via Group Policy", "addresses_step": 1},
                    {"text": "Configure UAC settings to Always Notify and restrict local administrator accounts", "addresses_step": 3},
                    {"text": "Implement network segmentation to prevent workstations from discovering NAS admin shares", "addresses_step": 5},
                    {"text": "Maintain offline, encrypted immutable backups to ensure zero data loss during encryption", "addresses_step": 7}
                ]
            },
            {
                "summary": f"Attackers utilize compromised vendor firmware on USB drives to infiltrate {organization_type}. Deploying stealthy lockers, they exfiltrate operational logs and paralyze core local workstations.",
                "steps": [
                    {
                        "step_number": 1,
                        "title": "Vendor Hardware Update Insertion",
                        "description": f"A maintenance technician connects a vendor USB stick to {organization_type} workstations for an update.",
                        "tactic": "Initial Access",
                        "technique_id": "T1091",
                        "technique_name": "Replication Through Removable Media",
                        "detection_hint": "USB device insertion log matching untrusted hardware vendor ID.",
                        "containment_action": "Unplug USB drive and isolate maintenance workstation from production network."
                    },
                    {
                        "step_number": 2,
                        "title": "Malicious Installer Binary Execution",
                        "description": "User clicks the installer package, which runs an embedded obfuscated dropper in the background.",
                        "tactic": "Execution",
                        "technique_id": "T1204.002",
                        "technique_name": "Malicious File",
                        "detection_hint": "Endpoint detection alert on setup.exe dropping secondary DLLs into Temp folder.",
                        "containment_action": "Terminate installer process tree and quarantine dropped binaries."
                    },
                    {
                        "step_number": 3,
                        "title": "Local Administrator Account Creation",
                        "description": "The payload adds a hidden administrative account to maintain persistence across reboots.",
                        "tactic": "Persistence",
                        "technique_id": "T1078.002",
                        "technique_name": "Domain Accounts",
                        "detection_hint": "Windows Security Event ID 4720 recording new user account creation with elevated rights.",
                        "containment_action": "Disable the rogue user account and audit active administrative accounts."
                    },
                    {
                        "step_number": 4,
                        "title": "Local Security Tool Disablement",
                        "description": "Attacker terminates antivirus services and modifies Windows Defender exclusion paths.",
                        "tactic": "Defense Evasion",
                        "technique_id": "T1562.001",
                        "technique_name": "Disable or Modify Tools",
                        "detection_hint": "Event ID 5001 recorded when Windows Defender real-time protection is disabled.",
                        "containment_action": "Enforce Group Policy overriding local exclusions and restart security services."
                    },
                    {
                        "step_number": 5,
                        "title": "Lateral SMB Admin Share Connection",
                        "description": "Using compromised credentials, attacker moves laterally to secondary workstations over SMB.",
                        "tactic": "Lateral Movement",
                        "technique_id": "T1021.002",
                        "technique_name": "SMB/Windows Admin Shares",
                        "detection_hint": "Event ID 4624 Type 3 network logon from workstation to workstation on port 445.",
                        "containment_action": "Block workstation-to-workstation SMB connections via host firewalls."
                    },
                    {
                        "step_number": 6,
                        "title": "System Diagnostic & Archive Collection",
                        "description": "Attacker packages operational database backups and credential logs into compressed archives.",
                        "tactic": "Collection",
                        "technique_id": "T1560.001",
                        "technique_name": "Archive via Utility",
                        "detection_hint": "EDR alert on command-line utility archiving system databases in background.",
                        "containment_action": "Quarantine compressed archives and verify data exposure scope."
                    },
                    {
                        "step_number": 7,
                        "title": "Multi-Endpoint Ransomware Encryption",
                        "description": "Ransomware executes across all compromised systems, locking local drives and demanding cryptocurrency.",
                        "tactic": "Impact",
                        "technique_id": "T1486",
                        "technique_name": "Data Encrypted for Impact",
                        "detection_hint": "Antivirus alert on mass file modification and deployment of ransom instructions.",
                        "containment_action": "Power down unencrypted systems immediately and initiate recovery from cold backups."
                    }
                ],
                "response_plan": {
                    "immediate_actions": [
                        "Isolate all workstations that had external USB drives mounted recently",
                        "Revoke local administrator passwords across all enterprise endpoints",
                        "Halt inter-workstation SMB communications across the local subnet"
                    ],
                    "recovery_steps": [
                        "Reimage compromised machines from known-good golden baseline images",
                        "Restore operational database backups from verified immutable storage",
                        "Conduct thorough post-incident forensic validation on all connected endpoints"
                    ],
                    "lessons_learned": [
                        "Establish dedicated, isolated kiosk systems for scanning vendor removable media",
                        "Enforce Local Administrator Password Solution (LAPS) to prevent credential reuse",
                        "Deploy host-based firewall rules blocking all lateral SMB traffic between endpoints"
                    ]
                },
                "prevention_tips": [
                    {"text": "Prohibit direct connection of untrusted vendor USB drives on production workstations", "addresses_step": 1},
                    {"text": "Deploy Microsoft LAPS to ensure unique local administrator passwords on all hosts", "addresses_step": 3},
                    {"text": "Block workstation-to-workstation SMB traffic using Windows Defender Firewall", "addresses_step": 5},
                    {"text": "Maintain offline immutable backups following the 3-2-1 backup strategy", "addresses_step": 7}
                ]
            }
        ],
        "rdp": [
            {
                "summary": f"Attackers brute-force an internet-exposed RDP endpoint at {organization_type}. After escalating privileges and blinding sensors, they exfiltrate customer databases and deploy enterprise-wide ransomware.",
                "steps": [
                    {
                        "step_number": 1,
                        "title": "Exposed RDP Port Brute-Force",
                        "description": f"Threat actors identify an internet-facing RDP port at {organization_type} and brute-force weak credentials.",
                        "tactic": "Initial Access",
                        "technique_id": "T1133",
                        "technique_name": "External Remote Services",
                        "detection_hint": "Windows Security Event ID 4625 (repeated failed logons) followed by Event ID 4624 (successful logon).",
                        "containment_action": "Block attacker source IP at edge firewall and disable external RDP access immediately."
                    },
                    {
                        "step_number": 2,
                        "title": "Interactive PowerShell Script Execution",
                        "description": "Attacker connects via RDP session and launches PowerShell to download ransomware staging tools.",
                        "tactic": "Execution",
                        "technique_id": "T1059.001",
                        "technique_name": "PowerShell",
                        "detection_hint": "PowerShell Script Block Logging (Event ID 4104) capturing malicious download cradles.",
                        "containment_action": "Kill active interactive RDP session and terminate PowerShell child processes."
                    },
                    {
                        "step_number": 3,
                        "title": "Security Sensor & Log Disablement",
                        "description": "Attacker modifies registry values to disable real-time EDR scanning and clear Windows event logs.",
                        "tactic": "Defense Evasion",
                        "technique_id": "T1562.001",
                        "technique_name": "Disable or Modify Tools",
                        "detection_hint": "Event ID 1102 (The audit log was cleared) and EDR sensor communication failure.",
                        "containment_action": "Restore tamper protection policies and restart centralized SIEM log streaming."
                    },
                    {
                        "step_number": 4,
                        "title": "LSASS Memory Credential Harvesting",
                        "description": "Adversary dumps memory credentials to obtain domain administrator passwords for lateral movement.",
                        "tactic": "Credential Access",
                        "technique_id": "T1003.001",
                        "technique_name": "LSASS Memory",
                        "detection_hint": "Sysmon Event ID 10 showing unauthorized process querying lsass.exe memory handle.",
                        "containment_action": "Reset all domain administrator passwords and invalidate Kerberos ticket-granting tickets."
                    },
                    {
                        "step_number": 5,
                        "title": "Lateral RDP Pivot to Domain Controller",
                        "description": "Using compromised domain credentials, attacker establishes RDP sessions to internal server subnets.",
                        "tactic": "Lateral Movement",
                        "technique_id": "T1021.001",
                        "technique_name": "Remote Desktop Protocol",
                        "detection_hint": "Event ID 4624 Type 10 logon between internal server subnets during unusual hours.",
                        "containment_action": "Block internal RDP routing and require multi-factor jump hosts for server administration."
                    },
                    {
                        "step_number": 6,
                        "title": "Database Staging & Cloud Exfiltration",
                        "description": "Attacker archives customer databases and exfiltrates them to external cloud storage for double extortion.",
                        "tactic": "Exfiltration",
                        "technique_id": "T1567.002",
                        "technique_name": "Exfiltration to Cloud Storage",
                        "detection_hint": "VPC flow logs and perimeter proxy alerting on large outbound uploads to cloud providers.",
                        "containment_action": "Block exfiltration destination URL at proxy and revoke cloud API credentials."
                    },
                    {
                        "step_number": 7,
                        "title": "Enterprise Storage Encryption",
                        "description": "Ransomware payload encrypts core server volumes and database tables, demanding ransom for decryption.",
                        "tactic": "Impact",
                        "technique_id": "T1486",
                        "technique_name": "Data Encrypted for Impact",
                        "detection_hint": "Mass file write operations and appearance of ransom instructions across server drives.",
                        "containment_action": "Disconnect storage appliances from network and initiate recovery from offline immutable backups."
                    }
                ],
                "response_plan": {
                    "immediate_actions": [
                        "Close all internet-exposed RDP ports and place remote access strictly behind MFA VPNs",
                        "Terminate all active RDP sessions and force domain-wide password resets",
                        "Isolate compromised servers from internal network segments"
                    ],
                    "recovery_steps": [
                        "Validate the integrity of offline immutable backups before restoring data",
                        "Rebuild affected server infrastructure from clean baseline images",
                        "Perform comprehensive network vulnerability scans before restoring services"
                    ],
                    "lessons_learned": [
                        "Never expose RDP (port 3389) directly to the public internet",
                        "Enforce Multi-Factor Authentication (MFA) on all external access solutions",
                        "Implement account lockout policies and rate limiting on remote login endpoints"
                    ]
                },
                "prevention_tips": [
                    {"text": "Disable public-facing RDP ports and require secure MFA VPN access", "addresses_step": 1},
                    {"text": "Enable Windows Credential Guard to prevent LSASS memory credential harvesting", "addresses_step": 4},
                    {"text": "Restrict internal RDP access to dedicated, hardened administrative jump hosts", "addresses_step": 5},
                    {"text": "Maintain offline, air-gapped immutable backups to guarantee recovery", "addresses_step": 7}
                ]
            },
            {
                "summary": f"Attackers leverage stolen VPN credentials to enter {organization_type}. Exploiting hypervisors, they exfiltrate virtual disk snapshots and deploy ransomware across virtual infrastructure.",
                "steps": [
                    {
                        "step_number": 1,
                        "title": "VPN Gateway Credential Abuse",
                        "description": f"Adversary logs into {organization_type} corporate SSL-VPN using credentials purchased on the dark web.",
                        "tactic": "Initial Access",
                        "technique_id": "T1133",
                        "technique_name": "External Remote Services",
                        "detection_hint": "VPN login telemetry showing successful authentication from anomalous geographic location without MFA.",
                        "containment_action": "Terminate active VPN session and revoke compromised user credentials."
                    },
                    {
                        "step_number": 2,
                        "title": "Automated PowerShell Network Sweeping",
                        "description": "Attacker runs automated PowerShell scripts to probe management interfaces on internal hypervisors.",
                        "tactic": "Execution",
                        "technique_id": "T1059.001",
                        "technique_name": "PowerShell",
                        "detection_hint": "PowerShell operational logs recording rapid Test-NetConnection loops across server VLANs.",
                        "containment_action": "Block VPN subnet from reaching server management interfaces."
                    },
                    {
                        "step_number": 3,
                        "title": "Hypervisor Vulnerability Exploitation",
                        "description": "Attacker exploits an unpatched vulnerability in virtualization management software to achieve root privileges.",
                        "tactic": "Privilege Escalation",
                        "technique_id": "T1068",
                        "technique_name": "Exploitation for Privilege Escalation",
                        "detection_hint": "Web server crash log and abnormal child process spawned by hypervisor management daemon.",
                        "containment_action": "Apply hypervisor vendor security patch and isolate virtualization control plane."
                    },
                    {
                        "step_number": 4,
                        "title": "Hypervisor Cluster Port Discovery",
                        "description": "Attacker scans internal subnets to catalog connected storage arrays and secondary hypervisor nodes.",
                        "tactic": "Discovery",
                        "technique_id": "T1046",
                        "technique_name": "Network Service Discovery",
                        "detection_hint": "Network IDS alerts on port scan targeting ESXi/vCenter management ports.",
                        "containment_action": "Isolate virtualization management network onto a dedicated out-of-band VLAN."
                    },
                    {
                        "step_number": 5,
                        "title": "SMB Administrative Pivot to Backup Repository",
                        "description": "Adversary connects to backup server storage shares using compromised root-equivalent credentials.",
                        "tactic": "Lateral Movement",
                        "technique_id": "T1021.002",
                        "technique_name": "SMB/Windows Admin Shares",
                        "detection_hint": "Event ID 4624 administrative logon to backup storage appliance.",
                        "containment_action": "Sever network connections to backup servers and lock admin accounts."
                    },
                    {
                        "step_number": 6,
                        "title": "VM Snapshot Exfiltration via C2",
                        "description": "Attacker extracts core customer database virtual disk snapshots and exfiltrates them over C2.",
                        "tactic": "Exfiltration",
                        "technique_id": "T1041",
                        "technique_name": "Exfiltration Over C2 Channel",
                        "detection_hint": "High-volume outbound data flow over port 443 originating from virtualization host.",
                        "containment_action": "Block C2 destination IP and terminate exfiltration data streams."
                    },
                    {
                        "step_number": 7,
                        "title": "Virtual Machine Disk Image Encryption",
                        "description": "Ransomware encrypts all virtual machine disk files (.vmdk) directly on the datastore, stopping services.",
                        "tactic": "Impact",
                        "technique_id": "T1486",
                        "technique_name": "Data Encrypted for Impact",
                        "detection_hint": "Storage I/O surge followed by sudden crash and failure of all running virtual machines.",
                        "containment_action": "Shut down hypervisor cluster and switch to air-gapped immutable recovery storage."
                    }
                ],
                "response_plan": {
                    "immediate_actions": [
                        "Enforce immediate MFA on all remote VPN access connections",
                        "Isolate the virtualization management plane from user subnets",
                        "Verify physical security of air-gapped offline backup tapes/disks"
                    ],
                    "recovery_steps": [
                        "Deploy patched, clean hypervisor installations from vendor ISO media",
                        "Restore virtual machine disk images from immutable offline backups",
                        "Conduct rigorous integrity checks on customer data before restoring online access"
                    ],
                    "lessons_learned": [
                        "Mandate hardware-token MFA for all external remote access solutions",
                        "Keep hypervisor and virtualization management appliances patched and isolated",
                        "Implement immutable write-once-read-many (WORM) storage for all enterprise backups"
                    ]
                },
                "prevention_tips": [
                    {"text": "Mandate hardware token Multi-Factor Authentication for all corporate VPN logins", "addresses_step": 1},
                    {"text": "Apply hypervisor vendor security updates immediately upon release", "addresses_step": 3},
                    {"text": "Isolate virtualization management interfaces on a dedicated, non-routable VLAN", "addresses_step": 4},
                    {"text": "Store enterprise backups on immutable, air-gapped WORM storage repositories", "addresses_step": 7}
                ]
            }
        ],
        "link": [
            {
                "summary": f"An employee at {organization_type} clicks a malicious link disguised as a software patch. A drive-by browser exploit executes, disables security tools, exfiltrates sensitive files, and deploys ransomware.",
                "steps": [
                    {
                        "step_number": 1,
                        "title": "Drive-by Malicious Link Exploitation",
                        "description": f"An employee at {organization_type} navigates to a deceptive link triggering a drive-by download exploit.",
                        "tactic": "Initial Access",
                        "technique_id": "T1189",
                        "technique_name": "Drive-by Compromise",
                        "detection_hint": "Web proxy alert on connection to newly registered high-risk domain with malicious payload headers.",
                        "containment_action": "Block malicious URL across web proxy and isolate user workstation from corporate network."
                    },
                    {
                        "step_number": 2,
                        "title": "Browser Shellcode Execution & PowerShell Invocation",
                        "description": "Browser vulnerability execution triggers PowerShell in memory to download the secondary ransomware payload.",
                        "tactic": "Execution",
                        "technique_id": "T1059.001",
                        "technique_name": "PowerShell",
                        "detection_hint": "Sysmon Event ID 1 showing browser process spawning powershell.exe with encoded arguments.",
                        "containment_action": "Terminate browser and PowerShell process trees and revoke local user access."
                    },
                    {
                        "step_number": 3,
                        "title": "Local Kernel Privilege Escalation",
                        "description": "Attacker leverages local exploit to escalate privileges from standard user to SYSTEM administrator.",
                        "tactic": "Privilege Escalation",
                        "technique_id": "T1068",
                        "technique_name": "Exploitation for Privilege Escalation",
                        "detection_hint": "Security log alert for unauthorized privilege token elevation on workstation.",
                        "containment_action": "Apply emergency kernel patch and quarantine system process."
                    },
                    {
                        "step_number": 4,
                        "title": "Endpoint Antivirus Sensor Disablement",
                        "description": "Payload terminates endpoint antivirus services and unhooks kernel monitoring drivers.",
                        "tactic": "Defense Evasion",
                        "technique_id": "T1562.001",
                        "technique_name": "Disable or Modify Tools",
                        "detection_hint": "EDR heartbeat failure notification and Windows Defender tamper detection alerts.",
                        "containment_action": "Re-enable tamper protection and reinstall security monitoring agent."
                    },
                    {
                        "step_number": 5,
                        "title": "System Information & Network Share Discovery",
                        "description": "Attacker queries system configurations and catalogs mapped network drives and database paths.",
                        "tactic": "Discovery",
                        "technique_id": "T1082",
                        "technique_name": "System Information Discovery",
                        "detection_hint": "Process monitoring recording automated systeminfo and net view queries.",
                        "containment_action": "Block discovery queries and disconnect network shares on the host."
                    },
                    {
                        "step_number": 6,
                        "title": "Sensitive Document Staging & Cloud Exfiltration",
                        "description": "Proprietary contracts and database files are encrypted into zip files and uploaded to external cloud storage.",
                        "tactic": "Exfiltration",
                        "technique_id": "T1567.002",
                        "technique_name": "Exfiltration to Cloud Storage",
                        "detection_hint": "Web proxy alerts on large volume outbound file upload to cloud storage endpoint.",
                        "containment_action": "Block cloud storage URL and revoke exposed user session tokens."
                    },
                    {
                        "step_number": 7,
                        "title": "Local Drive & Network Share File Encryption",
                        "description": "Ransomware payload encrypts all local documents and mapped network drives, displaying ransom demands.",
                        "tactic": "Impact",
                        "technique_id": "T1486",
                        "technique_name": "Data Encrypted for Impact",
                        "detection_hint": "Mass file renaming alerts and high CPU utilization by cryptographic encryption worker.",
                        "containment_action": "Sever network connections and restore files from air-gapped immutable backups."
                    }
                ],
                "response_plan": {
                    "immediate_actions": [
                        "Block the malicious domain at the DNS and web proxy levels",
                        "Isolate the affected workstation and disconnect all mapped network shares",
                        "Trigger enterprise-wide threat hunting for the downloaded payload hash"
                    ],
                    "recovery_steps": [
                        "Reimage the infected workstation with updated browser and OS security patches",
                        "Restore encrypted files from verified offline immutable backups",
                        "Validate that no residual persistence mechanisms remain across corporate endpoints"
                    ],
                    "lessons_learned": [
                        "Implement web content filtering and DNS-layer domain reputation security",
                        "Keep web browsers and extensions automatically updated and isolated in sandboxes",
                        "Maintain immutable offsite backups following the 3-2-1 rule"
                    ]
                },
                "prevention_tips": [
                    {"text": "Deploy DNS-layer security filtering to block access to untrusted, newly registered domains", "addresses_step": 1},
                    {"text": "Enable browser isolation and automated patching for all employee web browsers", "addresses_step": 2},
                    {"text": "Enforce endpoint tamper protection to prevent tampering with security services", "addresses_step": 4},
                    {"text": "Maintain offline immutable backups to protect data against ransomware encryption", "addresses_step": 7}
                ]
            },
            {
                "summary": f"A deceptive browser update link prompts {organization_type} staff to download a malicious installer. Staged trojans harvest credentials, exfiltrate data, and execute double-extortion ransomware.",
                "steps": [
                    {
                        "step_number": 1,
                        "title": "Fake Browser Update Link Prompt",
                        "description": f"An employee visiting a compromised website is presented with a fake browser update prompt.",
                        "tactic": "Initial Access",
                        "technique_id": "T1189",
                        "technique_name": "Drive-by Compromise",
                        "detection_hint": "Web filter alert on redirect to deceptive fake update hosting domain.",
                        "containment_action": "Block domain tenant-wide and alert employee against downloading the update."
                    },
                    {
                        "step_number": 2,
                        "title": "Malicious Installer Package Execution",
                        "description": "User runs the downloaded installer, which executes an embedded obfuscated loader binary.",
                        "tactic": "Execution",
                        "technique_id": "T1204.002",
                        "technique_name": "Malicious File",
                        "detection_hint": "EDR alert on unrecognized unsigned installer executing from Downloads folder.",
                        "containment_action": "Terminate installer process and quarantine downloaded file hash."
                    },
                    {
                        "step_number": 3,
                        "title": "Payload Obfuscation via Cryptor",
                        "description": "Loader uses multi-layer XOR encryption and process hollowing to evade static antivirus scanners.",
                        "tactic": "Defense Evasion",
                        "technique_id": "T1027",
                        "technique_name": "Obfuscated Files or Information",
                        "detection_hint": "Behavioral detection alert on process injection into legitimate Windows binaries.",
                        "containment_action": "Kill injected process and isolate workstation from internal subnet."
                    },
                    {
                        "step_number": 4,
                        "title": "Web Browser Saved Credential Harvesting",
                        "description": "Malware dumps saved passwords and cookies from Chrome and Edge profile databases.",
                        "tactic": "Credential Access",
                        "technique_id": "T1555.003",
                        "technique_name": "Credentials from Web Browsers",
                        "detection_hint": "EDR alert on unauthorized process reading browser SQLite database files.",
                        "containment_action": "Force password reset for all harvested corporate accounts and invalidate web sessions."
                    },
                    {
                        "step_number": 5,
                        "title": "Domain Account & Network Discovery",
                        "description": "Attacker queries domain controller to locate high-value file servers and administrator accounts.",
                        "tactic": "Discovery",
                        "technique_id": "T1087.002",
                        "technique_name": "Domain Account",
                        "detection_hint": "SIEM alert on anomalous volume of LDAP queries from client endpoint.",
                        "containment_action": "Restrict LDAP queries and enforce network segmentation."
                    },
                    {
                        "step_number": 6,
                        "title": "Customer Data Exfiltration",
                        "description": "Harvested customer records and financial sheets are exfiltrated to external drop servers.",
                        "tactic": "Exfiltration",
                        "technique_id": "T1048.003",
                        "technique_name": "Exfiltration Over Alternative Protocol",
                        "detection_hint": "Firewall logs showing high-volume encrypted upload to untrusted external server.",
                        "containment_action": "Block drop server IP at firewall and capture traffic pcaps."
                    },
                    {
                        "step_number": 7,
                        "title": "Enterprise Ransomware File Encryption",
                        "description": "Ransomware payload encrypts local drives and shared folders, creating ransom demand notes.",
                        "tactic": "Impact",
                        "technique_id": "T1486",
                        "technique_name": "Data Encrypted for Impact",
                        "detection_hint": "Mass file renaming and creation of 'DECRYPT_FILES.txt' on system desktop.",
                        "containment_action": "Disconnect storage drives and initiate recovery from offline backups."
                    }
                ],
                "response_plan": {
                    "immediate_actions": [
                        "Block fake update domains across all DNS and web filtering solutions",
                        "Isolate the infected endpoint and disconnect network storage drives",
                        "Reset credentials for all accounts accessed on the compromised machine"
                    ],
                    "recovery_steps": [
                        "Reimage the affected workstation with clean software baseline images",
                        "Restore encrypted file shares from immutable offline backups",
                        "Conduct threat hunting for secondary loader persistence artifacts"
                    ],
                    "lessons_learned": [
                        "Prohibit standard users from downloading and installing executable files",
                        "Deploy centralized enterprise password managers and disable browser password caching",
                        "Implement automated software distribution tools to eliminate manual user updates"
                    ]
                },
                "prevention_tips": [
                    {"text": "Deploy centralized patch management to eliminate manual user-initiated software updates", "addresses_step": 1},
                    {"text": "Enforce AppLocker / Software Restriction Policies blocking unsigned downloads", "addresses_step": 2},
                    {"text": "Disable browser password caching and mandate enterprise password managers", "addresses_step": 4},
                    {"text": "Maintain offline immutable backups to protect against ransomware impact", "addresses_step": 7}
                ]
            }
        ]
    }
    
    # Generic fallback pool (e.g. for unknown or supply-chain vectors)
    default_pool = vector_templates["email"]
    selected_pool = default_pool
    
    if "email" in vector:
        selected_pool = vector_templates["email"]
    elif "usb" in vector:
        selected_pool = vector_templates["usb"]
    elif "rdp" in vector:
        selected_pool = vector_templates["rdp"]
    elif "link" in vector:
        selected_pool = vector_templates["link"]
        
    chosen = random.choice(selected_pool)
    
    raw_steps = chosen["steps"]
    inf_flow = [s["description"] for s in raw_steps]
    
    # De-duplicated mitre mapping
    seen_ids = set()
    mitre_map = []
    for s in raw_steps:
        if s["technique_id"] not in seen_ids:
            seen_ids.add(s["technique_id"])
            mitre_map.append({"id": s["technique_id"], "name": s["technique_name"]})
            
    return {
        "summary": chosen["summary"],
        "infection_flow": inf_flow,
        "mitre_mapping": mitre_map,
        "steps": raw_steps,
        "response_plan": chosen["response_plan"],
        "prevention_tips": chosen["prevention_tips"]
    }

def assign_detection_likelihoods(maturity: str, num_stages: int) -> List[str]:
    m = maturity.lower()
    if "low" in m:
        # Low maturity: mostly Low, at most one Medium
        res = ["Low"] * num_stages
        if num_stages > 0:
            res[-1] = "Medium"
        return res
    elif "high" in m:
        # High maturity: mostly Medium or High, at most one Low
        res = ["High"] * num_stages
        if num_stages > 0:
            res[0] = "Low"
        if num_stages > 1:
            res[1] = "Medium"
        if num_stages > 2:
            res[-1] = "Medium"
        return res
    else:
        # Medium maturity: mix of Low, Medium, High
        pattern = ["Low", "Low", "Medium", "Medium", "High", "High", "Medium", "Low", "Medium", "High"]
        return (pattern * (num_stages // len(pattern) + 1))[:num_stages]


def fallback_generate_attack_scenario(organization_type: str, security_maturity: str) -> dict:
    org_type = organization_type.lower()
    maturity = security_maturity.lower()
    
    # 3 distinct 8-stage templates per organization type fulfilling all MITRE completeness rules
    scenario_templates = {
        "tech startup": [
            {
                "title": "Supply Chain Infiltration & Cloud Key Hijacking",
                "summary": "Adversaries compromise an open-source software dependency used by the engineering team. By injecting a stealthy loader into the dependency tree, the attackers obtain build server execution, harvest cloud API keys, and exfiltrate proprietary source code repository archives.",
                "stages": [
                    {
                        "stage": "Public Repository & Namespace Reconnaissance",
                        "tactic": "Reconnaissance",
                        "techniques": [{"technique_id": "T1595.002", "technique_name": "Vulnerability Scanning"}],
                        "description": "Threat actors scan developer package registries and GitHub repositories to identify unclaimed internal module names.",
                        "impact": "Target organization dependency naming conventions are mapped.",
                        "detection_hint": "Inspect web proxy and repository audit logs for anomalous bulk scraping.",
                        "mitigation": "Register internal package namespaces across public registries and use scoped packages."
                    },
                    {
                        "stage": "Malicious Package Publication",
                        "tactic": "Resource Development",
                        "techniques": [{"technique_id": "T1587.001", "technique_name": "Malware: Software Modules"}],
                        "description": "Attacker uploads a typosquatted package containing an obfuscated Node.js reverse shell payload to the registry.",
                        "impact": "Malicious code is published and ready for automated dependency ingestion.",
                        "detection_hint": "Monitor package repository alerts for newly published packages matching internal names.",
                        "mitigation": "Implement automated software bill-of-materials (SBOM) dependency scanning."
                    },
                    {
                        "stage": "Automated CI/CD Build Ingestion",
                        "tactic": "Initial Access",
                        "techniques": [{"technique_id": "T1195.002", "technique_name": "Supply Chain Compromise: Software Supply Chain"}],
                        "description": "Continuous integration runners pull the backdoored package during an automated pull-request build pipeline.",
                        "impact": "Malicious code gains initial execution on build runner infrastructure.",
                        "detection_hint": "Detect outbound network connections initiated by build runners during dependency resolution.",
                        "mitigation": "Enforce private proxy artifact repositories with strict package hash lockfiles."
                    },
                    {
                        "stage": "Pre-Install Script Execution",
                        "tactic": "Execution",
                        "techniques": [{"technique_id": "T1059.007", "technique_name": "Command and Scripting Interpreter: JavaScript"}],
                        "description": "A package pre-install script triggers Node.js child_process to execute a background payload.",
                        "impact": "Arbitrary shell execution achieved in CI/CD runner container.",
                        "detection_hint": "Sysmon Event ID 1 / process monitoring showing node.exe spawning sh or bash shells.",
                        "mitigation": "Disable pre-install and post-install lifecycle scripts in build configurations."
                    },
                    {
                        "stage": "Environment Variable Secrets Scraping",
                        "tactic": "Credential Access",
                        "techniques": [{"technique_id": "T1552.001", "technique_name": "Unsecured Credentials: Credentials In Files"}],
                        "description": "The payload scans build container environment variables and dotfiles to extract AWS and GitHub tokens.",
                        "impact": "Production deployment access tokens and repository access keys compromised.",
                        "detection_hint": "Audit runtime access to environment variables and secret stores by untrusted build steps.",
                        "mitigation": "Migrate static credentials to short-lived OpenID Connect (OIDC) identity federation."
                    },
                    {
                        "stage": "Cloud Identity & Infrastructure Discovery",
                        "tactic": "Discovery",
                        "techniques": [{"technique_id": "T1087.004", "technique_name": "Account Discovery: Cloud Account"}],
                        "description": "The attacker queries cloud provider identity endpoints to enumerate active roles and permission boundaries.",
                        "impact": "Cloud administrative hierarchy and container registry boundaries discovered.",
                        "detection_hint": "CloudTrail audit logs showing rapid ListRoles and GetAccountAuthorizationDetails requests.",
                        "mitigation": "Enforce strict least-privilege IAM policies and monitor IAM enumeration calls."
                    },
                    {
                        "stage": "Cloud API Infrastructure Hijack",
                        "tactic": "Lateral Movement",
                        "techniques": [{"technique_id": "T1078.004", "technique_name": "Valid Accounts: Cloud Accounts"}],
                        "description": "Attacker uses exfiltrated cloud deployment keys to authenticate directly against production cloud APIs.",
                        "impact": "Attacker achieves administrative control over cloud compute clusters.",
                        "detection_hint": "CloudTrail / Cloud audit logs showing administrative API calls from foreign IP ranges.",
                        "mitigation": "Enforce IP restriction and conditional access policies for cloud administrative actions."
                    },
                    {
                        "stage": "Source Code & Data Exfiltration",
                        "tactic": "Exfiltration",
                        "techniques": [{"technique_id": "T1567.002", "technique_name": "Exfiltration Over Web Service: Cloud Storage"}],
                        "description": "Proprietary core source repositories and customer database dumps are encrypted and uploaded to external cloud storage.",
                        "impact": "Severe intellectual property theft and customer database compromise.",
                        "detection_hint": "VPC Flow Logs and egress monitoring indicating anomalous large uploads to external cloud storage.",
                        "mitigation": "Implement egress traffic filtering and sensitive data loss prevention (DLP) controls."
                    }
                ]
            },
            {
                "title": "OAuth App Consent Phishing & SaaS Environment Takeover",
                "summary": "Attackers craft a malicious third-party OAuth application imitating a popular productivity tool. After tricking a lead software engineer into granting tenant-wide read permissions, the threat actors access internal email, repositories, and cloud configuration files.",
                "stages": [
                    {
                        "stage": "OAuth Application Infrastructure Setup",
                        "tactic": "Resource Development",
                        "techniques": [{"technique_id": "T1583.001", "technique_name": "Acquire Infrastructure: Domains"}],
                        "description": "Threat actors register a deceptive domain and configure an OAuth application requesting broad workspace permissions.",
                        "impact": "Adversary infrastructure ready to deceive staff into granting authorization.",
                        "detection_hint": "Monitor domain registration logs and brand monitoring alerts for lookalike domains.",
                        "mitigation": "Restrict third-party OAuth application consent to approved administrators only."
                    },
                    {
                        "stage": "Targeted Spearphishing for Consent",
                        "tactic": "Initial Access",
                        "techniques": [{"technique_id": "T1566.002", "technique_name": "Spearphishing Link"}],
                        "description": "An urgent collaboration invitation is sent to senior developers urging them to connect the productivity integration.",
                        "impact": "Developer approves OAuth scopes granting persistent token access to Google Workspace and GitHub.",
                        "detection_hint": "Audit SaaS identity provider logs for unusual OAuth grant approvals by end users.",
                        "mitigation": "Enforce strict OAuth app allowlisting and security awareness phishing simulations."
                    },
                    {
                        "stage": "Malicious App Authorization Execution",
                        "tactic": "Execution",
                        "techniques": [{"technique_id": "T1204.002", "technique_name": "User Execution: Malicious File"}],
                        "description": "User clicks the authorization flow executing the token exchange handshake with the adversary server.",
                        "impact": "Adversary obtains valid OAuth refresh and access tokens.",
                        "detection_hint": "OAuth token grant telemetry indicating unusual application publishers.",
                        "mitigation": "Implement centralized app verification and restrict third-party API permissions."
                    },
                    {
                        "stage": "Persistent OAuth Token Integration",
                        "tactic": "Credential Access",
                        "techniques": [{"technique_id": "T1552.001", "technique_name": "Unsecured Credentials: Credentials In Files"}],
                        "description": "The adversary extracts and persists OAuth access tokens and API keys across local profiles.",
                        "impact": "Long-term unauthenticated SaaS access maintained without triggering password changes.",
                        "detection_hint": "Audit log alerts for continuous programmatic access using older OAuth grants.",
                        "mitigation": "Set short maximum token lifetimes and require periodic re-authorization."
                    },
                    {
                        "stage": "SaaS Workspace Enumeration",
                        "tactic": "Discovery",
                        "techniques": [{"technique_id": "T1087.004", "technique_name": "Account Discovery: Cloud Account"}],
                        "description": "The adversary uses valid API tokens to enumerate internal channels, drive folders, and user directories.",
                        "impact": "Confidential internal roadmaps and developer wiki pages cataloged.",
                        "detection_hint": "Cloud Access Security Broker (CASB) alerts on rapid API enumeration across multiple services.",
                        "mitigation": "Implement least-privilege API scope policies and continuous CASB monitoring."
                    },
                    {
                        "stage": "Staging Server Lateral Pivot",
                        "tactic": "Lateral Movement",
                        "techniques": [{"technique_id": "T1021.004", "technique_name": "Remote Services: SSH"}],
                        "description": "Using discovered private SSH keys, the attacker establishes remote SSH tunnels to internal staging environments.",
                        "impact": "Access expanded into internal network perimeter.",
                        "detection_hint": "Network firewall alerts on outbound SSH connections to unfamiliar external IPs.",
                        "mitigation": "Require SSH certificate authentication tied to hardware security keys."
                    },
                    {
                        "stage": "Chat Log & Document Collection",
                        "tactic": "Collection",
                        "techniques": [{"technique_id": "T1114.002", "technique_name": "Email Collection: Remote Email Collection"}],
                        "description": "Attacker downloads archived developer conversations, sensitive attachments, and roadmap documents.",
                        "impact": "Proprietary design discussions and business secrets gathered.",
                        "detection_hint": "CASB telemetry showing massive bulk download operations across cloud drives.",
                        "mitigation": "Enforce data loss prevention rules restricting mass export of workspace files."
                    },
                    {
                        "stage": "Automated Cloud Bucket Exfiltration",
                        "tactic": "Exfiltration",
                        "techniques": [{"technique_id": "T1537", "technique_name": "Transfer Data to Cloud Account"}],
                        "description": "Customer export archives in cloud storage buckets are copied directly to attacker accounts using cloud-native APIs.",
                        "impact": "Loss of sensitive customer analytics and database backup archives.",
                        "detection_hint": "Storage bucket access logs showing massive read and cross-account copy operations.",
                        "mitigation": "Enforce bucket policies preventing cross-account access and encrypt with customer-managed keys."
                    }
                ]
            },
            {
                "title": "Compromised Developer Identity & Cloud Infrastructure Sabotage",
                "summary": "Attackers obtain a developer's session token through infostealer malware on a personal device. Bypassing MFA via session replay, they access source control, inject backdoors, and deploy unauthorized compute instances for resource hijacking.",
                "stages": [
                    {
                        "stage": "Infostealer Malware Session Harvesting",
                        "tactic": "Initial Access",
                        "techniques": [{"technique_id": "T1539", "technique_name": "Steal Web Session Cookie"}],
                        "description": "An infostealer trojan on an employee's personal device extracts active Single Sign-On session cookies.",
                        "impact": "Valid authenticated session tokens obtained without needing to solve MFA prompts.",
                        "detection_hint": "Identity provider risk alerts for session usage with mismatched device fingerprints.",
                        "mitigation": "Enforce device compliance checks and FIDO2 WebAuthn authentication with bound sessions."
                    },
                    {
                        "stage": "Administrative Portal Script Execution",
                        "tactic": "Execution",
                        "techniques": [{"technique_id": "T1059.001", "technique_name": "Command and Scripting Interpreter: PowerShell"}],
                        "description": "Attacker runs automated PowerShell automation scripts using the hijacked developer session token.",
                        "impact": "Automated administrative API queries executed against the cloud tenant.",
                        "detection_hint": "PowerShell Script Block Logging showing cloud management cmdlet execution.",
                        "mitigation": "Restricted administrative PowerShell access and require device-bound certificate authentication."
                    },
                    {
                        "stage": "Privilege Escalation via IAM Role Policy Injection",
                        "tactic": "Privilege Escalation",
                        "techniques": [{"technique_id": "T1078.004", "technique_name": "Valid Accounts: Cloud Accounts"}],
                        "description": "Attacker attaches an administrator access policy to a dormant service account role.",
                        "impact": "Full root-equivalent cloud subscription privileges achieved.",
                        "detection_hint": "CloudTrail Event 'AttachUserPolicy' or 'PutRolePolicy' on high-privilege roles.",
                        "mitigation": "Enforce IAM permission boundaries and require multi-party approval for privilege escalation."
                    },
                    {
                        "stage": "Security Sensor Impairment",
                        "tactic": "Defense Evasion",
                        "techniques": [{"technique_id": "T1562.001", "technique_name": "Impair Defenses: Disable or Modify Tools"}],
                        "description": "Attacker modifies cloud guardrail alarms and suppresses audit log delivery to the security operations team.",
                        "impact": "Cloud monitoring visibility severely degraded across active regions.",
                        "detection_hint": "Cloud audit log alert for 'StopLogging' or 'DeleteDetector' API calls.",
                        "mitigation": "Protect log archives in dedicated write-once accounts with SCP guardrails."
                    },
                    {
                        "stage": "Browser Credential Store Harvesting",
                        "tactic": "Credential Access",
                        "techniques": [{"technique_id": "T1555.003", "technique_name": "Credentials from Password Stores: Web Browsers"}],
                        "description": "Adversary extracts stored credentials and database connection passwords saved in the developer profile.",
                        "impact": "Production database connection strings and passwords compromised.",
                        "detection_hint": "EDR alert on unauthorized process access to browser SQLite vault files.",
                        "mitigation": "Prohibit browser password caching via centralized management policies."
                    },
                    {
                        "stage": "Internal Kubernetes Cluster Discovery",
                        "tactic": "Discovery",
                        "techniques": [{"technique_id": "T1613", "technique_name": "Container and Resource Discovery"}],
                        "description": "The adversary lists active Kubernetes clusters, namespaces, and running microservices.",
                        "impact": "Topology of customer-facing application services exposed.",
                        "detection_hint": "Kubernetes audit log anomalies showing rapid cluster-wide 'get' and 'list' requests.",
                        "mitigation": "Implement role-based access control (RBAC) limiting developer API server queries."
                    },
                    {
                        "stage": "Local Container Data Collection",
                        "tactic": "Collection",
                        "techniques": [{"technique_id": "T1005", "technique_name": "Data from Local System"}],
                        "description": "Attacker gathers environment configuration maps and secret volumes mounted inside running containers.",
                        "impact": "Internal database credentials and proprietary encryption keys collected.",
                        "detection_hint": "Kubernetes exec log alerts on shell sessions into production microservice pods.",
                        "mitigation": "Disable exec privileges in production clusters and enforce read-only root filesystems."
                    },
                    {
                        "stage": "Unauthorized Compute Deployment",
                        "tactic": "Impact",
                        "techniques": [{"technique_id": "T1496", "technique_name": "Resource Hijacking"}],
                        "description": "Attacker provisions dozens of GPU-enabled cloud instances to execute cryptomining payloads and exhaust quotas.",
                        "impact": "Severe cloud infrastructure bill inflation and degradation of customer services.",
                        "detection_hint": "Cloud billing anomaly alerts and sudden spike in GPU instance creation events.",
                        "mitigation": "Set strict quota limits and real-time automated anomaly alerts on cloud compute provisioning."
                    }
                ]
            }
        ],
        "enterprise": [
            {
                "title": "Enterprise Spearphishing & Active Directory Domain Compromise",
                "summary": "A sophisticated adversary executes a multi-stage intrusion against corporate workstations. Leveraging Kerberoasting and credential dumping, the attackers pivot across subnets to seize Domain Admin privileges and stage data for extortion.",
                "stages": [
                    {
                        "stage": "Corporate Hierarchy & Employee Reconnaissance",
                        "tactic": "Reconnaissance",
                        "techniques": [{"technique_id": "T1589.002", "technique_name": "Gather Victim Identity Information: Email Addresses"}],
                        "description": "Attackers scrape LinkedIn and corporate portals to map the finance team hierarchy and target email addresses.",
                        "impact": "Target list of key executive assistants and accounts payable staff compiled.",
                        "detection_hint": "Monitor external threat intelligence feeds and email gateway perimeter probes.",
                        "mitigation": "Enforce public profile privacy policies and monitor external email exposure."
                    },
                    {
                        "stage": "Spearphishing with Weaponized Invoice Document",
                        "tactic": "Initial Access",
                        "techniques": [{"technique_id": "T1566.001", "technique_name": "Spearphishing Attachment"}],
                        "description": "A tailored spearphishing email with a malicious macro-enabled spreadsheet is delivered to an accounts specialist.",
                        "impact": "Workstation compromised when user enables macro content.",
                        "detection_hint": "Email gateway attachment sandbox detonation alerts and Microsoft Defender macro blocking logs.",
                        "mitigation": "Block internet-originating macros via Group Policy Attack Surface Reduction rules."
                    },
                    {
                        "stage": "In-Memory PowerShell Shellcode Injection",
                        "tactic": "Execution",
                        "techniques": [{"technique_id": "T1059.001", "technique_name": "Command and Scripting Interpreter: PowerShell"}],
                        "description": "The macro spawns PowerShell with encoded arguments to inject Cobalt Strike beacon into memory.",
                        "impact": "Persistent stealthy command and control beacon established.",
                        "detection_hint": "PowerShell Script Block Logging (Event ID 4104) showing suspicious Base64 execution.",
                        "mitigation": "Enforce PowerShell Constrained Language Mode and AMSI script inspection."
                    },
                    {
                        "stage": "Kerberos Ticket Request & Offline Password Cracking",
                        "tactic": "Credential Access",
                        "techniques": [{"technique_id": "T1558.003", "technique_name": "Steal or Forge Kerberos Tickets: Kerberoasting"}],
                        "description": "Attacker requests service tickets for SPNs in Active Directory and cracks weak service account passwords offline.",
                        "impact": "Plaintext credentials for domain administrative service accounts extracted.",
                        "detection_hint": "Active Directory Event ID 4769 with RC4 encryption type requested for service tickets.",
                        "mitigation": "Use Managed Service Accounts (gMSA) with complex, automatically rotating 128-bit passwords."
                    },
                    {
                        "stage": "Domain Controller & Group Membership Discovery",
                        "tactic": "Discovery",
                        "techniques": [{"technique_id": "T1087.002", "technique_name": "Account Discovery: Domain Account"}],
                        "description": "Adversary uses native LDAP queries and bloodhound to map Domain Admin group relationships.",
                        "impact": "Shortest attack paths to Enterprise Admin permissions identified.",
                        "detection_hint": "SIEM alert on anomalous volume of LDAP queries originating from a non-server workstation.",
                        "mitigation": "Restrict LDAP reconnaissance by enforcing LDAP channel binding and query auditing."
                    },
                    {
                        "stage": "Domain Controller Remote Administration Pivot",
                        "tactic": "Lateral Movement",
                        "techniques": [{"technique_id": "T1021.002", "technique_name": "Remote Services: SMB/Windows Admin Shares"}],
                        "description": "Using compromised domain credentials, attacker connects to the Primary Domain Controller via SMB admin shares.",
                        "impact": "Full enterprise forest and Active Directory database under adversary control.",
                        "detection_hint": "Event ID 4624 (Type 3 logon) with administrative credentials originating from non-admin subnet.",
                        "mitigation": "Implement Tiered Administration model and Privileged Access Workstations (PAWs)."
                    },
                    {
                        "stage": "Mass Data Archiving & Staging",
                        "tactic": "Collection",
                        "techniques": [{"technique_id": "T1560.001", "technique_name": "Archive Collected Data: Archive via Utility"}],
                        "description": "Adversary uses 7-Zip utility to compress enterprise file shares and database backups into password-protected archives.",
                        "impact": "Gigabytes of proprietary enterprise records prepared for exfiltration.",
                        "detection_hint": "EDR alert on 7z.exe or rar.exe executing with command-line arguments targeting file servers.",
                        "mitigation": "Restrict executable permissions on file shares and deploy folder access auditing."
                    },
                    {
                        "stage": "Encrypted C2 Channel Exfiltration",
                        "tactic": "Exfiltration",
                        "techniques": [{"technique_id": "T1041", "technique_name": "Exfiltration Over C2 Channel"}],
                        "description": "Encrypted archives are exfiltrated over HTTPS C2 channels during off-peak weekend hours.",
                        "impact": "Massive confidential enterprise and financial data breach.",
                        "detection_hint": "Network traffic analysis (NTA) alerting on sustained outbound TLS streams with high byte ratio.",
                        "mitigation": "Deploy TLS decryption proxy inspection and strict egress data rate limiting."
                    }
                ]
            },
            {
                "title": "Contractor VPN Credential Abuse & Hypervisor Ransomware",
                "summary": "Threat actors breach a facilities contractor and reuse valid VPN credentials to enter the corporate intranet. Bypassing network segmentation via unpatched server vulnerabilities, they deploy ransomware across virtual machine hypervisors.",
                "stages": [
                    {
                        "stage": "Contractor VPN Credential Stuffing",
                        "tactic": "Initial Access",
                        "techniques": [{"technique_id": "T1078.002", "technique_name": "Valid Accounts: Domain Accounts"}],
                        "description": "Attackers leverage compromised vendor credentials obtained in a dark web dump to log into corporate SSL-VPN.",
                        "impact": "Unrestricted network tunnel into corporate intranet established.",
                        "detection_hint": "VPN authentication logs showing connection from anomalous geographic region without MFA challenge.",
                        "mitigation": "Mandate hardware token MFA and certificate-based device posture verification for all VPN access."
                    },
                    {
                        "stage": "Automated PowerShell Network Probing",
                        "tactic": "Execution",
                        "techniques": [{"technique_id": "T1059.001", "technique_name": "Command and Scripting Interpreter: PowerShell"}],
                        "description": "Attacker runs automated PowerShell network discovery scripts against internal virtualization clusters.",
                        "impact": "PowerShell script executes network sweeps across private management subnets.",
                        "detection_hint": "PowerShell operational logs recording rapid Test-NetConnection sweeps.",
                        "mitigation": "Restrict PowerShell execution and enforce Constrained Language Mode on endpoints."
                    },
                    {
                        "stage": "Hypervisor Vulnerability Exploitation",
                        "tactic": "Privilege Escalation",
                        "techniques": [{"technique_id": "T1068", "technique_name": "Exploitation for Privilege Escalation"}],
                        "description": "Attacker exploits an unpatched remote code execution vulnerability in virtualization management server.",
                        "impact": "Root-level shell access achieved on central VM cluster host.",
                        "detection_hint": "Web server crash logs and unexpected child process spawned by hypervisor daemon.",
                        "mitigation": "Apply virtualization vendor security patches and isolate management interfaces on dedicated VLANs."
                    },
                    {
                        "stage": "Disabling Endpoint Protection & Backup Services",
                        "tactic": "Defense Evasion",
                        "techniques": [{"technique_id": "T1562.001", "technique_name": "Impair Defenses: Disable or Modify Tools"}],
                        "description": "Attacker runs scripts to terminate EDR agents, unhook security drivers, and delete volume shadow copies.",
                        "impact": "Local security sensors blinded and local restore points eliminated.",
                        "detection_hint": "EDR heartbeat failure alerts and Windows Event ID 7036 (service stopped unexpectedly).",
                        "mitigation": "Enable tamper protection on endpoint sensors and enforce immutable offsite backups."
                    },
                    {
                        "stage": "Internal Network Service Discovery",
                        "tactic": "Discovery",
                        "techniques": [{"technique_id": "T1046", "technique_name": "Network Service Discovery"}],
                        "description": "Attacker scans internal subnets to catalog active hypervisors and storage area network management ports.",
                        "impact": "All hypervisor nodes and backup storage appliances identified.",
                        "detection_hint": "Network IDS alert on port scanning across virtualization management VLAN.",
                        "mitigation": "Enforce strict network microsegmentation and isolate VM management interfaces."
                    },
                    {
                        "stage": "Hypervisor Cluster Lateral Movement",
                        "tactic": "Lateral Movement",
                        "techniques": [{"technique_id": "T1021.001", "technique_name": "Remote Services: Remote Desktop Protocol"}],
                        "description": "Adversary pivots across management hosts using RDP sessions with compromised administrator credentials.",
                        "impact": "Administrative access established across all secondary hypervisor nodes.",
                        "detection_hint": "RDP logon events between server subnets during unusual off-hours.",
                        "mitigation": "Disable direct RDP between servers and require multi-factor jump hosts."
                    },
                    {
                        "stage": "Virtual Disk Archive Staging",
                        "tactic": "Collection",
                        "techniques": [{"technique_id": "T1560.001", "technique_name": "Archive Collected Data: Archive via Utility"}],
                        "description": "Critical database VM configuration files and snapshot metadata are staged for encryption.",
                        "impact": "Core enterprise operational workloads prepared for mass encryption.",
                        "detection_hint": "Abnormal mass read operations on virtual disk storage repositories.",
                        "mitigation": "Deploy storage-layer behavioral monitoring and snapshot protection."
                    },
                    {
                        "stage": "Virtual Disk Encryption & Cluster Shutdown",
                        "tactic": "Impact",
                        "techniques": [{"technique_id": "T1486", "technique_name": "Data Encrypted for Impact"}],
                        "description": "Ransomware payload encrypts all virtual machine disk images (.vmdk/.vhdx) and halts core enterprise services.",
                        "impact": "Total operational paralysis of enterprise ERP, communications, and database systems.",
                        "detection_hint": "Storage volume I/O throughput spike followed by mass VM kernel panic alerts.",
                        "mitigation": "Maintain air-gapped, immutable write-once-read-many (WORM) storage backups."
                    }
                ]
            },
            {
                "title": "ERP Portal SQL Injection & Financial Record Tampering",
                "summary": "Adversaries exploit a web application vulnerability in an enterprise ERP portal. Gaining database access, they manipulate vendor banking records to execute unauthorized international wire transfers.",
                "stages": [
                    {
                        "stage": "ERP Web Interface Vulnerability Exploitation",
                        "tactic": "Initial Access",
                        "techniques": [{"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application"}],
                        "description": "Threat actors exploit a SQL injection flaw in the vendor self-service portal of the enterprise ERP system.",
                        "impact": "Database querying and arbitrary command execution on backend database server.",
                        "detection_hint": "Web Application Firewall (WAF) rule trigger on SQL syntax in HTTP POST parameters.",
                        "mitigation": "Conduct regular dynamic code analysis and enforce parameterized queries across all forms."
                    },
                    {
                        "stage": "Backend Web Shell Execution",
                        "tactic": "Execution",
                        "techniques": [{"technique_id": "T1059.004", "technique_name": "Command and Scripting Interpreter: Unix Shell"}],
                        "description": "Attacker leverages SQL command execution to write and execute a persistent PHP/Unix web shell.",
                        "impact": "Interactive operating system command execution on the ERP web server.",
                        "detection_hint": "Web server process spawning bash/sh child processes with abnormal arguments.",
                        "mitigation": "Run web applications with non-privileged service accounts and mount document roots read-only."
                    },
                    {
                        "stage": "Local System Privilege Escalation",
                        "tactic": "Privilege Escalation",
                        "techniques": [{"technique_id": "T1548.002", "technique_name": "Abuse Elevation Control Mechanism: Bypass User Account Control"}],
                        "description": "Adversary exploits misconfigured sudo permissions to escalate privileges to root on the ERP server.",
                        "impact": "Full root access achieved on production ERP application host.",
                        "detection_hint": "Auditd alerts on unauthorized sudo execution for non-standard binaries.",
                        "mitigation": "Enforce strict sudoers rules and audit privilege elevation permissions."
                    },
                    {
                        "stage": "Web Access Log Clean-Up",
                        "tactic": "Defense Evasion",
                        "techniques": [{"technique_id": "T1070.004", "technique_name": "Indicator Removal: File Deletion"}],
                        "description": "Attacker removes web server access log entries containing their source IP addresses and SQL injection payloads.",
                        "impact": "Evidence of initial intrusion erased from local log files.",
                        "detection_hint": "Log gap detection alerting on truncated or deleted access.log files.",
                        "mitigation": "Forward logs in real time to an immutable, centralized SIEM repository."
                    },
                    {
                        "stage": "Database Schema & Table Enumeration",
                        "tactic": "Discovery",
                        "techniques": [{"technique_id": "T1082", "technique_name": "System Information Discovery"}],
                        "description": "Attacker queries database metadata tables to locate vendor banking account records and pending payments.",
                        "impact": "Structure of accounts payable and wire approval workflows uncovered.",
                        "detection_hint": "Database audit logs showing atypical queries against information_schema and sys.tables.",
                        "mitigation": "Enforce strict database user least-privilege and query monitoring."
                    },
                    {
                        "stage": "Database Backend Pivot",
                        "tactic": "Lateral Movement",
                        "techniques": [{"technique_id": "T1021.002", "technique_name": "Remote Services: SMB/Windows Admin Shares"}],
                        "description": "Attacker connects from the web server into internal database cluster shares to stage batch files.",
                        "impact": "Direct interactive file share access to core accounting data repositories.",
                        "detection_hint": "Internal network firewall alert on SMB traffic originating from DMZ web tier.",
                        "mitigation": "Block DMZ-to-internal network lateral connections and enforce strict network zoning."
                    },
                    {
                        "stage": "Vendor Banking Detail Collection",
                        "tactic": "Collection",
                        "techniques": [{"technique_id": "T1119", "technique_name": "Automated Collection"}],
                        "description": "Automated SQL scripts dump pending accounts payable disbursement records and vendor details.",
                        "impact": "Complete ledger of pending corporate payouts extracted.",
                        "detection_hint": "Database monitoring alert on bulk SELECT queries against financial tables.",
                        "mitigation": "Implement column-level database encryption and query threshold monitoring."
                    },
                    {
                        "stage": "Vendor Payment Record Manipulation",
                        "tactic": "Impact",
                        "techniques": [{"technique_id": "T1565.001", "technique_name": "Data Manipulation: Stored Data Manipulation"}],
                        "description": "Attacker executes SQL updates replacing legitimate vendor IBAN numbers with offshore mule accounts.",
                        "impact": "Upcoming batch payment files corrupted to direct funds to attacker accounts.",
                        "detection_hint": "Database integrity monitoring alert on bulk modifications to vendor payment fields.",
                        "mitigation": "Require dual-authorization out-of-band verification for any vendor banking detail modifications."
                    }
                ]
            }
        ],
        "government": [
            {
                "title": "State-Sponsored Zero-Day Edge Infiltration & Espionage",
                "summary": "A foreign intelligence service leverages a zero-day vulnerability in edge networking equipment to gain covert access. Using memory-only backdoors and DNS tunneling, they exfiltrate classified policy briefs and diplomatic cables.",
                "stages": [
                    {
                        "stage": "Perimeter Gateway Zero-Day Exploitation",
                        "tactic": "Reconnaissance",
                        "techniques": [{"technique_id": "T1595.002", "technique_name": "Vulnerability Scanning"}],
                        "description": "Adversaries conduct covert port scans to identify vulnerable firmware builds on edge firewalls.",
                        "impact": "Agency perimeter hardware vulnerabilities mapped.",
                        "detection_hint": "Anomalous probe activity recorded on exterior firewall interfaces.",
                        "mitigation": "Regular vulnerability scanning and zero-trust edge architecture."
                    },
                    {
                        "stage": "Perimeter Gateway Exploit Execution",
                        "tactic": "Initial Access",
                        "techniques": [{"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application"}],
                        "description": "Adversaries deploy an undisclosed zero-day exploit targeting the agency's edge VPN gateway.",
                        "impact": "Root-level shell access achieved on edge firewall/gateway device.",
                        "detection_hint": "Anomalous crash dumps on network appliances and unexpected outbound connections from gateway.",
                        "mitigation": "Maintain rapid patch management and isolate edge gateways from internal management interfaces."
                    },
                    {
                        "stage": "In-Memory Implant Deployment",
                        "tactic": "Execution",
                        "techniques": [{"technique_id": "T1059.004", "technique_name": "Command and Scripting Interpreter: Unix Shell"}],
                        "description": "Attacker runs a custom ELF implant that resides entirely in RAM to avoid touching disk storage.",
                        "impact": "Covert persistent backdoor operating undetected by traditional antivirus.",
                        "detection_hint": "Linux memory analysis showing unmapped executable memory segments in system processes.",
                        "mitigation": "Deploy modern Linux EDR with kernel-level memory integrity monitoring."
                    },
                    {
                        "stage": "Payload Obfuscation & Memory Masking",
                        "tactic": "Defense Evasion",
                        "techniques": [{"technique_id": "T1027", "technique_name": "Obfuscated Files or Information"}],
                        "description": "The implant encrypts internal command strings and dynamically resolves API symbols at runtime.",
                        "impact": "Memory scanning signatures fail to match known adversary tooling.",
                        "detection_hint": "EDR memory inspection alerts on dynamically decrypted executable regions.",
                        "mitigation": "Enforce kernel-level code integrity policies and hardware-enforced stack protection."
                    },
                    {
                        "stage": "Device Credential & Config Extraction",
                        "tactic": "Credential Access",
                        "techniques": [{"technique_id": "T1552.001", "technique_name": "Unsecured Credentials: Credentials In Files"}],
                        "description": "Adversary extracts plaintext VPN service account passwords and cryptographic tokens stored in gateway memory.",
                        "impact": "Internal enterprise service credentials compromised.",
                        "detection_hint": "Audit log alerts on unauthenticated processes reading gateway secrets vaults.",
                        "mitigation": "Utilize hardware security modules (HSMs) for sensitive cryptographic key storage."
                    },
                    {
                        "stage": "Internal Active Directory Enumeration",
                        "tactic": "Discovery",
                        "techniques": [{"technique_id": "T1087.002", "technique_name": "Account Discovery: Domain Account"}],
                        "description": "Adversary uses native LDAP queries through compromised appliances to map security groups and clearances.",
                        "impact": "Clearance levels and agency personnel roles mapped.",
                        "detection_hint": "SIEM alert on anomalous volume of LDAP search queries originating from a non-domain asset.",
                        "mitigation": "Enforce LDAP signing and channel binding with strict access control lists."
                    },
                    {
                        "stage": "Classified Subnet Lateral Jump",
                        "tactic": "Lateral Movement",
                        "techniques": [{"technique_id": "T1021.001", "technique_name": "Remote Services: Remote Desktop Protocol"}],
                        "description": "Attacker utilizes stolen credentials to jump across router boundaries into restricted policy subnet.",
                        "impact": "Direct interactive access to workstations housing diplomatic cables.",
                        "detection_hint": "Network firewall logs indicating unexpected RDP sessions spanning security zones.",
                        "mitigation": "Enforce microsegmentation with jump-host bastion servers and multi-factor authorization."
                    },
                    {
                        "stage": "Covert DNS Tunneling Exfiltration",
                        "tactic": "Exfiltration",
                        "techniques": [{"technique_id": "T1048.003", "technique_name": "Exfiltration Over Alternative Protocol"}],
                        "description": "Stolen confidential documents are encoded into subdomains and exfiltrated via low-and-slow DNS requests.",
                        "impact": "Classified national policy briefs and diplomatic correspondence compromised.",
                        "detection_hint": "DNS server logs showing high entropy domain queries and anomalous request volume to authoritative nameserver.",
                        "mitigation": "Deploy DNS security filtering with deep packet inspection to block DNS tunneling."
                    }
                ]
            },
            {
                "title": "Defense Contractor Watering Hole & Classified Data Extraction",
                "summary": "Threat actors compromise a public standards portal frequented by agency researchers. Injecting an exploit payload that targets browser vulnerabilities, they gain remote access to agency research laptops.",
                "stages": [
                    {
                        "stage": "Public Contractor Website Compromise",
                        "tactic": "Resource Development",
                        "techniques": [{"technique_id": "T1584.004", "technique_name": "Compromise Infrastructure: Server"}],
                        "description": "Adversary compromises the web server hosting industry policy standards to inject an exploit kit.",
                        "impact": "Watering hole staging server ready to deliver exploits to visiting agency staff.",
                        "detection_hint": "Third-party threat intelligence monitoring for compromised industry partner portals.",
                        "mitigation": "Deploy remote browser isolation (RBI) for web browsing on high-security workstations."
                    },
                    {
                        "stage": "Drive-by Download Browser Exploitation",
                        "tactic": "Initial Access",
                        "techniques": [{"technique_id": "T1189", "technique_name": "Drive-by Compromise"}],
                        "description": "An agency policy analyst visits the compromised site, triggering a zero-click browser engine vulnerability.",
                        "impact": "Arbitrary code execution within the analyst user context.",
                        "detection_hint": "EDR alert showing browser process (chrome.exe/msedge.exe) spawning cmd.exe or powershell.exe.",
                        "mitigation": "Enable browser sandboxing, Exploit Guard, and enforce automated browser patching."
                    },
                    {
                        "stage": "PowerShell Script Dropper Execution",
                        "tactic": "Execution",
                        "techniques": [{"technique_id": "T1059.001", "technique_name": "Command and Scripting Interpreter: PowerShell"}],
                        "description": "The browser exploit executes an in-memory PowerShell loader to download secondary surveillance tools.",
                        "impact": "Stealthy agent payload executing on government analyst workstation.",
                        "detection_hint": "PowerShell Script Block Logging (Event ID 4104) capturing encoded script invocation.",
                        "mitigation": "Enforce Application Control / AppLocker blocking unauthorized PowerShell scripts."
                    },
                    {
                        "stage": "Local Privilege Escalation via Windows Kernel Flaw",
                        "tactic": "Privilege Escalation",
                        "techniques": [{"technique_id": "T1068", "technique_name": "Exploitation for Privilege Escalation"}],
                        "description": "Payload leverages an unpatched kernel vulnerability to elevate from user space to SYSTEM level.",
                        "impact": "Complete administrative control over the compromised endpoint.",
                        "detection_hint": "Sysmon Event ID 10 (Process Access) showing suspicious handle creation against csrss.exe or lsass.exe.",
                        "mitigation": "Enable Hypervisor-Protected Code Integrity (HVCI) and virtualization-based security."
                    },
                    {
                        "stage": "Security Sensor Blindness",
                        "tactic": "Defense Evasion",
                        "techniques": [{"technique_id": "T1562.001", "technique_name": "Impair Defenses: Disable or Modify Tools"}],
                        "description": "Adversary unloads kernel minifilter drivers and disables EDR real-time scanning services.",
                        "impact": "Host endpoint defense telemetry disabled.",
                        "detection_hint": "EDR sensor offline alerts and Windows Defender tampering warnings.",
                        "mitigation": "Enable tamper protection and monitor agent service health continuously."
                    },
                    {
                        "stage": "File System & Document Discovery",
                        "tactic": "Discovery",
                        "techniques": [{"technique_id": "T1082", "technique_name": "System Information Discovery"}],
                        "description": "The malware searches all local drives for classified documents matching keyword markers.",
                        "impact": "Full catalog of sensitive local research files generated.",
                        "detection_hint": "File integrity monitoring alerts on mass directory traversal in user profile folders.",
                        "mitigation": "Enforce mandatory encryption on all workstation storage volumes."
                    },
                    {
                        "stage": "Sensitive Document Discovery & Collection",
                        "tactic": "Collection",
                        "techniques": [{"technique_id": "T1005", "technique_name": "Data from Local System"}],
                        "description": "The adversary script searches local user profile directories for PDF, DOCX, and encrypted zip archives.",
                        "impact": "Sensitive defense project specifications staged for extraction.",
                        "detection_hint": "File integrity monitoring alert on rapid access to sensitive classified document repositories.",
                        "mitigation": "Store sensitive documents strictly in centralized, encrypted document management systems."
                    },
                    {
                        "stage": "Steganographic Image Exfiltration",
                        "tactic": "Exfiltration",
                        "techniques": [{"technique_id": "T1048.003", "technique_name": "Exfiltration Over Alternative Protocol"}],
                        "description": "Staged documents are embedded into benign image files and posted to public image hosting services.",
                        "impact": "Defense research specifications leaked to foreign intelligence.",
                        "detection_hint": "Web proxy alerts on image upload sizes disproportionate to typical social media traffic.",
                        "mitigation": "Deploy advanced content inspection proxies capable of steganographic artifact analysis."
                    }
                ]
            },
            {
                "title": "Citizen Identity Portal API Breach & Welfare Fund Sabotage",
                "summary": "Attackers exploit an authentication bypass flaw in an online citizen service portal. Extracting millions of national identity records, the data is weaponized for spearphishing and fraudulent benefits claims.",
                "stages": [
                    {
                        "stage": "Citizen Portal API Authentication Bypass",
                        "tactic": "Initial Access",
                        "techniques": [{"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application"}],
                        "description": "Adversary discovers and exploits a broken object-level authorization (BOLA) flaw in the citizen portal API.",
                        "impact": "Unauthenticated access to citizen identity profile endpoint.",
                        "detection_hint": "API Gateway alerts on sequential ID parameter enumeration with high request rates.",
                        "mitigation": "Implement robust server-side authorization checks on all API endpoints."
                    },
                    {
                        "stage": "Automated Scraper Script Execution",
                        "tactic": "Execution",
                        "techniques": [{"technique_id": "T1059.004", "technique_name": "Command and Scripting Interpreter: Unix Shell"}],
                        "description": "Adversary launches automated bash scraper jobs across compromised proxy nodes.",
                        "impact": "High-velocity automated API requests executed against government database endpoints.",
                        "detection_hint": "Web server logs showing rapid execution of scraping scripts.",
                        "mitigation": "Implement web application rate limiting and behavioral bot detection."
                    },
                    {
                        "stage": "API Key Privilege Escalation",
                        "tactic": "Privilege Escalation",
                        "techniques": [{"technique_id": "T1068", "technique_name": "Exploitation for Privilege Escalation"}],
                        "description": "Attacker leverages administrative API endpoints to elevate API token permissions to system auditor.",
                        "impact": "Read and write privileges obtained across the entire citizen registry database.",
                        "detection_hint": "API gateway logs showing user tokens executing admin-tier API routes.",
                        "mitigation": "Enforce strict role-based access control and token scope validation on all API gateways."
                    },
                    {
                        "stage": "API Query Log Erasure",
                        "tactic": "Defense Evasion",
                        "techniques": [{"technique_id": "T1070.004", "technique_name": "Indicator Removal: File Deletion"}],
                        "description": "Attacker purges application access logs to obscure the origin of high-volume scraping requests.",
                        "impact": "Audit trail of unauthorized queries erased from local web server disks.",
                        "detection_hint": "System monitoring alert on sudden truncation of API access logs.",
                        "mitigation": "Stream audit logs to a remote, immutable append-only storage sink."
                    },
                    {
                        "stage": "Citizen Database Schema Discovery",
                        "tactic": "Discovery",
                        "techniques": [{"technique_id": "T1082", "technique_name": "System Information Discovery"}],
                        "description": "Adversary maps the relational schema of citizen tax records, national identifiers, and banking payouts.",
                        "impact": "Complete database table mapping of citizen financial records.",
                        "detection_hint": "Database audit logs recording schema inspection commands.",
                        "mitigation": "Restrict database metadata queries and segment sensitive database tables."
                    },
                    {
                        "stage": "Core Disbursement Server Pivot",
                        "tactic": "Lateral Movement",
                        "techniques": [{"technique_id": "T1021.004", "technique_name": "Remote Services: SSH"}],
                        "description": "Attacker pivots from the web portal backend to the core treasury disbursement server using stolen SSH keys.",
                        "impact": "Direct interactive shell established on payment dispatch system.",
                        "detection_hint": "Internal network firewall alert on SSH connection between portal DMZ and treasury core.",
                        "mitigation": "Enforce strict network microsegmentation preventing DMZ servers from reaching core financial systems."
                    },
                    {
                        "stage": "Automated Citizen Record Scraping",
                        "tactic": "Collection",
                        "techniques": [{"technique_id": "T1119", "technique_name": "Automated Collection"}],
                        "description": "Attacker runs distributed worker scripts to query millions of citizen records including tax IDs and addresses.",
                        "impact": "Massive registry of citizen personal identifiable information (PII) harvested.",
                        "detection_hint": "Database query performance alerts and web server request spike from residential proxy networks.",
                        "mitigation": "Implement rate limiting, bot management, and IP reputation filtering at web application perimeter."
                    },
                    {
                        "stage": "Data Integrity Tampering",
                        "tactic": "Impact",
                        "techniques": [{"technique_id": "T1565.001", "technique_name": "Data Manipulation: Stored Data Manipulation"}],
                        "description": "Attacker modifies citizen banking details in benefit databases to redirect upcoming pension distributions.",
                        "impact": "Disruption of government welfare disbursements and severe public trust impact.",
                        "detection_hint": "Database change audit logs showing automated bulk updates to citizen bank account numbers.",
                        "mitigation": "Require cryptographic audit logs and administrative dual-control for bulk record modifications."
                    }
                ]
            }
        ],
        "smb": [
            {
                "title": "Business Email Compromise (BEC) & Invoice Redirection",
                "summary": "Attackers compromise an executive assistant's email via credential stuffing. After establishing mailbox forwarding rules, they intercept customer invoices and substitute fraudulent payment routing details.",
                "stages": [
                    {
                        "stage": "Email Portal Credential Stuffing",
                        "tactic": "Initial Access",
                        "techniques": [{"technique_id": "T1110.004", "technique_name": "Brute Force: Credential Stuffing"}],
                        "description": "Threat actor uses leaked password databases to gain access to an employee Microsoft 365 account.",
                        "impact": "Attacker achieves valid mailbox access without triggering account lockout.",
                        "detection_hint": "Azure AD sign-in logs showing successful authentication from high-risk IP with atypical user-agent.",
                        "mitigation": "Enforce mandatory multi-factor authentication (MFA) and block legacy authentication protocols."
                    },
                    {
                        "stage": "PowerShell Mailbox Rule Automation",
                        "tactic": "Execution",
                        "techniques": [{"technique_id": "T1059.001", "technique_name": "Command and Scripting Interpreter: PowerShell"}],
                        "description": "Adversary runs automated PowerShell scripts via Exchange Online remote management module.",
                        "impact": "Administrative PowerShell session established against cloud mailbox.",
                        "detection_hint": "Exchange audit log showing PowerShell connection from unfamiliar external IP.",
                        "mitigation": "Disable remote PowerShell access for non-administrator cloud accounts."
                    },
                    {
                        "stage": "Silent Mailbox Forwarding Rule Creation",
                        "tactic": "Persistence",
                        "techniques": [{"technique_id": "T1114.003", "technique_name": "Email Collection: Email Forwarding Rule"}],
                        "description": "Attacker configures hidden inbox rules to forward emails containing 'invoice' or 'wire' to an external inbox.",
                        "impact": "Continuous passive surveillance of incoming and outgoing financial communications.",
                        "detection_hint": "Exchange Online audit alert for 'New-InboxRule' with external forwarding address.",
                        "mitigation": "Disable auto-forwarding to external domains at the tenant level."
                    },
                    {
                        "stage": "Staff Invoicing Credential Extraction",
                        "tactic": "Credential Access",
                        "techniques": [{"technique_id": "T1555.003", "technique_name": "Credentials from Password Stores: Web Browsers"}],
                        "description": "Attacker extracts cached accounting portal credentials and cookies saved in the employee browser.",
                        "impact": "Single Sign-On and billing software credentials compromised.",
                        "detection_hint": "EDR alert on unrecognized process accessing browser SQLite vault files.",
                        "mitigation": "Enforce enterprise password managers and disable browser credential saving."
                    },
                    {
                        "stage": "Organization User & Customer Directory Discovery",
                        "tactic": "Discovery",
                        "techniques": [{"technique_id": "T1087.004", "technique_name": "Account Discovery: Cloud Account"}],
                        "description": "Attacker pulls the global address list and shared contact books to map customer accounts receivable contacts.",
                        "impact": "Complete list of active business clients and payment managers exposed.",
                        "detection_hint": "Audit log alert for bulk export of Global Address List.",
                        "mitigation": "Restrict address list viewing permissions and alert on bulk directory exports."
                    },
                    {
                        "stage": "Cloud Account Lateral Impersonation",
                        "tactic": "Lateral Movement",
                        "techniques": [{"technique_id": "T1078.004", "technique_name": "Valid Accounts: Cloud Accounts"}],
                        "description": "Attacker uses harvested credentials to log into shared company accounting and invoicing portals.",
                        "impact": "Direct access to billing software and invoice generator tools.",
                        "detection_hint": "Sign-in alerts from unrecognized browser sessions accessing financial SaaS apps.",
                        "mitigation": "Enforce single sign-on (SSO) with conditional access and step-up authentication."
                    },
                    {
                        "stage": "Financial Communication Surveillance",
                        "tactic": "Collection",
                        "techniques": [{"technique_id": "T1114.002", "technique_name": "Email Collection: Remote Email Collection"}],
                        "description": "Adversary monitors client invoice correspondence to identify large pending payment transactions.",
                        "impact": "Details of upcoming client receivables and billing cycles exposed.",
                        "detection_hint": "Audit log alerts on rapid email search queries and bulk message downloads.",
                        "mitigation": "Deploy email security tools with AI-driven behavioral anomaly detection."
                    },
                    {
                        "stage": "Fraudulent Invoice Substitution",
                        "tactic": "Impact",
                        "techniques": [{"technique_id": "T1565.002", "technique_name": "Data Manipulation: Transmitted Data Manipulation"}],
                        "description": "Attacker intercepts a legitimate invoice and replies from a lookalike domain with altered bank details.",
                        "impact": "Customer sends payment to attacker account resulting in permanent capital loss.",
                        "detection_hint": "Mail trace showing emails originating from registered lookalike domain with spoofed display names.",
                        "mitigation": "Enforce out-of-band voice confirmation for any changes to banking payment details."
                    }
                ]
            },
            {
                "title": "Unpatched Edge Firewall Exploitation & Locker Ransomware",
                "summary": "Adversaries scan SMB perimeters for unpatched edge routers. Exploiting an RCE vulnerability, they deploy a locker ransomware script that encrypts local shared drives and accounting databases.",
                "stages": [
                    {
                        "stage": "Edge Network Perimeter Vulnerability Scanning",
                        "tactic": "Reconnaissance",
                        "techniques": [{"technique_id": "T1595.002", "technique_name": "Vulnerability Scanning"}],
                        "description": "Automated botnets scan SMB IP blocks looking for unpatched router firmware versions.",
                        "impact": "Vulnerable perimeter router identified and targeted.",
                        "detection_hint": "Firewall logs showing repeated scanning probes against port 443 and 8443.",
                        "mitigation": "Disable remote management on WAN interfaces and apply vendor firmware updates immediately."
                    },
                    {
                        "stage": "Perimeter Router Remote Code Execution",
                        "tactic": "Initial Access",
                        "techniques": [{"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application"}],
                        "description": "Attacker executes buffer overflow exploit against the router web interface to gain root shell.",
                        "impact": "Complete control over the office network gateway.",
                        "detection_hint": "Unexpected router reboot and anomalous network traffic generated directly by router.",
                        "mitigation": "Isolate network appliance management interfaces onto a dedicated, restricted management subnet."
                    },
                    {
                        "stage": "Malicious Shell Payload Execution",
                        "tactic": "Execution",
                        "techniques": [{"technique_id": "T1059.004", "technique_name": "Command and Scripting Interpreter: Unix Shell"}],
                        "description": "Adversary deploys automated shell scripts on the router to establish reverse tunnels into the LAN.",
                        "impact": "Remote shell persistence established inside the corporate network perimeter.",
                        "detection_hint": "Router process list showing unrecognized background daemon processes.",
                        "mitigation": "Enforce router firmware signature verification and disable telnet/SSH on external ports."
                    },
                    {
                        "stage": "LAN Gateway Privilege Escalation",
                        "tactic": "Privilege Escalation",
                        "techniques": [{"technique_id": "T1068", "technique_name": "Exploitation for Privilege Escalation"}],
                        "description": "Attacker exploits local device vulnerabilities to obtain full root permissions across network storage.",
                        "impact": "Administrative access to office Network Attached Storage (NAS) units.",
                        "detection_hint": "NAS device audit logs showing privilege elevation from guest account.",
                        "mitigation": "Keep NAS firmware updated and disable default administrative accounts."
                    },
                    {
                        "stage": "Endpoint Security Tampering",
                        "tactic": "Defense Evasion",
                        "techniques": [{"technique_id": "T1562.001", "technique_name": "Impair Defenses: Disable or Modify Tools"}],
                        "description": "Attacker broadcasts malicious ARP packets to disrupt local antivirus signature updates.",
                        "impact": "Local security sensors prevented from fetching real-time threat intelligence.",
                        "detection_hint": "Switch security logs showing ARP spoofing detection alerts.",
                        "mitigation": "Enable Dynamic ARP Inspection (DAI) and DHCP Snooping on local switches."
                    },
                    {
                        "stage": "Local Network Share Discovery",
                        "tactic": "Discovery",
                        "techniques": [{"technique_id": "T1135", "technique_name": "Network Share Discovery"}],
                        "description": "Attacker enumerates accessible Windows SMB file shares and network-attached storage (NAS) devices.",
                        "impact": "Location of critical business documents and customer accounting records identified.",
                        "detection_hint": "Network monitoring alert on rapid SMB port 445 connection attempts across all internal IPs.",
                        "mitigation": "Enforce SMB encryption and restrict file share access to authenticated corporate users."
                    },
                    {
                        "stage": "Local File Share Data Collection",
                        "tactic": "Collection",
                        "techniques": [{"technique_id": "T1005", "technique_name": "Data from Local System"}],
                        "description": "Attacker identifies and stages critical business database records and accounting files across network shares.",
                        "impact": "Core enterprise accounting and customer databases staged for encryption.",
                        "detection_hint": "File integrity monitoring alerts on mass read access across shared accounting folders.",
                        "mitigation": "Deploy automated file activity auditing and restrict share permissions."
                    },
                    {
                        "stage": "Local Accounting Database Encryption",
                        "tactic": "Impact",
                        "techniques": [{"technique_id": "T1486", "technique_name": "Data Encrypted for Impact"}],
                        "description": "Ransomware encrypts QuickBooks databases and office documents, leaving ransom instructions on desktop.",
                        "impact": "Complete stoppage of business accounting and daily operations.",
                        "detection_hint": "Antivirus alert on mass file renaming and creation of 'HOW_TO_DECRYPT.txt' files.",
                        "mitigation": "Implement automated offline cloud backups following the 3-2-1 backup rule."
                    }
                ]
            },
            {
                "title": "Phishing with Macro Loader & Customer Record Exfiltration",
                "summary": "An employee receives a fake shipping notification containing a malicious Excel attachment. The loader installs a modular trojan that steals browser passwords and uploads customer records to an FTP server.",
                "stages": [
                    {
                        "stage": "Shipping Notification Phishing Campaign",
                        "tactic": "Initial Access",
                        "techniques": [{"technique_id": "T1566.001", "technique_name": "Spearphishing Attachment"}],
                        "description": "Attacker sends an email masquerading as a postal delivery exception with an attached spreadsheet.",
                        "impact": "Employee opens attachment on office desktop.",
                        "detection_hint": "Email gateway alert for suspicious sender domain and executable attachments.",
                        "mitigation": "Deploy automated email filtering and regular employee phishing awareness drills."
                    },
                    {
                        "stage": "VBScript Dropper Execution",
                        "tactic": "Execution",
                        "techniques": [{"technique_id": "T1059.005", "technique_name": "Command and Scripting Interpreter: Visual Basic"}],
                        "description": "Embedded macro executes VBScript to download and run a secondary remote access trojan.",
                        "impact": "Secondary payload executes in user space.",
                        "detection_hint": "Sysmon Event ID 1 showing excel.exe spawning wscript.exe or cscript.exe.",
                        "mitigation": "Block Office macros from executing across all corporate workstations via Group Policy."
                    },
                    {
                        "stage": "Scheduled Task Persistence Establishment",
                        "tactic": "Persistence",
                        "techniques": [{"technique_id": "T1053.005", "technique_name": "Scheduled Task/Job: Scheduled Task"}],
                        "description": "Trojan creates a scheduled task to maintain persistence across system reboots.",
                        "impact": "Malware automatically executes every time the employee logs into the workstation.",
                        "detection_hint": "Security Event ID 4698 (A scheduled task was created) with unknown binary path.",
                        "mitigation": "Monitor and restrict scheduled task creation via endpoint detection policies."
                    },
                    {
                        "stage": "Payload Encryption & Obfuscation",
                        "tactic": "Defense Evasion",
                        "techniques": [{"technique_id": "T1027", "technique_name": "Obfuscated Files or Information"}],
                        "description": "The trojan uses multi-layer XOR encryption to evade signature-based file scanners.",
                        "impact": "Static antivirus scanners fail to identify the malicious payload.",
                        "detection_hint": "EDR behavioral detection alert for high entropy executable files in Temp folder.",
                        "mitigation": "Deploy behavioral-based endpoint detection and response (EDR) agents."
                    },
                    {
                        "stage": "Web Browser Password Scraping",
                        "tactic": "Credential Access",
                        "techniques": [{"technique_id": "T1555.003", "technique_name": "Credentials from Password Stores: Web Browsers"}],
                        "description": "Trojan decrypts saved passwords from Chrome and Edge SQLite credential databases.",
                        "impact": "Staff credentials for CRM, banking, and email portals compromised.",
                        "detection_hint": "EDR alert on unrecognized process opening AppData browser SQLite files.",
                        "mitigation": "Enforce enterprise password managers and disable browser built-in credential saving."
                    },
                    {
                        "stage": "Local File System Discovery",
                        "tactic": "Discovery",
                        "techniques": [{"technique_id": "T1082", "technique_name": "System Information Discovery"}],
                        "description": "Trojan scans local desktop and document folders for spreadsheets containing customer contacts.",
                        "impact": "Local customer contact files and invoices mapped for extraction.",
                        "detection_hint": "EDR alert on non-standard process traversing multiple user document directories.",
                        "mitigation": "Implement centralized data loss prevention (DLP) monitoring on user endpoints."
                    },
                    {
                        "stage": "Customer Contact Database Collection",
                        "tactic": "Collection",
                        "techniques": [{"technique_id": "T1005", "technique_name": "Data from Local System"}],
                        "description": "Trojan aggregates customer contact lists, emails, and phone numbers into a staging archive.",
                        "impact": "Customer contact records collected in preparation for exfiltration.",
                        "detection_hint": "File creation alert for hidden zip archives in AppData directory.",
                        "mitigation": "Deploy endpoint DLP tools that block unauthorized local archiving."
                    },
                    {
                        "stage": "Encrypted Network Exfiltration",
                        "tactic": "Exfiltration",
                        "techniques": [{"technique_id": "T1048.003", "technique_name": "Exfiltration Over Alternative Protocol"}],
                        "description": "Attacker uses harvested credentials to upload customer contact lists to an external server.",
                        "impact": "Customer contact list and private notes leaked to competitors.",
                        "detection_hint": "Firewall alerts on outbound encrypted connections originating from non-server endpoints.",
                        "mitigation": "Block outbound unencrypted protocols and enforce strict DLP egress filtering."
                    }
                ]
            }
        ]
    }
    
    # Generic fallback if organization type is not specifically listed
    default_templates = scenario_templates["enterprise"]
    
    # Select organization type template pool
    selected_pool = default_templates
    for key, templates in scenario_templates.items():
        if key in org_type:
            selected_pool = templates
            break
            
    # Pick one template from the pool
    chosen_template = random.choice(selected_pool)
    
    # Time unit and progression step based on maturity
    if "high" in maturity:
        time_unit = "Week"
        time_step = 2
        impact_modifier = " (Mitigated by SOC controls)"
    elif "low" in maturity:
        time_unit = "Hour"
        time_step = 6
        impact_modifier = " (Undetected due to logging gaps)"
    else: # medium
        time_unit = "Day"
        time_step = 2
        impact_modifier = " (Partial SOC detection)"

    raw_stages = chosen_template["stages"]
    num_stages = len(raw_stages)
    detection_levels = assign_detection_likelihoods(maturity, num_stages)
    
    timeline = []
    base_time = 0
    for i, s in enumerate(raw_stages):
        time_val = f"{time_unit} {base_time + (i * time_step)}"
        timeline.append({
            "stage": s["stage"],
            "time": time_val,
            "tactic": s["tactic"],
            "techniques": s["techniques"],
            "detection_likelihood": detection_levels[i],
            "description": s["description"],
            "impact": s["impact"] + impact_modifier,
            "detection_hint": s["detection_hint"],
            "mitigation": s["mitigation"]
        })

    return {
        "title": chosen_template["title"] + f" ({maturity.title()} Maturity)",
        "summary": chosen_template["summary"],
        "timeline": timeline
    }


# ============= API ENDPOINTS =============
@api_router.get("/")
async def root():
    return {"message": "CyberRange AI API v1.0"}

@api_router.get("/health/llm", response_model=LLMHealthResponse)
async def check_llm_health():
    """
    Health check endpoint for the configured LLM provider.
    Executes a minimal test completion without exposing sensitive keys or credentials.
    """
    api_key = settings.LLM_API_KEY
    if not api_key:
        return LLMHealthResponse(
            llm_available=False,
            model=settings.LLM_MODEL,
            error="No API key configured for LLM provider"
        )
        
    start_time = time.perf_counter()
    try:
        response = await asyncio.wait_for(
            acompletion(
                model=settings.LLM_MODEL,
                messages=[{"role": "user", "content": "Ping. Respond with 'pong'."}],
                api_key=api_key
            ),
            timeout=min(settings.LLM_TIMEOUT, 5.0)
        )
        latency_ms = (time.perf_counter() - start_time) * 1000
        logger.info("LLM Health Check passed [model=%s, latency=%.2fms]", settings.LLM_MODEL, latency_ms)
        return LLMHealthResponse(
            llm_available=True,
            model=settings.LLM_MODEL,
            error=None
        )
    except Exception as e:
        latency_ms = (time.perf_counter() - start_time) * 1000
        clean_error = sanitize_llm_error(e)
        logger.warning("LLM Health Check failed [model=%s, latency=%.2fms]: %s", settings.LLM_MODEL, latency_ms, clean_error)
        return LLMHealthResponse(
            llm_available=False,
            model=settings.LLM_MODEL,
            error=clean_error
        )

@api_router.post("/phishing/generate", response_model=PhishingResponse)
async def generate_phishing(request: PhishingRequest):
    prompt = f"""You are a Cybersecurity Training Specialist and Phishing Defense Architect.
Generate a realistic, educational phishing simulation email for employee awareness training.

Target Role: {request.target_role}
Difficulty Level: {request.difficulty}
Industry: {request.industry}

Rules:
1. SAFETY & ETHICS (Training Simulation Only):
   - All email domains and URL destinations MUST strictly use reserved fictional TLDs ending in '.example' or '.test' (e.g., 'payroll-portal.example', 'http://verify-account.test').
   - NEVER use real company domains, real brands, or working links. Rejects .com, .net, .org.
   - The email is strictly defensive educational training content.

2. PERSONALIZATION:
   - Target Role ({request.target_role}): Use realistic pretexts (Finance: invoice/payment change; HR: resume/benefits; IT/Admin: password/SSO/cert alert; Student: scholarship/portal; Employee: tax/policy/SSO).
   - Industry ({request.industry}): Use authentic industry-specific vocabulary and scenarios.
   - Fictional recipient name matching the role (e.g. 'Alex Rivera', 'Dr. Jordan Hayes').
   - Fictional sender name and plausible title in the signature.
   - The email greeting MUST explicitly address recipient_name (e.g. 'Dear Alex,' or 'Hello Alex Rivera,') unless it is a mass organization broadcast notice.

3. DIFFICULTY RULES FOR RED FLAGS:
   - Easy: 4 to 5 obvious red flags (typos/misspellings, generic greeting, mismatched sender domain, failing SPF/DMARC).
   - Medium: 3 to 4 red flags (plausible wording, lookalike domain, mismatched link text vs destination).
   - Hard / Advanced: 2 to 3 subtle red flags (well-written, personalized, passing SPF/DKIM on attacker-owned lookalike domain, subtle process anomaly).
   - At least one red flag MUST concern the sender address, reply-to address, or sender domain.

4. VERIFIABLE EVIDENCE:
   - Every red flag MUST have an 'evidence' field containing the EXACT string, address, or URL found in the subject, body, sender, or link fields.
   - Do NOT invent flags that are not physically present in the email.

5. PSYCHOLOGICAL TRIGGERS & RESPONSE:
   - Identify psychological triggers used (Urgency, Authority, Fear, Curiosity, Reward, Familiarity) with a direct short quote in 'where_used'.
   - Include 3 concise 'safe_response' steps explaining what the recipient should do.

6. HEADER ANALYSIS:
   - Evaluate SPF, DKIM, and DMARC ('pass', 'fail', 'softfail', 'none') consistent with the attack scenario (e.g., spoofed domain fails SPF/DMARC; lookalike domain passes for its own domain).
   - Provide a 1-sentence explanatory 'notes'.

Format as JSON with keys:
- subject: string
- sender_name: string
- sender_email: string (must end in @...example or @...test)
- reply_to_email: string (must end in @...example or @...test)
- recipient_name: string
- date_sent: string
- body: string
- link_display_text: string
- link_url: string (must end in .example or .test)
- header_analysis: object with keys 'spf', 'dkim', 'dmarc', 'notes'
- red_flags: array of objects with keys 'flag', 'evidence', 'explanation'
- psychological_triggers: array of objects with keys 'trigger', 'where_used'
- safe_response: array of 3 strings
- analysis: string (educational breakdown)
- difficulty: string ("{request.difficulty}")

[SIMULATION ONLY - Educational Cybersecurity Awareness]"""

    validated_payload, fallback_reason = await execute_llm_with_validation(prompt, LLMPhishingPayload)

    if validated_payload is not None:
        phishing_data = PhishingResponse(
            subject=validated_payload.subject,
            sender_name=validated_payload.sender_name,
            sender_email=validated_payload.sender_email,
            reply_to_email=validated_payload.reply_to_email,
            recipient_name=validated_payload.recipient_name,
            date_sent=validated_payload.date_sent,
            body=validated_payload.body,
            link_display_text=validated_payload.link_display_text,
            link_url=validated_payload.link_url,
            header_analysis=validated_payload.header_analysis.model_dump(),
            red_flags=[rf.model_dump() for rf in validated_payload.red_flags],
            psychological_triggers=[pt.model_dump() for pt in validated_payload.psychological_triggers],
            safe_response=validated_payload.safe_response,
            analysis=validated_payload.analysis,
            generation_source="llm",
            fallback_reason=None
        )
    else:
        fallback_data = fallback_generate_phishing(
            role=request.target_role,
            difficulty=request.difficulty,
            industry=request.industry
        )
        phishing_data = PhishingResponse(
            subject=fallback_data["subject"],
            sender_name=fallback_data.get("sender_name"),
            sender_email=fallback_data.get("sender_email"),
            reply_to_email=fallback_data.get("reply_to_email"),
            recipient_name=fallback_data.get("recipient_name"),
            date_sent=fallback_data.get("date_sent"),
            body=fallback_data["body"],
            link_display_text=fallback_data.get("link_display_text"),
            link_url=fallback_data.get("link_url"),
            header_analysis=fallback_data.get("header_analysis"),
            red_flags=fallback_data["red_flags"],
            psychological_triggers=fallback_data.get("psychological_triggers"),
            safe_response=fallback_data.get("safe_response"),
            analysis=fallback_data["analysis"],
            generation_source="fallback",
            fallback_reason=fallback_reason
        )

    # Store in database with created_at as ISO string
    doc = phishing_data.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.phishing_simulations.insert_one(doc)

    return phishing_data

@api_router.post("/ransomware/generate", response_model=RansomwareResponse)
async def generate_ransomware(request: RansomwareRequest):
    prompt = f"""You are a Cyber Threat Simulation Specialist and Ransomware Incident Response Architect.
Generate a realistic, step-by-step ransomware infection simulation and incident response plan for cybersecurity training.

Attack Vector: {request.attack_vector}
Organization Type: {request.organization_type}

Rules:
1. Output MUST be valid JSON matching the exact schema below.
2. The scenario MUST contain 6 to 8 sequential infection steps.
3. Steps must cover the complete ransomware attack lifecycle:
   - Initial Access tailored to {request.attack_vector}
   - Execution
   - Discovery or Command and Control
   - Credential Access or Lateral Movement
   - Exfiltration or Collection
   - Impact with technique T1486 (Data Encrypted for Impact) as the final or near-final step.
4. Each step MUST specify:
   - step_number: Integer (1, 2, 3...)
   - title: Concise step title (DO NOT prefix with 'Step N:')
   - description: 1-2 detailed sentences tailored to {request.attack_vector} and {request.organization_type} (DO NOT prefix with 'Step N:')
   - tactic: Exactly ONE primary Enterprise ATT&CK tactic from: Reconnaissance, Resource Development, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact.
   - technique_id: Valid MITRE ATT&CK Enterprise technique ID (e.g. 'T1566.001', 'T1059.001', 'T1486').
   - technique_name: Matching MITRE technique name.
   - detection_hint: 1 sentence naming a specific log source, Windows Event ID, Sysmon event, EDR alert, or network telemetry.
   - containment_action: 1 sentence actionable defender response at this stage.
5. DOUBLE EXTORTION & TECHNICAL CONSISTENCY:
   - If data exfiltration or double extortion is performed, the exfiltration step MUST come BEFORE the encryption (T1486) step.
   - The summary (2-3 sentences) must be written AFTER planning the steps and must accurately describe the SAME initial vector, tools, and extortion objective.
   - Each step's description, tactic, technique, detection hint, and containment action must be technically consistent (e.g. macros exist only in Office files, not PDFs; RDP exploits differ from email attachments).
6. Response Plan: Include 3 immediate actions, 3 recovery steps, and 3 lessons learned.
7. Prevention Tips: Include 3-5 actionable prevention tips where each tip object has 'text' (plain text, NO leading asterisks '*' or bullet points '-') and 'addresses_step' (integer step number).

Format as JSON with keys:
- summary: string
- steps: array of step objects
- response_plan: object with keys 'immediate_actions' (array of 3 strings), 'recovery_steps' (array of 3 strings), 'lessons_learned' (array of 3 strings)
- prevention_tips: array of objects with keys 'text' (string) and 'addresses_step' (integer)

[SIMULATION ONLY - Educational Cybersecurity Training]"""

    validated_payload, fallback_reason = await execute_llm_with_validation(prompt, LLMRansomwarePayload)
    
    if validated_payload is not None:
        steps_dicts = [s.model_dump() for s in validated_payload.steps]
        tips_dicts = [t.model_dump() for t in validated_payload.prevention_tips]
        inf_flow = [s.description for s in validated_payload.steps]
        
        seen_tids = set()
        mitre_map = []
        for s in validated_payload.steps:
            if s.technique_id not in seen_tids:
                seen_tids.add(s.technique_id)
                mitre_map.append({"id": s.technique_id, "name": s.technique_name})

        ransomware_data = RansomwareResponse(
            attack_vector=request.attack_vector,
            summary=validated_payload.summary,
            infection_flow=inf_flow,
            mitre_mapping=mitre_map,
            steps=steps_dicts,
            response_plan=validated_payload.response_plan.model_dump(),
            prevention_tips=tips_dicts,
            generation_source="llm",
            fallback_reason=None
        )
    else:
        fallback_data = fallback_generate_ransomware(
            attack_vector=request.attack_vector,
            organization_type=request.organization_type
        )
        ransomware_data = RansomwareResponse(
            attack_vector=request.attack_vector,
            summary=fallback_data.get("summary", ""),
            infection_flow=fallback_data["infection_flow"],
            mitre_mapping=fallback_data["mitre_mapping"],
            steps=fallback_data.get("steps"),
            response_plan=fallback_data.get("response_plan"),
            prevention_tips=fallback_data["prevention_tips"],
            generation_source="fallback",
            fallback_reason=fallback_reason
        )
    
    doc = ransomware_data.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.ransomware_simulations.insert_one(doc)
    
    return ransomware_data

@api_router.post("/attack-scenario/generate", response_model=AttackScenarioResponse)
async def generate_attack_scenario(request: AttackScenarioRequest):
    prompt = f"""You are an Expert Cyber Threat Scenario Architect.
Generate a complete, realistic cyber attack scenario simulation for training.

Organization Type: {request.organization_type}
Security Maturity: {request.security_maturity}

Rules:
1. Output MUST be valid JSON conforming to the schema below.
2. The 'timeline' must contain 8 to 10 attack stages strictly following forward MITRE ATT&CK kill-chain sequence in this order: Reconnaissance -> Resource Development -> Initial Access -> Execution -> Persistence -> Privilege Escalation -> Defense Evasion -> Credential Access -> Discovery -> Lateral Movement -> Collection -> Command and Control -> Exfiltration -> Impact. A tactic may only be followed by the same tactic or a later tactic in this order.
3. The scenario MUST cover the full attack lifecycle:
   - At least one stage with tactic 'Initial Access'
   - At least one stage with tactic 'Execution'
   - At least one stage with tactic 'Credential Access' or 'Privilege Escalation'
   - At least one stage with tactic 'Lateral Movement' or 'Discovery'
   - At least one stage with tactic 'Collection' or 'Exfiltration'
   - The final stage MUST have tactic 'Impact' or 'Exfiltration'
4. Each stage MUST specify:
   - stage: Clear title for the stage (e.g., 'Initial Access via Spearphishing Link')
   - time: Relative time progression (e.g., 'Day 0', 'Day 2', 'Week 1', 'Month 1')
   - tactic: Exactly ONE primary Enterprise ATT&CK tactic from the ordered list above.
   - techniques: Array of 1 to 2 objects with 'technique_id' (e.g., 'T1566.002', 'T1059.001') and 'technique_name'. Use ONLY real ATT&CK Enterprise techniques matching what the stage description actually performs.
   - detection_likelihood: Based on organization maturity ({request.security_maturity}):
       * Low maturity = mostly "Low", at most one "Medium"
       * Medium maturity = mix of "Low", "Medium", and "High"
       * High maturity = mostly "Medium" or "High", at most one "Low"
   - description: 1-2 sentence detailed explanation of the attack activity tailored to {request.organization_type}. Every stage must have a distinct, unique description.
   - impact: Concise sentence explaining the consequence of this stage.
   - detection_hint: 1 sentence naming the specific log source, telemetry, or detection rule (e.g. Sysmon Event ID 1, Zeek DNS, EDR).
   - mitigation: 1 sentence actionable defensive countermeasure.
5. SUMMARY CONSISTENCY: Write the summary AFTER planning the stages, and make it consistent with them. Do not mention techniques, cloud providers or goals that do not appear in the stages.

Format as JSON with keys: title, summary, timeline (array of stage objects).
[SIMULATION ONLY]"""

    validated_payload, fallback_reason = await execute_llm_with_validation(prompt, LLMAttackScenarioPayload)
    
    if validated_payload is not None:
        scenario_data = AttackScenarioResponse(
            title=validated_payload.title,
            summary=validated_payload.summary,
            timeline=[s.model_dump() for s in validated_payload.timeline],
            generation_source="llm",
            fallback_reason=None
        )
    else:
        fallback_data = fallback_generate_attack_scenario(
            organization_type=request.organization_type,
            security_maturity=request.security_maturity
        )
        scenario_data = AttackScenarioResponse(
            title=fallback_data["title"],
            summary=fallback_data.get("summary", ""),
            timeline=fallback_data["timeline"],
            generation_source="fallback",
            fallback_reason=fallback_reason
        )
    
    doc = scenario_data.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.attack_scenarios.insert_one(doc)
    
    return scenario_data

@api_router.post("/training/question", response_model=TrainingQuestionResponse)
async def generate_training_question(request: TrainingQuestionRequest):
    category = request.scenario_type.strip() if request.scenario_type else "General Security"
    prompt = f"""You are a Principal Cybersecurity Educator and Certification Exam Author.
Generate a high-quality, balanced multiple-choice cybersecurity training question.

Requested Category: {category}

RULES:
1. STRICT CATEGORY ADHERENCE:
   The question must be strictly about '{category}' and must not be about any other topic.
   - Phishing questions MUST focus on email lures, spoofing, lookalike domains, headers (SPF/DKIM/DMARC), attachments, or credentials.
   - Ransomware questions MUST focus on encryption (T1486), extortion, shadow copies, backups, RDP vectors, or containment.
   - General Security questions MUST focus on MFA, least privilege, zero trust, passwords, CIA triad, vulnerabilities, or firewalls.
   - Incident Response questions MUST focus on PICERL phases (Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned).

2. BALANCED OPTIONS (NO OBVIOUS CLUES):
   - Provide exactly 4 options.
   - All 4 options must be similar in length, detail, and tone (the correct option must NEVER be significantly longer than the wrong ones).
   - Distractors must be plausible, technically realistic security concepts from the same domain (NEVER nonsense like "Encryption Error").
   - Do NOT prefix options with letters or numbers (e.g. write "Exfiltrating sensitive data", NOT "A) Exfiltrating sensitive data").
   - Do NOT include any HTML tags.

3. OPTION EXPLANATIONS:
   - Provide an explanation for each option explaining why the correct option is right and why each incorrect option is wrong.

Format as JSON with keys:
- question: string
- options: array of exactly 4 strings (plain text without leading labels)
- correct_answer: string (exact text of the correct option, or letter A/B/C/D)
- explanation: string (overall comprehensive explanation)
- option_explanations: object mapping option letters ("A", "B", "C", "D") to 1-sentence explanations
- category: string ("{category}")
"""

    validated_payload, fallback_reason = await execute_llm_with_validation(
        prompt,
        LLMTrainingQuestionPayload
    )
    
    if validated_payload is not None:
        formatted = shuffle_and_format_question(
            question_text=validated_payload.question,
            options=validated_payload.options,
            correct_idx_or_text_or_letter=validated_payload.correct_answer,
            explanation=validated_payload.explanation,
            option_explanations=validated_payload.option_explanations,
            category=category
        )
        question_data = TrainingQuestionResponse(
            question=formatted["question"],
            options=formatted["options"],
            correct_answer=formatted["correct_answer"],
            explanation=formatted["explanation"],
            category=category,
            option_explanations=formatted["option_explanations"],
            generation_source="llm",
            fallback_reason=None
        )
    else:
        fallback_data = fallback_generate_training_question(category)
        question_data = TrainingQuestionResponse(
            question=fallback_data["question"],
            options=fallback_data["options"],
            correct_answer=fallback_data["correct_answer"],
            explanation=fallback_data["explanation"],
            category=category,
            option_explanations=fallback_data.get("option_explanations"),
            generation_source="fallback",
            fallback_reason=fallback_reason
        )
    
    # Store question in database for answer verification
    doc = question_data.model_dump()
    doc['created_at'] = datetime.now(timezone.utc).isoformat()
    await db.training_questions.insert_one(doc)
    
    return question_data

@api_router.post("/training/answer", response_model=TrainingAnswerResponse)
async def check_training_answer(request: TrainingAnswerRequest):
    question_doc = await db.training_questions.find_one({"id": request.question_id})
    category = question_doc.get("category", "General Security") if question_doc else "General Security"
    
    if request.skipped:
        correct = False
        score_gained = 0
        skipped = True
        explanation = question_doc.get("explanation", "Question skipped.") if question_doc else "Question skipped."
        correct_letter = str(question_doc.get("correct_answer", "A")).strip().upper() if question_doc else "A"
    elif question_doc:
        correct_letter = str(question_doc.get("correct_answer", "")).strip().upper()
        user_letter = str(request.user_answer or "").strip().upper()
        correct = (user_letter == correct_letter)
        score_gained = 10 if correct else 0
        skipped = False
        explanation = question_doc.get("explanation", "Good job!" if correct else "Review the material and try again.")
    else:
        correct = False
        score_gained = 0
        skipped = False
        correct_letter = "A"
        explanation = "Question session expired or not found. Please generate a new question."
    
    # Record attempt
    attempt_doc = {
        "id": str(uuid.uuid4()),
        "question_id": request.question_id,
        "category": category,
        "user_answer": request.user_answer if not request.skipped else None,
        "correct": correct,
        "skipped": skipped,
        "score": score_gained,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    await db.training_scores.insert_one(attempt_doc)
    
    # Compute updated global metrics
    scores = await db.training_scores.find({}).to_list(5000)
    metrics = compute_training_metrics(scores)
    
    return TrainingAnswerResponse(
        correct=correct,
        explanation=explanation,
        score_gained=score_gained,
        option_explanations=question_doc.get("option_explanations") if question_doc else None,
        correct_answer=correct_letter,
        user_answer=request.user_answer,
        skipped=skipped,
        total_score=metrics["total_score"],
        accuracy=metrics["overall_accuracy"],
        streak=metrics["current_streak"]
    )

@api_router.get("/training/stats", response_model=TrainingStatsResponse)
async def get_training_stats():
    scores = await db.training_scores.find({}).to_list(5000)
    metrics = compute_training_metrics(scores)
    return TrainingStatsResponse(
        total_score=metrics["total_score"],
        questions_answered=metrics["questions_answered"],
        overall_accuracy=metrics["overall_accuracy"],
        current_streak=metrics["current_streak"],
        category_accuracy=metrics["category_accuracy"],
        weakest_area=metrics["weakest_area"],
        recommended_next=metrics["recommended_next"]
    )

@api_router.get("/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats():
    phishing_count = await db.phishing_simulations.count_documents({})
    ransomware_count = await db.ransomware_simulations.count_documents({})
    scenario_count = await db.attack_scenarios.count_documents({})
    
    scores = await db.training_scores.find({}).to_list(5000)
    metrics = compute_training_metrics(scores)
    
    simulations_by_type = [
        {"name": "Phishing", "count": phishing_count, "color": "#00f0ff"},
        {"name": "Ransomware", "count": ransomware_count, "color": "#ff003c"},
        {"name": "Attack Scenario", "count": scenario_count, "color": "#fcee0a"}
    ]
    
    return DashboardStats(
        total_simulations=phishing_count + ransomware_count + scenario_count,
        phishing_sims=phishing_count,
        ransomware_sims=ransomware_count,
        attack_scenarios=scenario_count,
        training_score=metrics["total_score"],
        total_score=metrics["total_score"],
        questions_answered=metrics["questions_answered"],
        overall_accuracy=metrics["overall_accuracy"],
        current_streak=metrics["current_streak"],
        category_accuracy=metrics["category_accuracy"],
        score_over_time=metrics["score_over_time"],
        simulations_by_type=simulations_by_type,
        weakest_area=metrics["weakest_area"],
        recommended_next=metrics["recommended_next"]
    )


# Include router
app.include_router(api_router)

# CORS middleware using settings
cors_origins_list = [origin.strip() for origin in settings.CORS_ORIGINS.split(",") if origin.strip()]
if not cors_origins_list:
    cors_origins_list = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=cors_origins_list,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
