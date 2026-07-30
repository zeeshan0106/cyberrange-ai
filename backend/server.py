from fastapi import FastAPI, APIRouter, HTTPException
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional
import uuid
from datetime import datetime, timezone
import json
import random
import asyncio
from litellm import acompletion


ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ["DB_NAME"]]

# Create the main app
app = FastAPI()
api_router = APIRouter(prefix="/api")


# ============= MODELS =============
class PhishingRequest(BaseModel):
    target_role: str
    difficulty: str
    industry: str

class PhishingResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    subject: str
    body: str
    red_flags: List[str]
    analysis: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class RansomwareRequest(BaseModel):
    attack_vector: str
    organization_type: str

class RansomwareResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    attack_vector: str
    infection_flow: List[str]
    mitre_mapping: List[dict]
    prevention_tips: List[str]
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class AttackScenarioRequest(BaseModel):
    organization_type: str
    security_maturity: str

class AttackScenarioResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    timeline: List[dict]
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class TrainingQuestionRequest(BaseModel):
    scenario_type: str

class TrainingQuestionResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    question: str
    options: List[str]
    correct_answer: str
    explanation: str

class TrainingAnswerRequest(BaseModel):
    question_id: str
    user_answer: str

class TrainingAnswerResponse(BaseModel):
    correct: bool
    explanation: str
    score_gained: int

class DashboardStats(BaseModel):
    model_config = ConfigDict(extra="ignore")
    total_simulations: int
    phishing_sims: int
    ransomware_sims: int
    attack_scenarios: int
    training_score: int
    multiplayer_stats: dict

class MultiplayerAttackRequest(BaseModel):
    subject: str
    body: str
    link: str

class MultiplayerAttackResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    subject: str
    body: str
    link: str
    status: str = "pending"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# --- DYNAMIC QUESTION GENERATORS ---

def format_question(question_text, correct_text, distractors_pool, explanation_text):
    # Ensure unique distractors
    distractors = random.sample([d for d in distractors_pool if d != correct_text], 3)
    options = distractors + [correct_text]
    random.shuffle(options)
    
    # Map to A, B, C, D
    labels = ["A", "B", "C", "D"]
    correct_idx = options.index(correct_text)
    correct_letter = labels[correct_idx]
    
    return {
        "question": question_text,
        "options": options,
        "correct_answer": correct_letter,
        "explanation": explanation_text
    }

def generate_phishing_question_v2():
    actors = ["HR Department", "IT Support", "The CEO", "A Vendor", "FedEx/UPS", "Bank Security"]
    actions = ["verify your password", "pay an overdue invoice", "download a software update", "confirm a delivery", "claim a refund"]
    vectors = [
        {"type": "Typosquatting", "desc": "The URL is 'c0mpany.com' instead of 'company.com'.", "ans": "Typosquatting / URL Spoofing"},
        {"type": "Malicious Attachment", "desc": "The file is named 'Report.pdf.exe'.", "ans": "Double Extension / Executable"},
        {"type": "Urgency", "desc": "The email says 'ACT NOW OR BE FIRED'.", "ans": "Psychological Manipulation (Urgency)"},
        {"type": "Mismatched Sender", "desc": "The sender name is 'IT Support' but the email is 'gamer123@gmail.com'.", "ans": "Sender Identity Mismatch"},
        {"type": "Credential Harvesting", "desc": "The login page is HTTP (not HTTPS) and asks for credentials.", "ans": "Unsecured Login / Credential Harvesting"}
    ]
    
    actor = random.choice(actors)
    action = random.choice(actions)
    vector = random.choice(vectors)
    
    scenario = f"You receive an email from {actor} asking you to {action}. You notice that {vector['desc']}"
    
    q = f"Scenario: {scenario}\\n\\nWhat is the specific red flag here?"
    correct = vector['ans']
    distractors = [v['ans'] for v in vectors if v['ans'] != correct] + ["Valid Business Communication", "Server Latency", "Encryption Error"]
    
    return format_question(q, correct, distractors, f"The presence of '{vector['desc']}' indicates {vector['ans']}.")

def generate_ransomware_question_v2():
    concepts = [
        ("Ransomware", "Malware that encrypts data and demands payment.", ["Spyware", "Adware", "Rootkit"]),
        ("Double Extortion", "Encrypting data AND threatening to leak it.", ["Encrypting backups", "Charging double fees", "Infecting two devices"]),
        ("RDP (Remote Desktop)", "A common entry point for ransomware attackers.", ["USB Drives", "Bluetooth", "NFC"]),
        ("3-2-1 Backup Rule", "The best defense strategy for data recovery.", ["RAID 0", "Cloud Sync", "Antivirus"]),
        ("Kill Switch", "A mechanism to stop malware propagation.", ["Firewall", "Router", "VPN"])
    ]
    
    concept, defn, wrong = random.choice(concepts)
    
    if random.choice([True, False]):
        q = f"What is '{concept}' in the context of ransomware?"
        correct = defn
        distractors = wrong + ["A method to speed up encryption", "A type of firewall rule", "A network protocol"]
        expl = f"{concept}: {defn}"
    else:
        q = f"Which of the following best describes '{concept}'?"
        correct = defn
        distractors = wrong + ["System performance tool", "Network monitoring software", "Database optimization"]
        expl = f"{concept} is defined as: {defn}"
        
    return format_question(q, correct, distractors, expl)

def generate_ir_question_v2():
    phases = [
        ("Preparation", "Setting up tools, policies, and teams before an incident.", ["Cleaning up malware", "Restoring backups"]),
        ("Identification", "Detecting and determining the scope of an incident.", ["Patching vulnerabilities", "Updating policies"]),
        ("Containment", "Limiting the spread of the attack.", ["Deleting all files", "Ignoring the alert"]),
        ("Eradication", "Removing the root cause and artifacts of the attack.", ["Reporting to legal", "Monitoring traffic"]),
        ("Recovery", "Restoring systems to normal operation.", ["Collecting evidence", "Isolating the host"]),
        ("Lessons Learned", "Documenting the incident and improving future responses.", ["Firing the admin", "Paying the ransom"])
    ]
    
    phase, action, wrong = random.choice(phases)
    
    if random.choice([True, False]):
        q = f"During the '{phase}' phase of Incident Response, what is the primary goal?"
        correct = action
        distractors = wrong + ["Negotiating with attackers", "Publicly announcing the breach", "Purchasing new hardware"]
        expl = f"The {phase} phase focuses on {action.lower()}"
    else:
        q = f"Which phase of the PICERL cycle involves '{action.lower()}'?"
        correct = phase
        distractors = [p[0] for p in phases if p[0] != phase]
        expl = f"{action} is the core activity of the {phase} phase."
        
    return format_question(q, correct, distractors, expl)

def generate_general_question_v2():
    topics = [
        ("Least Privilege", "Users have only the minimum access necessary.", ["Admin access for all", "No access at all"]),
        ("Zero Trust", "Never trust, always verify.", ["Trust internal network", "Trust but verify"]),
        ("MFA", "Using two or more different factors to verify identity.", ["Using two passwords", "Changing passwords monthly"]),
        ("Social Engineering", "Manipulating people into revealing confidential info.", ["Hacking firewalls", "Brute forcing passwords"]),
        ("CIA Triad", "Confidentiality, Integrity, Availability.", ["Control, Identity, Access", "Computer, Internet, Access"])
    ]
    
    t, d, w = random.choice(topics)
    q = f"What is the core principle of '{t}'?"
    correct = d
    distractors = w + ["Ensuring fast network speeds", "Reducing hardware costs", "Simplifying user login"]
    expl = f"{t} relies on: {d}"
    
    return format_question(q, correct, distractors, expl)

def generate_dynamic_question_response(prompt):
    prompt_lower = prompt.lower()
    if "phishing" in prompt_lower:
        return generate_phishing_question_v2()
    elif "ransomware" in prompt_lower:
        return generate_ransomware_question_v2()
    elif "incident" in prompt_lower:
        return generate_ir_question_v2()
    else:
        return generate_general_question_v2()

async def query_llm(prompt: str) -> Optional[str]:
    api_key = os.environ.get("EMERGENT_LLM_KEY")
    if not api_key:
        return None
        
    try:
        response = await asyncio.wait_for(
            acompletion(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                api_key=api_key
            ),
            timeout=5.0
        )
        return response.choices[0].message.content
    except asyncio.TimeoutError:
        print("LLM Request Timed Out - Falling back to local generation")
        return None
    except Exception as e:
        print(f"LLM Error: {e}")
        return None

async def get_llm_response(prompt: str) -> str:
    # Try Real LLM first
    llm_result = await query_llm(prompt)
    if llm_result:
        return llm_result

    prompt_lower = prompt.lower()
    
    if "training question" in prompt_lower:
        # Generate truly dynamic, component-based questions
        return json.dumps(generate_dynamic_question_response(prompt))

    elif "phishing" in prompt_lower:
        # Extract Role, Difficulty, Industry from prompt
        role = "Employee" # Default
        if "target role: hr" in prompt_lower: role = "HR"
        elif "target role: finance" in prompt_lower: role = "Finance"
        elif "target role: student" in prompt_lower: role = "Student"
        elif "target role: admin" in prompt_lower: role = "Admin"
        
        difficulty = "Medium"
        if "low" in prompt_lower and "difficulty" in prompt_lower: difficulty = "Low"
        elif "high" in prompt_lower and "difficulty" in prompt_lower: difficulty = "High"
        
        industry = "IT"
        if "education" in prompt_lower: industry = "Education"
        elif "healthcare" in prompt_lower: industry = "Healthcare"

        # --- COMPONENT-BASED GENERATOR ---
        
        # 1. Greetings
        greetings = {
            "Employee": ["Dear Employee,", "Hi Team,", "Attention Staff,", "Hello,", "Dear User,"],
            "HR": ["Dear Colleague,", "HR Team,", "Hello,", "Attn: HR Manager,"],
            "Finance": ["Hi,", "Accounts Payable,", "Dear Finance Team,", "Attention: CFO,"],
            "Student": ["Dear Student,", "Hi,", "Campus Alert:", "Library Notice:"],
            "Admin": ["Admin,", "System Alert:", "Dear Administrator,", "IT Security Notice:"],
            "Generic": ["Hello,", "Dear Customer,", "Urgent:", "Notification:"]
        }
        
        # 2. Hooks / Contexts (The "Why")
        hooks = {
            "Finance": [
                "I need you to process a wire transfer for a new vendor immediately.",
                "Attached is an overdue invoice that needs to be paid by end of day.",
                "We are auditing our accounts and need you to verify the attached transaction logs.",
                "Please update the payment details for Project Horizon."
            ],
            "HR": [
                "Please review the attached resume for the Senior Developer position.",
                "Open enrollment for benefits ends tomorrow. Please confirm your selection.",
                "A complaint has been filed against you. See details in the attached report.",
                "New policy update regarding remote work. Acknowledgement required."
            ],
            "Student": [
                "You have an overdue library fine that will block your registration.",
                "We are hiring remote assistants for $500/week. No experience needed.",
                "Your student portal access will be revoked due to inactivity.",
                "Scholarship opportunity approved! Click to claim your funds."
            ],
            "Admin": [
                "SSL Certificate for *.company.com is expiring in 24 hours.",
                "Unusual login activity detected from IP 192.168.1.55 (Russia).",
                "Critical vulnerability found in VPN gateway. Apply patch immediately.",
                "Server storage capacity reached 99%. Cleanup required."
            ],
            "Employee": [
                "Your password expires in 24 hours.",
                "You have a new voicemail from +1 (555) 019-2834.",
                "A package delivery failed. Reschedule delivery now.",
                "Payroll mismatch detected. Please verify your bank details."
            ]
        }
        
        # 3. Urgency / Pressure (The "When")
        urgency_drivers = {
            "Low": ["Act now!!", "You won big!", "Don't wait!", "Urgent response needed!!!"],
            "Medium": ["Please complete this by EOD.", "Action required within 24 hours.", "To avoid service interruption, please act now.", "Awaiting your confirmation."],
            "High": ["This is confidential.", "The board is waiting on this.", "Per compliance regulations, this is mandatory.", "I am stepping into a meeting, handle this ASAP."]
        }
        
        # 4. Call to Action (The "How")
        ctas = [
            f"Click here: http://{random.choice(['secure-login', 'verify-portal', 'admin-tools', 'company-support'])}.net/{random.choice(['login', 'auth', 'verify', 'update'])}",
            f"Download attachment: {random.choice(['Invoice_4022.pdf.exe', 'Resume_John.doc', 'Payment_Info.xlsx', 'System_Patch.msi'])}",
            "Reply with your mobile number so I can text you the code.",
            "Login to the portal to view the secure message."
        ]
        
        # 5. Sign-offs
        signoffs = {
            "Finance": ["CFO", "Finance Director", "Vendor Management", "Accounts Payable"],
            "HR": ["HR Director", "People Ops", "Benefits Team", "Compliance Officer"],
            "Admin": ["IT Support", "NOC Team", "CISO", "System Administrator"],
            "Student": ["University Admin", "Dean of Students", "Library Services", "Financial Aid Office"],
            "Employee": ["IT Helpdesk", "HR Department", "Management", "Security Team"]
        }
        
        # BUILD THE EMAIL
        greeting = random.choice(greetings.get(role, greetings["Generic"]))
        
        # Select hook based on role, fallback to Employee if empty or specific industry match needed
        # (For simplicity using Role-based hooks which cover most industry contexts here)
        hook_pool = hooks.get(role, hooks["Employee"])
        if industry == "Healthcare" and role == "Employee":
            hook_pool.append("HIPAA Compliance Audit scheduled for your department.")
            hook_pool.append("Patient records access verification required.")
        elif industry == "Education" and role == "Employee": # Staff in education
            hook_pool.append("Faculty meeting schedule changed.")
            hook_pool.append("Grade submission deadline reminder.")
            
        context = random.choice(hook_pool)
        
        urgency = random.choice(urgency_drivers.get(difficulty, urgency_drivers["Medium"]))
        cta = random.choice(ctas)
        signoff = random.choice(signoffs.get(role, signoffs["Employee"]))
        
        # Assemble Body
        body = f"{greeting}\n\n{context}\n\n{urgency}\n\n{cta}\n\nRegards,\n{signoff}"
        
        # Determine Subject based on context (simple mapping or generation)
        # For a truly dynamic subject, we can map hooks to subjects or generate them
        subject_map = {
            "wire transfer": "Urgent: Wire Transfer Request",
            "invoice": "Overdue Invoice #9928",
            "auditing": "Audit: Action Required",
            "resume": "Application: Senior Dev",
            "enrollment": "Benefits Enrollment Closing",
            "complaint": "HR: Incident Report",
            "policy": "New Policy Update",
            "library": "Library Fine Notice",
            "hiring": "Job Opportunity",
            "portal": "Access Revoked",
            "scholarship": "Scholarship Update",
            "SSL": "Alert: Certificate Expiry",
            "login": "Security Alert: Unusual Activity",
            "vulnerability": "Patch Management",
            "storage": "System Alert: Disk Space",
            "password": "Password Expiry Notice",
            "voicemail": "New Voicemail (2)",
            "package": "Delivery Exception",
            "Payroll": "Payroll Action Item",
            "HIPAA": "Compliance Audit",
            "Patient": "Access Verification",
            "Faculty": "Meeting Update",
            "Grade": "Grade Submission"
        }
        
        subject = "Urgent Notification" # Default
        for key, val in subject_map.items():
            if key in context:
                subject = val
                break
                
        # Analysis Generation
        red_flags = []
        if difficulty == "Low":
            red_flags = ["Generic greeting", "Typos/Poor grammar", "Unrealistic urgency", "Suspicious link"]
        elif difficulty == "Medium":
            red_flags = ["Urgency", "Link to external site", "Request for sensitive info"]
        else: # High
            red_flags = ["Authority pressure", "Spoofed internal process", "Contextual relevance"]
            
        analysis = f"This simulated phishing email targets the {role} role using {difficulty} difficulty tactics. "
        analysis += f"It leverages '{subject}' to create a sense of importance. "
        analysis += "Always verify such requests through a secondary channel."

        return json.dumps({
            "subject": subject,
            "body": body,
            "red_flags": red_flags,
            "analysis": analysis
        })
    
    elif "ransomware" in prompt_lower:
        # Extract parameters from prompt
        vector = "email" # Default
        if "usb" in prompt_lower: vector = "usb"
        elif "rdp" in prompt_lower: vector = "rdp"
        elif "link" in prompt_lower or "malicious link" in prompt_lower: vector = "link"
        
        org = "it" # Default
        if "healthcare" in prompt_lower: org = "healthcare"
        elif "financial" in prompt_lower: org = "financial"
        elif "education" in prompt_lower: org = "education"
        
        # 1. Infection Flow Logic
        steps = []
        
        # Initial Access (Step 1-2)
        if vector == "email":
            steps.append("User receives a phishing email with a disguised invoice attachment")
            steps.append("User opens the attachment enabling malicious macros")
        elif vector == "usb":
            steps.append("Employee inserts an infected USB drive found in the parking lot")
            steps.append("Malicious payload executes via AutoRun or user curiosity")
        elif vector == "rdp":
            steps.append("Attacker scans network for exposed RDP ports")
            steps.append("Attacker brute-forces weak credentials to gain access")
        elif vector == "link":
            steps.append("User clicks a malicious link disguised as a software update")
            steps.append("Drive-by download exploits a browser vulnerability")
            
        # Execution & Persistence (Step 3)
        steps.append("Malware establishes connection to Command & Control (C2) server")
        
        # Lateral Movement & Org Specific Impact (Step 4-5)
        if org == "healthcare":
            steps.append("Malware moves laterally to access PACS and EHR systems")
            steps.append("Critical patient databases are prioritized for encryption")
        elif org == "financial":
            steps.append("Attacker pivots to the secure payment processing VLAN")
            steps.append("Financial transaction logs and customer PII are exfiltrated")
        elif org == "education":
            steps.append("Worm spreads through the open campus Wi-Fi network")
            steps.append("Student record systems and research data are targeted")
        else: # IT Company
            steps.append("Malware scans for SSH keys and cloud credentials")
            steps.append("Source code repositories and CI/CD pipelines are encrypted")
            
        # Final Impact (Step 6)
        steps.append("Ransom note is displayed demanding payment in Bitcoin")
        
        # 2. MITRE ATT&CK Mapping
        mitre = []
        
        # Initial Access
        if vector == "email": mitre.append({"id": "T1566", "name": "Phishing"})
        elif vector == "usb": mitre.append({"id": "T1091", "name": "Replication Through Removable Media"})
        elif vector == "rdp": mitre.append({"id": "T1133", "name": "External Remote Services"})
        elif vector == "link": mitre.append({"id": "T1189", "name": "Drive-by Compromise"})
        
        # Execution/Persistence
        mitre.append({"id": "T1204", "name": "User Execution"})
        mitre.append({"id": "T1486", "name": "Data Encrypted for Impact"})
        
        if org == "financial": mitre.append({"id": "T1048", "name": "Exfiltration Over Alternative Protocol"})
        elif org == "healthcare": mitre.append({"id": "T1490", "name": "Inhibit System Recovery"})
        
        # 3. Prevention Tips
        tips = ["Maintain offline, encrypted backups (3-2-1 rule)"]
        
        if vector == "email":
            tips.append("Implement email filtering and sandboxing for attachments")
            tips.append("Conduct regular phishing simulation training")
        elif vector == "usb":
            tips.append("Disable AutoRun and restrict USB port usage")
            tips.append("Implement physical security policies for removable media")
        elif vector == "rdp":
            tips.append("Disable RDP if not needed or place behind a VPN")
            tips.append("Enforce strong passwords and MFA for remote access")
        elif vector == "link":
            tips.append("Keep browsers and plugins patched/updated")
            tips.append("Use DNS filtering to block known malicious domains")
            
        if org == "healthcare": tips.append("Segment medical devices (IoMT) from the main network")
        elif org == "financial": tips.append("Implement Data Loss Prevention (DLP) solutions")
        elif org == "education": tips.append("Segregate student/guest networks from administrative systems")
        else: tips.append("Secure code signing keys and cloud credentials")

        return json.dumps({
            "infection_flow": steps,
            "mitre_mapping": mitre,
            "prevention_tips": tips
        })
        
    elif "attack scenario" in prompt_lower:
        # Extract context from prompt to generate dynamic scenarios
        org_type = "generic"
        maturity = "medium"
        
        if "financial" in prompt_lower: org_type = "financial"
        elif "healthcare" in prompt_lower: org_type = "healthcare"
        elif "retail" in prompt_lower: org_type = "retail"
        elif "technology" in prompt_lower or "tech" in prompt_lower: org_type = "technology"
        elif "government" in prompt_lower: org_type = "government"
        
        if "low" in prompt_lower: maturity = "low"
        elif "high" in prompt_lower: maturity = "high"
        
        # Define scenario templates based on organization type
        scenarios = {
            "financial": {
                "title": "APT Simulation: Banking Trojan & Fraud",
                "stages": [
                    ("Initial Access", "Spear-phishing targeting SWIFT operators"),
                    ("Execution", "Malicious macro enables C2 beacon"),
                    ("Persistence", "Registry run keys modified for survival"),
                    ("Privilege Escalation", "Kerberoasting to gain Domain Admin"),
                    ("Lateral Movement", "Pivot to restricted Payment VLAN"),
                    ("Exfiltration", "Drip-exfiltration of transaction logs")
                ]
            },
            "healthcare": {
                "title": "APT Simulation: Hospital Infrastructure Ransom",
                "stages": [
                    ("Initial Access", "Compromised VPN credentials from vendor"),
                    ("Execution", "PowerShell script executes in memory"),
                    ("Persistence", "Scheduled task creation on gateway"),
                    ("Defense Evasion", "Disabling endpoint protection services"),
                    ("Lateral Movement", "Scanning for PACS/EHR servers"),
                    ("Impact", "Encryption of patient records and backups")
                ]
            },
            "technology": {
                "title": "APT Simulation: Supply Chain Compromise",
                "stages": [
                    ("Initial Access", "DevOps engineer session hijacking"),
                    ("Discovery", "Scanning internal git repositories"),
                    ("Persistence", "Backdoored library committed to codebase"),
                    ("Credential Access", "Harvesting CI/CD pipeline secrets"),
                    ("Lateral Movement", "Accessing production cloud environment"),
                    ("Exfiltration", "Theft of proprietary source code")
                ]
            },
            "government": {
                "title": "APT Simulation: State-Sponsored Espionage",
                "stages": [
                    ("Initial Access", "Zero-day exploit in public web server"),
                    ("Execution", "Web shell deployment"),
                    ("Persistence", "WMI event subscription"),
                    ("Command and Control", "Traffic mimicking legitimate DNS queries"),
                    ("Lateral Movement", "Pass-the-ticket to access classified subnet"),
                    ("Exfiltration", "Steganography used to hide stolen documents")
                ]
            },
            "retail": {
                "title": "APT Simulation: POS Malware Outbreak",
                "stages": [
                    ("Initial Access", "Phishing email with fake invoice"),
                    ("Execution", "Botnet loader installation"),
                    ("Persistence", "Service creation on store controller"),
                    ("Lateral Movement", "Spreading to Point-of-Sale terminals"),
                    ("Collection", "RAM scraping for credit card data"),
                    ("Exfiltration", "Batch upload to FTP server")
                ]
            }
        }
        
        # Default scenario
        default_scenario = {
            "title": "APT Simulation: Corporate Network Breach",
            "stages": [
                ("Initial Access", "Phishing campaign targets HR"),
                ("Execution", "Malware execution on workstation"),
                ("Persistence", "Attacker installs backdoor"),
                ("Lateral Movement", "Attacker moves to Domain Controller"),
                ("Exfiltration", "Sensitive customer data exfiltrated")
            ]
        }
        
        selected_scenario = scenarios.get(org_type, default_scenario)
        
        # Customize based on security maturity
        timeline = []
        base_time = 0
        
        # Time unit and progression speed depends on maturity
        # High maturity = slower, stealthier attack (Weeks/Months)
        # Low maturity = faster, noisier attack (Hours/Days)
        if maturity == "high":
            time_unit = "Week"
            time_step = 2
            desc_modifier = " using advanced evasion techniques"
            impact_modifier = " - Detected by SOC but difficult to contain"
        elif maturity == "low":
            time_unit = "Hour"
            time_step = 6
            desc_modifier = " exploiting unpatched vulnerability"
            impact_modifier = " - Undetected due to lack of logging"
        else: # medium
            time_unit = "Day"
            time_step = 2
            desc_modifier = ""
            impact_modifier = " - Partial detection"

        for i, (stage_name, stage_desc) in enumerate(selected_scenario["stages"]):
            time_val = f"{time_unit} {base_time + (i * time_step)}"
            
            timeline.append({
                "stage": stage_name,
                "time": time_val,
                "description": stage_desc + desc_modifier,
                "impact": "High" + impact_modifier
            })

        return json.dumps({
            "title": selected_scenario["title"] + f" ({maturity.title()} Maturity)",
            "timeline": timeline
        })
        
    return "{}"


# ============= API ENDPOINTS =============
@api_router.get("/")
async def root():
    return {"message": "CyberRange AI API v1.0"}

@api_router.post("/phishing/generate", response_model=PhishingResponse)
async def generate_phishing(request: PhishingRequest):
    prompt = f"""You are a Cybersecurity Training Email Generator.
    
    Your task is to generate realistic but SAFE phishing simulation emails strictly for educational and cyber-awareness training purposes.
    
    Rules:
    - Do NOT reference real companies or real people.
    - Always use fictional names, domains, and files.
    - Emails must look realistic but clearly be suitable for training simulations.
    - The generated email MUST change based on:
        1. Target Role: {request.target_role}
        2. Difficulty Level: {request.difficulty}
        3. Industry: {request.industry}
    
    Each output must include:
    - Subject
    - Email Body
    - One suspicious element (link OR attachment OR urgency OR authority pressure)
    - Language and tone adjusted to the selected parameters
    
    Never reuse the same wording across different parameter combinations.

    Format as JSON with keys: subject, body, red_flags (list of strings), analysis."""
    
    llm_response = await get_llm_response(prompt)
    
    # Parse LLM response
    try:
        import json
        import re
        json_match = re.search(r'```(?:json)?\s*({.*?})\s*```', llm_response, re.DOTALL)
        if json_match:
            parsed = json.loads(json_match.group(1))
        else:
            parsed = json.loads(llm_response)
    except:
        parsed = {
            "subject": "Urgent: Account Verification Required",
            "body": llm_response[:500],
            "red_flags": ["Urgency tactics", "Suspicious sender", "Generic greeting"],
            "analysis": "This is a simulated phishing attempt for training purposes."
        }
    
    phishing_data = PhishingResponse(
        subject=parsed.get('subject', 'Urgent Action Required'),
        body=parsed.get('body', llm_response),
        red_flags=parsed.get('red_flags', []),
        analysis=parsed.get('analysis', '')
    )
    
    # Store in database
    doc = phishing_data.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.phishing_simulations.insert_one(doc)
    
    return phishing_data

@api_router.post("/ransomware/generate", response_model=RansomwareResponse)
async def generate_ransomware(request: RansomwareRequest):
    prompt = f"""Generate a ransomware attack simulation for cybersecurity training.

Attack Vector: {request.attack_vector}
Organization Type: {request.organization_type}

Provide:
1. Step-by-step infection flow (5-7 steps)
2. MITRE ATT&CK mapping (3-5 techniques with IDs like T1566)
3. Prevention tips (3-5 actionable items)

Format as JSON with keys: infection_flow (array), mitre_mapping (array of objects with 'id' and 'name'), prevention_tips (array)
[SIMULATION ONLY - No Real Malware]"""

    llm_response = await get_llm_response(prompt)
    
    try:
        import json
        import re
        json_match = re.search(r'```(?:json)?\s*({.*?})\s*```', llm_response, re.DOTALL)
        if json_match:
            parsed = json.loads(json_match.group(1))
        else:
            parsed = json.loads(llm_response)
    except:
        parsed = {
            "infection_flow": ["Initial access", "Execution", "Persistence", "Privilege escalation", "Data encryption"],
            "mitre_mapping": [{"id": "T1566", "name": "Phishing"}],
            "prevention_tips": ["Regular backups", "Security awareness training", "Email filtering"]
        }
    
    ransomware_data = RansomwareResponse(
        attack_vector=request.attack_vector,
        infection_flow=parsed.get('infection_flow', []),
        mitre_mapping=parsed.get('mitre_mapping', []),
        prevention_tips=parsed.get('prevention_tips', [])
    )
    
    doc = ransomware_data.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.ransomware_simulations.insert_one(doc)
    
    return ransomware_data

@api_router.post("/attack-scenario/generate", response_model=AttackScenarioResponse)
async def generate_attack_scenario(request: AttackScenarioRequest):
    prompt = f"""Generate a complete cyber attack scenario for training.

Organization Type: {request.organization_type}
Security Maturity: {request.security_maturity}

Provide:
1. Attack title
2. Timeline with 6-8 stages, each with: stage (name), time (relative time like 'Day 0', 'Week 1'), description, impact

Format as JSON with keys: title, timeline (array of objects)
[SIMULATION ONLY]"""

    llm_response = await get_llm_response(prompt)
    
    try:
        import json
        import re
        json_match = re.search(r'```(?:json)?\s*({.*?})\s*```', llm_response, re.DOTALL)
        if json_match:
            parsed = json.loads(json_match.group(1))
        else:
            parsed = json.loads(llm_response)
    except:
        parsed = {
            "title": "Advanced Persistent Threat Simulation",
            "timeline": [
                {"stage": "Initial Access", "time": "Day 0", "description": "Phishing campaign", "impact": "Low"},
                {"stage": "Execution", "time": "Day 1", "description": "Malware execution", "impact": "Medium"}
            ]
        }
    
    scenario_data = AttackScenarioResponse(
        title=parsed.get('title', 'Cyber Attack Simulation'),
        timeline=parsed.get('timeline', [])
    )
    
    doc = scenario_data.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.attack_scenarios.insert_one(doc)
    
    return scenario_data

@api_router.post("/training/question", response_model=TrainingQuestionResponse)
async def generate_training_question(request: TrainingQuestionRequest):
    prompt = f"""Generate a cybersecurity training question.

Scenario Type: {request.scenario_type}

Provide:
1. A multiple-choice question
2. 4 options (A, B, C, D)
3. Correct answer (letter)
4. Detailed explanation

Format as JSON with keys: question, options (array of 4 strings), correct_answer (letter), explanation"""

    llm_response = await get_llm_response(prompt)
    
    
    # Check if llm_response is a JSON string directly (from our mock logic)
    parsed = {}
    try:
        if isinstance(llm_response, str) and llm_response.strip().startswith('{'):
             parsed = json.loads(llm_response)
        else:
             # Try to extract JSON from markdown code blocks
             import re
             json_match = re.search(r'```(?:json)?\s*({.*?})\s*```', llm_response, re.DOTALL)
             if json_match:
                 parsed = json.loads(json_match.group(1))
             else:
                 parsed = json.loads(llm_response)
    except Exception as e:
        logger.error(f"Failed to parse LLM response: {e}")
        parsed = {
            "question": "What is the first step in responding to a phishing email?",
            "options": ["Click the link", "Report to IT", "Reply to sender", "Delete immediately"],
            "correct_answer": "B",
            "explanation": "Always report suspicious emails to IT security team."
        }
    
    question_data = TrainingQuestionResponse(
        question=parsed.get('question', 'Error generating question'),
        options=parsed.get('options', ["Error", "Error", "Error", "Error"]),
        correct_answer=parsed.get('correct_answer', 'A'),
        explanation=parsed.get('explanation', 'Please try again.')
    )
    
    return question_data

@api_router.post("/training/answer", response_model=TrainingAnswerResponse)
async def check_training_answer(request: TrainingAnswerRequest):
    # Retrieve question from database by ID
    # For MVP, simplified logic
    correct = request.user_answer in ['B', 'C']
    
    response = TrainingAnswerResponse(
        correct=correct,
        explanation="Good job!" if correct else "Review the material and try again.",
        score_gained=10 if correct else 0
    )
    
    # Store score
    await db.training_scores.insert_one({
        "question_id": request.question_id,
        "user_answer": request.user_answer,
        "correct": correct,
        "score": response.score_gained,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    
    return response

@api_router.get("/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats():
    phishing_count = await db.phishing_simulations.count_documents({})
    ransomware_count = await db.ransomware_simulations.count_documents({})
    scenario_count = await db.attack_scenarios.count_documents({})
    
    # Calculate total training score
    scores = await db.training_scores.find({}).to_list(1000)
    total_score = sum(s.get('score', 0) for s in scores)
    
    # Calculate multiplayer stats
    total_attacks = await db.multiplayer_attacks.count_documents({})
    clicked_attacks = await db.multiplayer_attacks.count_documents({"status": "clicked"})
    reported_attacks = await db.multiplayer_attacks.count_documents({"status": "reported"})
    
    return DashboardStats(
        total_simulations=phishing_count + ransomware_count + scenario_count,
        phishing_sims=phishing_count,
        ransomware_sims=ransomware_count,
        attack_scenarios=scenario_count,
        training_score=total_score,
        multiplayer_stats={
            "total_attacks": total_attacks,
            "clicked": clicked_attacks,
            "reported": reported_attacks
        }
    )

@api_router.post("/multiplayer/send", response_model=MultiplayerAttackResponse)
async def send_attack(request: MultiplayerAttackRequest):
    attack_data = MultiplayerAttackResponse(
        subject=request.subject,
        body=request.body,
        link=request.link
    )
    doc = attack_data.model_dump()
    doc['timestamp'] = doc['timestamp'].isoformat()
    await db.multiplayer_attacks.insert_one(doc)
    return attack_data

@api_router.get("/multiplayer/inbox", response_model=List[MultiplayerAttackResponse])
async def get_inbox():
    # Get last 20 attacks, sorted by newest
    attacks = await db.multiplayer_attacks.find().sort("timestamp", -1).limit(20).to_list(20)
    return attacks

@api_router.post("/multiplayer/resolve")
async def resolve_attack(attack_id: str, action: str):
    await db.multiplayer_attacks.update_one(
        {"id": attack_id},
        {"$set": {"status": action}}
    )
    return {"status": "updated"}


# Include router
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
