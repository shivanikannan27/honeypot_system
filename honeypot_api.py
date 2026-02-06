from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime
import requests
import re

app = FastAPI(title="AI Honeypot API", version="2.0")

# ================= CONFIG =================

SECRET_API_KEY = "thinkheist_honeypot_2026_secure_key"
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

sessions = {}

# ================= MODELS =================

class Sender(str):
    scammer = "scammer"
    user = "user"


class Message(BaseModel):
    sender: str
    text: str
    timestamp: str


class IncomingRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = Field(default_factory=list)


class ExtractedIntelligence(BaseModel):
    bankAccounts: List[str] = []
    upiIds: List[str] = []
    phishingLinks: List[str] = []
    phoneNumbers: List[str] = []
    suspiciousKeywords: List[str] = []


class EngagementMetrics(BaseModel):
    engagementDurationSeconds: int
    totalMessagesExchanged: int


class HoneypotResponse(BaseModel):
    status: str
    scamDetected: bool
    response: Optional[str]
    engagementMetrics: EngagementMetrics
    extractedIntelligence: ExtractedIntelligence
    agentNotes: str


# ================= SESSION =================

class Session:
    def __init__(self, session_id):
        self.session_id = session_id
        self.start_time = datetime.now()
        self.messages = []
        self.scam_detected = False
        self.intelligence = ExtractedIntelligence()
        self.callback_sent = False
        self.notes = []

    def duration(self):
        return int((datetime.now() - self.start_time).total_seconds())

    def count(self):
        return len(self.messages)

    def extract(self, text):
        # Phone numbers
        phones = re.findall(r"\b\d{10}\b", text)
        for p in phones:
            if p not in self.intelligence.phoneNumbers:
                self.intelligence.phoneNumbers.append(p)

        # UPI IDs
        upis = re.findall(r"\b[\w\.-]+@[\w\.-]+\b", text.lower())
        for u in upis:
            if any(x in u for x in ["upi", "ybl", "okaxis", "okhdfc"]):
                if u not in self.intelligence.upiIds:
                    self.intelligence.upiIds.append(u)

        # URLs
        urls = re.findall(r"https?://[^\s]+", text)
        for u in urls:
            if u not in self.intelligence.phishingLinks:
                self.intelligence.phishingLinks.append(u)

        # Keywords
        keywords = ["urgent", "otp", "verify", "block", "account"]
        for k in keywords:
            if k in text.lower() and k not in self.intelligence.suspiciousKeywords:
                self.intelligence.suspiciousKeywords.append(k)


# ================= SCAM DETECTION =================

def detect_scam(text):
    patterns = ["urgent", "otp", "verify", "block", "account", "upi", "bank"]
    matches = sum(1 for p in patterns if p in text.lower())
    return matches >= 2


# ================= CALLBACK =================

def send_callback(session: Session):
    payload = {
        "sessionId": session.session_id,
        "scamDetected": session.scam_detected,
        "totalMessagesExchanged": session.count(),
        "extractedIntelligence": {
            "bankAccounts": session.intelligence.bankAccounts,
            "upiIds": session.intelligence.upiIds,
            "phishingLinks": session.intelligence.phishingLinks,
            "phoneNumbers": session.intelligence.phoneNumbers,
            "suspiciousKeywords": session.intelligence.suspiciousKeywords
        },
        "agentNotes": "; ".join(session.notes) if session.notes else "Engagement completed"
    }

    try:
        r = requests.post(GUVI_CALLBACK_URL, json=payload, timeout=10)
        print("GUVI CALLBACK STATUS:", r.status_code)
        print("PAYLOAD:", payload)
        return r.status_code == 200
    except Exception as e:
        print("CALLBACK ERROR:", e)
        return False


# ================= ENDPOINT =================

@app.post("/api/honeypot")
async def honeypot(data: Optional[IncomingRequest] = None, x_api_key: str = Header(None)):

    if x_api_key != SECRET_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")

    if data is None:
        return {
            "status": "success",
            "scamDetected": False,
            "response": "Honeypot endpoint reachable and authenticated",
            "engagementMetrics": {
                "engagementDurationSeconds": 0,
                "totalMessagesExchanged": 0
            },
            "extractedIntelligence": {
                "bankAccounts": [],
                "upiIds": [],
                "phishingLinks": [],
                "phoneNumbers": [],
                "suspiciousKeywords": []
            },
            "agentNotes": "Endpoint validation successful"
        }
    session_id = data.sessionId

    if session_id not in sessions:
        sessions[session_id] = Session(session_id)

    session = sessions[session_id]
    session.messages.append(data.message)

    text = data.message.text
    session.extract(text)

    if not session.scam_detected:
        if detect_scam(text):
            session.scam_detected = True
            session.notes.append("Scam detected")

    ai_reply = "Please provide more details to verify your request."

    session.messages.append(
        Message(
            sender="user",
            text=ai_reply,
            timestamp=datetime.now().isoformat() + "Z"
        )
    )

    # End early for evaluation (after 6 messages)
    if session.count() >= 6 and not session.callback_sent:
        session.callback_sent = True
        session.notes.append("Engagement completed")
        send_callback(session)
        ai_reply = None

    return HoneypotResponse(
        status="success",
        scamDetected=session.scam_detected,
        response=ai_reply,
        engagementMetrics=EngagementMetrics(
            engagementDurationSeconds=session.duration(),
            totalMessagesExchanged=session.count()
        ),
        extractedIntelligence=session.intelligence,
        agentNotes="; ".join(session.notes) if session.notes else "Active"
    )

