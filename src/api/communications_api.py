"""
Live backend APIs for EDEN-BioGuard communications workflows.
"""

from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def generate_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10].upper()}"


def default_store_path() -> Path:
    configured = os.getenv("EDEN_COMMUNICATIONS_DB_PATH", "").strip()
    if configured:
        return Path(configured)
    return Path("data/communications/records.json")


RecipientGroup = Literal["public", "stakeholders", "regulators", "internal"]
MessageType = Literal["incident_alert", "stakeholder_notice", "status_update", "resolution"]
IncidentStatus = Literal["DETECTED", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_ALARM"]
Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


MESSAGE_DEFAULT_STATUS: dict[MessageType, IncidentStatus] = {
    "incident_alert": "DETECTED",
    "stakeholder_notice": "INVESTIGATING",
    "status_update": "INVESTIGATING",
    "resolution": "RESOLVED",
}


class SendCommunicationRequest(BaseModel):
    messageType: MessageType
    recipients: list[RecipientGroup] = Field(min_length=1)
    referenceCode: str = Field(min_length=3, max_length=64)
    subject: str = Field(min_length=1, max_length=180)
    body: str = Field(min_length=1, max_length=10000)
    status: IncidentStatus | None = None
    severity: Severity | None = None
    preparedBy: str = Field(default="EDEN Communications API", max_length=120)
    channel: str = Field(default="api", max_length=64)


class SendCommunicationResponse(BaseModel):
    messageId: str
    referenceCode: str
    status: IncidentStatus
    severity: Severity | None
    sentAt: str
    recipients: list[RecipientGroup]


class AcknowledgeRequest(BaseModel):
    recipientGroup: RecipientGroup
    acknowledgedBy: str = Field(min_length=1, max_length=120)
    channel: str = Field(default="api", max_length=64)
    note: str = Field(default="", max_length=500)


class AcknowledgeResponse(BaseModel):
    acknowledgementId: str
    referenceCode: str
    recipientGroup: RecipientGroup
    acknowledgedBy: str
    acknowledgedAt: str


class CommunicationStatusResponse(BaseModel):
    referenceCode: str
    currentStatus: IncidentStatus
    severity: Severity | None
    lastMessageAt: str
    totalMessages: int
    acknowledgementsReceived: int
    acknowledgedGroups: list[RecipientGroup]
    pendingAcknowledgementGroups: list[RecipientGroup]
    messages: list[dict]
    acknowledgements: list[dict]


class CommunicationsStore:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text(json.dumps({"threads": {}}, indent=2), encoding="utf-8")

    def _load(self) -> dict:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return {"threads": {}}

    def _save(self, payload: dict) -> None:
        self.path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")

    def send(self, req: SendCommunicationRequest) -> dict:
        with self._lock:
            payload = self._load()
            threads = payload.setdefault("threads", {})
            reference = req.referenceCode.strip().upper()
            now = utc_now_iso()
            message_id = generate_id("MSG")

            thread = threads.get(reference)
            if thread is None:
                thread = {
                    "referenceCode": reference,
                    "createdAt": now,
                    "currentStatus": req.status or MESSAGE_DEFAULT_STATUS[req.messageType],
                    "severity": req.severity,
                    "messages": [],
                    "acknowledgements": [],
                    "recipientGroups": [],
                    "lastMessageAt": now,
                }
                threads[reference] = thread

            if req.status is not None:
                thread["currentStatus"] = req.status
            elif req.messageType == "resolution":
                thread["currentStatus"] = "RESOLVED"

            if req.severity is not None:
                thread["severity"] = req.severity

            merged_recipients = sorted(set(thread.get("recipientGroups", []) + list(req.recipients)))
            thread["recipientGroups"] = merged_recipients

            message = {
                "messageId": message_id,
                "messageType": req.messageType,
                "subject": req.subject.strip(),
                "body": req.body.strip(),
                "status": thread["currentStatus"],
                "severity": thread.get("severity"),
                "recipients": req.recipients,
                "preparedBy": req.preparedBy,
                "channel": req.channel,
                "sentAt": now,
            }
            thread["messages"].append(message)
            thread["lastMessageAt"] = now
            self._save(payload)
            return message

    def get_status(self, reference_code: str) -> dict | None:
        with self._lock:
            payload = self._load()
            reference = reference_code.strip().upper()
            thread = payload.get("threads", {}).get(reference)
            if thread is None:
                return None

            acknowledged_groups = sorted({ack["recipientGroup"] for ack in thread.get("acknowledgements", [])})
            recipient_groups = sorted(set(thread.get("recipientGroups", [])))
            pending_groups = [group for group in recipient_groups if group not in acknowledged_groups]

            return {
                "referenceCode": reference,
                "currentStatus": thread.get("currentStatus", "INVESTIGATING"),
                "severity": thread.get("severity"),
                "lastMessageAt": thread.get("lastMessageAt", thread.get("createdAt", utc_now_iso())),
                "totalMessages": len(thread.get("messages", [])),
                "acknowledgementsReceived": len(thread.get("acknowledgements", [])),
                "acknowledgedGroups": acknowledged_groups,
                "pendingAcknowledgementGroups": pending_groups,
                "messages": thread.get("messages", []),
                "acknowledgements": thread.get("acknowledgements", []),
            }

    def acknowledge(self, reference_code: str, req: AcknowledgeRequest) -> dict | None:
        with self._lock:
            payload = self._load()
            threads = payload.get("threads", {})
            reference = reference_code.strip().upper()
            thread = threads.get(reference)
            if thread is None:
                return None

            now = utc_now_iso()
            acknowledgement = {
                "acknowledgementId": generate_id("ACK"),
                "recipientGroup": req.recipientGroup,
                "acknowledgedBy": req.acknowledgedBy.strip(),
                "channel": req.channel,
                "note": req.note.strip(),
                "acknowledgedAt": now,
            }

            existing = [
                ack
                for ack in thread.get("acknowledgements", [])
                if ack.get("recipientGroup") != req.recipientGroup
            ]
            existing.append(acknowledgement)
            thread["acknowledgements"] = existing
            self._save(payload)
            return acknowledgement


store = CommunicationsStore(default_store_path())
app = FastAPI(title="EDEN-BioGuard Communications API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "communications-api", "time": utc_now_iso()}


@app.post("/api/communications/send", response_model=SendCommunicationResponse)
def send_communication(req: SendCommunicationRequest) -> SendCommunicationResponse:
    message = store.send(req)
    return SendCommunicationResponse(
        messageId=message["messageId"],
        referenceCode=req.referenceCode.strip().upper(),
        status=message["status"],
        severity=message.get("severity"),
        sentAt=message["sentAt"],
        recipients=message["recipients"],
    )


@app.get("/api/communications/{referenceCode}/status", response_model=CommunicationStatusResponse)
def communication_status(referenceCode: str) -> CommunicationStatusResponse:
    status = store.get_status(referenceCode)
    if status is None:
        raise HTTPException(status_code=404, detail="Reference code not found")
    return CommunicationStatusResponse(**status)


@app.post(
    "/api/communications/{referenceCode}/acknowledgements",
    response_model=AcknowledgeResponse,
)
def acknowledge(referenceCode: str, req: AcknowledgeRequest) -> AcknowledgeResponse:
    acknowledgement = store.acknowledge(referenceCode, req)
    if acknowledgement is None:
        raise HTTPException(status_code=404, detail="Reference code not found")

    return AcknowledgeResponse(
        acknowledgementId=acknowledgement["acknowledgementId"],
        referenceCode=referenceCode.strip().upper(),
        recipientGroup=acknowledgement["recipientGroup"],
        acknowledgedBy=acknowledgement["acknowledgedBy"],
        acknowledgedAt=acknowledgement["acknowledgedAt"],
    )


if __name__ == "__main__":
    uvicorn.run(
        "src.api.communications_api:app",
        host=os.getenv("EDEN_COMMUNICATIONS_HOST", "0.0.0.0"),
        port=int(os.getenv("EDEN_COMMUNICATIONS_PORT", "8080")),
        reload=False,
    )

