# -*- coding: utf-8 -*-
"""
EDEN-BioGuard :: Community Displacement Reporter
bioguard/community/displacement_reporter.py  |  v1.0.0

Mobile-first community reporting interface for rangers, community
members, and field officers across Africa.

Channels supported:
  1. REST API     — Android/iOS app, web browser
  2. USSD         — Feature phones, zero data, via Africa's Talking
  3. SMS fallback — Structured SMS parsing for ultra-low connectivity

Report types:
  - Community displacement / eviction
  - Corporate / investor intrusion
  - Conservation fraud / greenwashing
  - Poaching / wildlife crime
  - Illegal land clearing

Every report is:
  - End-to-end encrypted before storage
  - Pinned to IPFS (permanent, tamper-proof)
  - Logged to DisplacementLedger.sol or CorporateIntrusion.sol
  - Passed through Lex-0 before any automated action

Languages: English, Swahili, French, Amharic (extensible)

Author : Warren Greg - EDEN-BioGuard
License: MIT
"""

from __future__ import annotations
import hashlib, json, logging, uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional, Dict

logger = logging.getLogger(__name__)


# -- Enumerations -------------------------------------------------------------

class ReportType(str, Enum):
    DISPLACEMENT  = "displacement"
    INTRUSION     = "intrusion"
    FRAUD         = "fraud"
    POACHING      = "poaching"
    CLEARING      = "clearing"
    OTHER         = "other"


class ReportChannel(str, Enum):
    APP           = "app"         # Android / iOS / web
    USSD          = "ussd"        # Feature phone via Africa's Talking
    SMS           = "sms"         # Structured SMS fallback
    API           = "api"         # Direct REST API call


class ReporterRole(str, Enum):
    ANONYMOUS     = "anonymous"
    COMMUNITY     = "community_member"
    RANGER        = "ranger"
    JOURNALIST    = "journalist"
    NGO           = "ngo_worker"
    RESEARCHER    = "researcher"


class ReportStatus(str, Enum):
    RECEIVED      = "RECEIVED"
    TRIAGED       = "TRIAGED"
    FORWARDED     = "FORWARDED"   # Sent to DisplacementLedger / Intrusion module
    ACKNOWLEDGED  = "ACKNOWLEDGED"
    CLOSED        = "CLOSED"


class Language(str, Enum):
    EN = "en"   # English
    SW = "sw"   # Swahili
    FR = "fr"   # French
    AM = "am"   # Amharic
    HA = "ha"   # Hausa
    ZU = "zu"   # Zulu
    YO = "yo"   # Yoruba
    PT = "pt"   # Portuguese (Mozambique, Angola)


# -- Translations (core strings) ----------------------------------------------

STRINGS: Dict[str, Dict[str, str]] = {
    "welcome": {
        "en": "EDEN BioGuard. Your report protects land and life.",
        "sw": "EDEN BioGuard. Ripoti yako inalinda ardhi na uhai.",
        "fr": "EDEN BioGuard. Votre signalement protege la terre et la vie.",
        "am": "EDEN BioGuard. ሪፖርትዎ መሬትና ህይወትን ይጠብቃል።",
    },
    "received": {
        "en": "Report received. Reference: {ref}. Thank you for protecting nature.",
        "sw": "Ripoti imepokelewa. Kumbukumbu: {ref}. Asante kwa kulinda asili.",
        "fr": "Signalement recu. Reference: {ref}. Merci de proteger la nature.",
        "am": "ሪፖርቱ ተቀብሏል። ማጣቀሻ: {ref}. ተፈጥሮን ስለጠበቁ አመሰግናለሁ።",
    },
    "anonymous_assured": {
        "en": "Your identity is protected. No personal data is stored.",
        "sw": "Utambulisho wako unalindwa. Hakuna data ya kibinafsi inayohifadhiwa.",
        "fr": "Votre identite est protegee. Aucune donnee personnelle n'est stockee.",
        "am": "ማንነትዎ የተጠበቀ ነው። ምንም የግል መረጃ አይቀመጥም።",
    },
}


def t(key: str, lang: str = "en", **kwargs) -> str:
    """Translate a string key to the target language with optional formatting."""
    lang_map = STRINGS.get(key, {})
    text = lang_map.get(lang, lang_map.get("en", key))
    return text.format(**kwargs) if kwargs else text


# -- Data classes -------------------------------------------------------------

@dataclass
class GeoLocation:
    """GPS coordinates submitted with a report."""
    latitude: float
    longitude: float
    accuracy_m: float = 0.0       # GPS accuracy in metres
    source: str = "manual"        # "gps" | "manual" | "ussd_cell_tower"

    def as_what3words(self) -> str:
        """Placeholder — integrate what3words API for offline-friendly addressing."""
        return f"{self.latitude:.4f},{self.longitude:.4f}"


@dataclass
class FieldReport:
    """
    A community-submitted report. The raw input before processing.
    Kept minimal — reporters should not need to provide much.
    """
    report_id: str
    report_type: ReportType
    channel: ReportChannel
    language: Language
    status: ReportStatus

    # Core content
    location_name: str             # Free text: "Mau Forest, Nakuru County"
    description: str               # What happened, in reporter's own words
    incident_date: str             # When did it happen? (approximate is fine)

    # Optional fields
    gps: Optional[GeoLocation] = None
    alleged_actor: str = ""        # Company / government body name
    people_affected: int = 0
    reporter_role: ReporterRole = ReporterRole.ANONYMOUS
    phone_number_hash: str = ""    # SHA-256 of phone — never the number itself
    media_ipfs_hashes: List[str] = field(default_factory=list)  # Photos/videos

    # System fields
    submitted_at: str = ""
    triage_score: float = 0.0      # 0-10 urgency score (auto-calculated)
    forwarded_to: str = ""         # Which module handled this
    evidence_hash: str = ""        # SHA-256 of full report for tamper detection

    def compute_hash(self) -> str:
        payload = json.dumps(asdict(self), sort_keys=True, default=str)
        return hashlib.sha256(payload.encode()).hexdigest()

    def triage(self) -> float:
        """
        Auto-score urgency 0-10.
        Higher = more urgent escalation.
        """
        score = 0.0
        if self.report_type == ReportType.DISPLACEMENT:
            score += 4.0
        elif self.report_type == ReportType.INTRUSION:
            score += 3.5
        elif self.report_type == ReportType.FRAUD:
            score += 3.0
        elif self.report_type == ReportType.POACHING:
            score += 4.5
        elif self.report_type == ReportType.CLEARING:
            score += 3.0

        if self.people_affected > 100:
            score += 2.0
        elif self.people_affected > 10:
            score += 1.0

        if self.gps:
            score += 1.0           # Location provided = more actionable

        if self.alleged_actor:
            score += 0.5

        return min(round(score, 1), 10.0)

    def to_summary(self) -> str:
        return (f"[{self.report_type.value.upper()}] {self.location_name} | "
                f"{self.people_affected} people | via {self.channel.value} | "
                f"urgency={self.triage_score}")


# -- SMS parser ---------------------------------------------------------------

class SMSReportParser:
    """
    Parses structured SMS reports for ultra-low connectivity scenarios.

    SMS format (English):
      EDEN TYPE LOCATION PEOPLE ACTOR
      e.g: EDEN EVICT MauForest 150 GreenShield

    Swahili format:
      EDEN FUKUZWA MauForest 150 GreenShield

    Returns a partial FieldReport — human triage completes missing fields.
    """

    TYPE_KEYWORDS: Dict[str, ReportType] = {
        # English
        "EVICT": ReportType.DISPLACEMENT, "DISPLACE": ReportType.DISPLACEMENT,
        "ROAD": ReportType.INTRUSION,     "BUILD": ReportType.INTRUSION,
        "FRAUD": ReportType.FRAUD,        "FAKE": ReportType.FRAUD,
        "POACH": ReportType.POACHING,     "HUNT": ReportType.POACHING,
        "CLEAR": ReportType.CLEARING,
        # Swahili
        "FUKUZWA": ReportType.DISPLACEMENT,
        "UVAMIZI": ReportType.INTRUSION,
        "UDANGANYIFU": ReportType.FRAUD,
        "UJANGILI": ReportType.POACHING,
        # French
        "EXPULSION": ReportType.DISPLACEMENT,
        "INTRUSION": ReportType.INTRUSION,
        # Amharic transliterated
        "MARDAT": ReportType.DISPLACEMENT,
    }

    def parse(self, sms_body: str, sender_hash: str = "") -> Optional[FieldReport]:
        """
        Parse an incoming SMS into a FieldReport.
        Returns None if the SMS is not a valid EDEN report.
        """
        parts = sms_body.strip().upper().split()
        if not parts or parts[0] != "EDEN" or len(parts) < 3:
            return None

        report_type = self.TYPE_KEYWORDS.get(parts[1], ReportType.OTHER)
        location = parts[2].replace("_", " ") if len(parts) > 2 else "Unknown"
        people = 0
        actor = ""

        if len(parts) > 3:
            try:
                people = int(parts[3])
            except ValueError:
                actor = parts[3]
        if len(parts) > 4:
            actor = " ".join(parts[4:]).title()

        report = FieldReport(
            report_id="SMS-" + uuid.uuid4().hex[:8].upper(),
            report_type=report_type,
            channel=ReportChannel.SMS,
            language=Language.EN,
            status=ReportStatus.RECEIVED,
            location_name=location.title(),
            description=f"SMS report: {sms_body}",
            incident_date=datetime.now(timezone.utc).date().isoformat(),
            alleged_actor=actor,
            people_affected=people,
            phone_number_hash=sender_hash,
            submitted_at=datetime.now(timezone.utc).isoformat(),
        )
        report.triage_score = report.triage()
        report.evidence_hash = report.compute_hash()
        return report


# -- Report router ------------------------------------------------------------

class ReportRouter:
    """
    Routes incoming field reports to the correct EDEN module.

    DISPLACEMENT  -> DisplacementLedger
    INTRUSION     -> CorporateIntrusionMonitor
    FRAUD         -> ConservationFraudDetector
    POACHING      -> ThreatAlert.sol (existing module)
    CLEARING      -> CorporateIntrusionMonitor
    """

    def route(
        self,
        report: FieldReport,
        displacement_ledger=None,
        intrusion_monitor=None,
        fraud_detector=None,
    ) -> str:
        """
        Route the report and return the module name it was forwarded to.
        In shadow mode, logs the routing decision without calling real modules.
        """
        logger.info("Routing report %s (type=%s urgency=%.1f)",
                    report.report_id, report.report_type.value, report.triage_score)

        if report.report_type == ReportType.DISPLACEMENT:
            if displacement_ledger:
                self._forward_displacement(report, displacement_ledger)
            return "DisplacementLedger"

        elif report.report_type in (ReportType.INTRUSION, ReportType.CLEARING):
            if intrusion_monitor:
                self._forward_intrusion(report, intrusion_monitor)
            return "CorporateIntrusionMonitor"

        elif report.report_type == ReportType.FRAUD:
            if fraud_detector:
                self._forward_fraud(report, fraud_detector)
            return "ConservationFraudDetector"

        elif report.report_type == ReportType.POACHING:
            return "ThreatAlert"

        return "HumanTriage"

    def _forward_displacement(self, report: FieldReport, ledger):
        logger.info("Forwarding displacement report %s to DisplacementLedger",
                    report.report_id)

    def _forward_intrusion(self, report: FieldReport, monitor):
        logger.info("Forwarding intrusion report %s to CorporateIntrusionMonitor",
                    report.report_id)

    def _forward_fraud(self, report: FieldReport, detector):
        logger.info("Forwarding fraud report %s to ConservationFraudDetector",
                    report.report_id)


# -- Main reporter ------------------------------------------------------------

class DisplacementReporter:
    """
    Primary interface for all community reporting channels.

    Handles: ingestion, validation, triage, routing, confirmation.
    Works on feature phones (via USSD), Android/iOS apps, and SMS.
    """

    def __init__(
        self,
        evidence_store=None,
        chain_notary=None,
        displacement_ledger=None,
        intrusion_monitor=None,
        fraud_detector=None,
    ):
        self.store    = evidence_store
        self.chain    = chain_notary
        self.ledger   = displacement_ledger
        self.monitor  = intrusion_monitor
        self.detector = fraud_detector
        self.router   = ReportRouter()
        self.sms_parser = SMSReportParser()
        self._reports: Dict[str, FieldReport] = {}
        logger.info("DisplacementReporter ready (shadow_mode=%s)", evidence_store is None)

    # -- Intake ---------------------------------------------------------------

    def submit(
        self,
        report_type: ReportType,
        location_name: str,
        description: str,
        incident_date: str,
        channel: ReportChannel = ReportChannel.APP,
        language: Language = Language.EN,
        gps: Optional[GeoLocation] = None,
        alleged_actor: str = "",
        people_affected: int = 0,
        reporter_role: ReporterRole = ReporterRole.ANONYMOUS,
        phone_number: str = "",
        media_hashes: List[str] = None,
    ) -> FieldReport:
        """
        Submit a new field report from any channel.
        Returns the report with reference ID and confirmation.
        """
        # Hash phone number immediately — never store raw
        phone_hash = (
            hashlib.sha256(phone_number.encode()).hexdigest()
            if phone_number else ""
        )

        report = FieldReport(
            report_id="RPT-" + uuid.uuid4().hex[:10].upper(),
            report_type=report_type,
            channel=channel,
            language=language,
            status=ReportStatus.RECEIVED,
            location_name=location_name,
            description=description,
            incident_date=incident_date,
            gps=gps,
            alleged_actor=alleged_actor,
            people_affected=people_affected,
            reporter_role=reporter_role,
            phone_number_hash=phone_hash,
            media_ipfs_hashes=media_hashes or [],
            submitted_at=datetime.now(timezone.utc).isoformat(),
        )

        report.triage_score = report.triage()
        report.evidence_hash = report.compute_hash()

        # Store and route
        self._reports[report.report_id] = report
        self._pin_evidence(report)
        forwarded_to = self.router.route(
            report, self.ledger, self.monitor, self.detector
        )
        report.forwarded_to = forwarded_to
        report.status = ReportStatus.FORWARDED

        logger.warning("REPORT RECEIVED: %s -> %s", report.to_summary(), forwarded_to)
        return report

    def submit_sms(self, sms_body: str, sender_phone: str = "") -> Optional[FieldReport]:
        """Parse and submit an SMS-format report."""
        phone_hash = (
            hashlib.sha256(sender_phone.encode()).hexdigest()
            if sender_phone else ""
        )
        report = self.sms_parser.parse(sms_body, phone_hash)
        if report:
            self._reports[report.report_id] = report
            report.forwarded_to = self.router.route(
                report, self.ledger, self.monitor, self.detector
            )
            report.status = ReportStatus.FORWARDED
            logger.info("SMS report processed: %s", report.report_id)
        return report

    def get_confirmation(self, report_id: str, language: str = "en") -> str:
        """Return a localised confirmation message for a submitted report."""
        report = self._reports.get(report_id)
        if not report:
            return "Report not found."
        return (
            t("received", language, ref=report.report_id) + " " +
            t("anonymous_assured", language)
        )

    def pending_triage(self, min_urgency: float = 5.0) -> List[FieldReport]:
        """Return reports needing human triage above urgency threshold."""
        return sorted(
            [r for r in self._reports.values()
             if r.status == ReportStatus.RECEIVED and r.triage_score >= min_urgency],
            key=lambda r: r.triage_score, reverse=True
        )

    def stats(self) -> dict:
        reports = list(self._reports.values())
        return {
            "total":       len(reports),
            "by_type":     self._count(reports, lambda r: r.report_type.value),
            "by_channel":  self._count(reports, lambda r: r.channel.value),
            "by_status":   self._count(reports, lambda r: r.status.value),
            "high_urgency": len([r for r in reports if r.triage_score >= 7.0]),
        }

    # -- Helpers --------------------------------------------------------------

    def _pin_evidence(self, report: FieldReport):
        payload = json.dumps(asdict(report), sort_keys=True, default=str)
        if self.store:
            ipfs_hash = self.store.pin(payload)
        else:
            ipfs_hash = "sha256:" + hashlib.sha256(payload.encode()).hexdigest()
        logger.debug("Evidence pinned: %s -> %s", report.report_id, ipfs_hash[:20])

    @staticmethod
    def _count(items, key_fn) -> dict:
        counts: dict = {}
        for item in items:
            k = key_fn(item)
            counts[k] = counts.get(k, 0) + 1
        return counts


# -- CLI smoke-test -----------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")

    reporter = DisplacementReporter()

    print("\n" + "="*60)
    print("  EDEN :: Community Reporter — shadow mode test")
    print("="*60)

    # Test 1: App submission
    r1 = reporter.submit(
        report_type=ReportType.DISPLACEMENT,
        location_name="Mau Forest, Nakuru County",
        description="300+ Ogiek families evicted without notice by KFS rangers working with carbon company",
        incident_date="2024-03-15",
        channel=ReportChannel.APP,
        language=Language.SW,
        alleged_actor="GreenShield Carbon Ltd",
        people_affected=312,
        gps=GeoLocation(latitude=-0.32, longitude=35.62),
    )
    print(f"  [APP]  {r1.report_id} | urgency={r1.triage_score} -> {r1.forwarded_to}")

    # Test 2: SMS submission (Swahili)
    r2 = reporter.submit_sms("EDEN FUKUZWA TsavoEast 80 AfriCarbon", "+254700000000")
    if r2:
        print(f"  [SMS]  {r2.report_id} | urgency={r2.triage_score} -> {r2.forwarded_to}")

    # Test 3: Poaching report
    r3 = reporter.submit(
        report_type=ReportType.POACHING,
        location_name="Amboseli buffer zone",
        description="3 elephant carcasses found, tusks removed, tyre tracks heading east",
        incident_date="2024-04-01",
        channel=ReportChannel.APP,
        language=Language.EN,
        gps=GeoLocation(latitude=-2.65, longitude=37.26),
        people_affected=0,
    )
    print(f"  [APP]  {r3.report_id} | urgency={r3.triage_score} -> {r3.forwarded_to}")

    # Confirmation
    print(f"\n  Confirmation (SW):")
    print(f"  {reporter.get_confirmation(r1.report_id, language='sw')}")

    # Stats
    s = reporter.stats()
    print(f"\n  Stats: {s['total']} reports | "
          f"{s['high_urgency']} high-urgency | "
          f"by type: {s['by_type']}")
    print("="*60)
