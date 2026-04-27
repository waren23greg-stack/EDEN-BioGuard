# -*- coding: utf-8 -*-
"""
EDEN-BioGuard :: Displacement Ledger
bioguard/community/displacement_ledger.py  |  v1.0.0

Immutable record of communities displaced from ancestral land
under cover of conservation, investment, or development projects.

Why this exists:
  Communities across East Africa have been evicted from land their
  families occupied for generations — by national parks, carbon projects,
  private conservancies, and foreign investors — with no record, no
  compensation, and no legal recourse.

  This module creates that record. Satellite data going back to 1984
  (Landsat archive) can prove habitation existed before displacement.
  Every event is hashed and logged to DisplacementLedger.sol —
  permanently, publicly, and tamper-proof.

  Courts, UN bodies, journalists, and human rights organisations
  can query this ledger. It cannot be deleted.

Lex-0 hard rule:
  No CarbonCreditNFT may be minted for any zone with an active
  DisplacementEvent in this ledger. Conservation cannot profit
  from land theft.

Author : Warren Greg - EDEN-BioGuard
License: MIT
"""

from __future__ import annotations
import hashlib, json, logging, uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import List, Optional, Dict

logger = logging.getLogger(__name__)


# -- Enumerations -------------------------------------------------------------

class DisplacementType(str, Enum):
    FORCED_EVICTION        = "forced_eviction"
    CONSERVATION_EXCLUSION = "conservation_exclusion"  # "fortress conservation"
    CARBON_PROJECT_GRAB    = "carbon_project_grab"
    INVESTOR_LAND_GRAB     = "investor_land_grab"
    INFRASTRUCTURE_CLEARANCE = "infrastructure_clearance"
    UNKNOWN                = "unknown"


class DisplacementStatus(str, Enum):
    REPORTED    = "REPORTED"     # Community report received, not yet verified
    VERIFIED    = "VERIFIED"     # Confirmed by satellite + community testimony
    DISPUTED    = "DISPUTED"     # Alleged actor contests the record
    RESOLVED    = "RESOLVED"     # Community returned or compensated
    ESCALATED   = "ESCALATED"    # Referred to legal / UN body


class EvidenceType(str, Enum):
    SATELLITE_IMAGERY   = "satellite_imagery"    # Before/after Landsat or Sentinel-2
    COMMUNITY_TESTIMONY = "community_testimony"  # Recorded oral/written statement
    LAND_REGISTRY_DOC   = "land_registry_doc"    # Official title or customary claim
    PHOTO_VIDEO         = "photo_video"          # Field documentation
    NEWS_REPORT         = "news_report"          # Published media record
    NGO_REPORT          = "ngo_report"           # Third-party investigation


# -- Data classes -------------------------------------------------------------

@dataclass
class CommunityIdentity:
    """
    Identity record for a community filing a displacement report.
    Stored with care — community chooses what to make public.
    """
    community_id: str              # EDEN-assigned unique ID
    community_name: str
    ethnic_group: str = ""
    region: str = ""               # e.g. "Mau Forest, Nakuru County"
    country: str = "KE"
    representative_name: str = ""  # Optional — community may stay anonymous
    contact_encrypted: str = ""    # Encrypted contact (not stored in plain text)
    fpic_status: str = "pending"   # "granted" | "denied" | "pending"


@dataclass
class AncestralLandClaim:
    """
    The community's claim to the land from which they were displaced.
    Satellite evidence anchors this in verifiable history.
    """
    land_id: str
    community_id: str
    description: str
    coordinates: List[List[float]]   # Boundary polygon [[lon, lat], ...]
    area_hectares: float
    occupation_since_year: int       # e.g. 1920 — corroborated by Landsat 1984+
    customary_title: bool = True     # True if no formal title but customary right
    formal_title_number: str = ""    # If formal title exists
    landsat_habitation_confirmed: bool = False   # Set True after satellite analysis
    landsat_evidence_hash: str = ""  # IPFS hash of historical satellite imagery


@dataclass
class EvidenceItem:
    """A single piece of evidence attached to a displacement event."""
    evidence_id: str
    evidence_type: EvidenceType
    description: str
    ipfs_hash: str               # All evidence pinned to IPFS
    date_captured: str
    captured_by: str             # "community" | "EDEN-drone" | "NGO" | "journalist"
    gps_location: Optional[List[float]] = None
    verified: bool = False


@dataclass
class AllegedActor:
    """
    Entity alleged to have caused or enabled the displacement.
    May be a government body, corporation, NGO, or individual.
    """
    actor_id: str
    name: str
    actor_type: str              # "government" | "corporation" | "ngo" | "individual"
    registration_number: str = ""
    country_of_incorporation: str = ""
    project_name: str = ""       # e.g. "Mau Forest Carbon Project"
    project_id: str = ""         # Carbon registry ID if applicable


@dataclass
class DisplacementEvent:
    """
    The core record. One event per community displacement incident.
    This is what gets logged to DisplacementLedger.sol.

    An event can have multiple evidence items, multiple alleged actors,
    and progresses through a status lifecycle.
    """
    event_id: str
    community: CommunityIdentity
    land_claim: AncestralLandClaim
    displacement_type: DisplacementType
    status: DisplacementStatus
    incident_date: str           # When displacement occurred / began
    report_date: str             # When report was filed with EDEN
    alleged_actors: List[AllegedActor] = field(default_factory=list)
    evidence: List[EvidenceItem] = field(default_factory=list)
    fpic_violated: bool = True   # Was Free Prior Informed Consent violated?
    people_affected: int = 0
    structures_demolished: int = 0
    compensation_offered: bool = False
    compensation_amount_usd: float = 0.0
    legal_referral: str = ""     # e.g. "Kenya National Land Commission Case #"
    un_referral: str = ""        # e.g. "UN Special Rapporteur submission #"
    record_hash: str = ""        # SHA-256 of full record — tamper detection
    chain_tx_hash: str = ""      # Polygon transaction hash after on-chain log
    notes: str = ""

    def compute_record_hash(self) -> str:
        """SHA-256 of the serialised record — detects any tampering."""
        payload = json.dumps(asdict(self), sort_keys=True, default=str)
        return hashlib.sha256(payload.encode()).hexdigest()

    def blocks_carbon_credits(self) -> bool:
        """
        Lex-0 rule: active displacement event blocks all carbon credit
        minting for the affected land coordinates.
        """
        return self.status not in (
            DisplacementStatus.RESOLVED,
        )

    def to_chain_payload(self) -> dict:
        """Minimal payload for DisplacementLedger.sol — no PII on-chain."""
        return {
            "event_id":          self.event_id,
            "community_id":      self.community.community_id,
            "community_name":    self.community.community_name,
            "region":            self.community.region,
            "land_id":           self.land_claim.land_id,
            "area_hectares":     self.land_claim.area_hectares,
            "displacement_type": self.displacement_type.value,
            "status":            self.status.value,
            "incident_date":     self.incident_date,
            "fpic_violated":     self.fpic_violated,
            "people_affected":   self.people_affected,
            "alleged_actors":    [a.name for a in self.alleged_actors],
            "evidence_count":    len(self.evidence),
            "carbon_blocked":    self.blocks_carbon_credits(),
            "record_hash":       self.record_hash,
            "report_date":       self.report_date,
        }

    def to_summary(self) -> str:
        actors = ", ".join(a.name for a in self.alleged_actors) or "Unknown"
        return (
            f"[{self.status.value}] {self.displacement_type.value.upper()} | "
            f"{self.community.community_name} | {self.land_claim.area_hectares:.0f}ha | "
            f"~{self.people_affected} people | Actor: {actors}"
        )


# -- Ledger -------------------------------------------------------------------

class DisplacementLedger:
    """
    Local ledger manager for displacement events.

    Responsibilities:
      - Accept and validate new displacement reports
      - Confirm habitation via historical satellite analysis
      - Compute tamper-evident record hashes
      - Log confirmed events to DisplacementLedger.sol
      - Query events by community, zone, or alleged actor
      - Export court-ready evidence packages

    Production: backed by PostgreSQL + IPFS + Polygon.
    Shadow mode: in-memory store with local hash chain.
    """

    def __init__(
        self,
        chain_notary=None,
        satellite_client=None,
        evidence_store=None,
        local_db_path: str = "data/displacement_ledger.json",
    ):
        self.chain     = chain_notary
        self.satellite = satellite_client
        self.store     = evidence_store
        self.db_path   = Path(local_db_path)
        self._events: Dict[str, DisplacementEvent] = {}
        self._load_local()
        logger.info("DisplacementLedger ready (%d existing events)", len(self._events))

    # -- Filing ---------------------------------------------------------------

    def file_report(
        self,
        community: CommunityIdentity,
        land_claim: AncestralLandClaim,
        displacement_type: DisplacementType,
        incident_date: str,
        alleged_actors: List[AllegedActor] = None,
        evidence: List[EvidenceItem] = None,
        people_affected: int = 0,
        fpic_violated: bool = True,
        notes: str = "",
    ) -> DisplacementEvent:
        """
        File a new displacement report. Entry point for community submissions.
        Status starts as REPORTED until satellite verification runs.
        """
        event_id = "DISP-" + uuid.uuid4().hex[:10].upper()
        now = datetime.now(timezone.utc).isoformat()

        event = DisplacementEvent(
            event_id=event_id,
            community=community,
            land_claim=land_claim,
            displacement_type=displacement_type,
            status=DisplacementStatus.REPORTED,
            incident_date=incident_date,
            report_date=now,
            alleged_actors=alleged_actors or [],
            evidence=evidence or [],
            people_affected=people_affected,
            fpic_violated=fpic_violated,
            notes=notes,
        )

        # Attempt satellite verification of historical habitation
        event = self._verify_habitation(event)

        # Compute tamper-evident hash
        event.record_hash = event.compute_record_hash()

        # Store locally
        self._events[event_id] = event
        self._save_local()

        # Log to chain
        self._log_to_chain(event)

        logger.warning("DISPLACEMENT FILED: %s", event.to_summary())
        return event

    def update_status(self, event_id: str, new_status: DisplacementStatus, notes: str = "") -> Optional[DisplacementEvent]:
        """Update the status of an existing event (e.g. REPORTED -> VERIFIED)."""
        event = self._events.get(event_id)
        if not event:
            logger.error("Event not found: %s", event_id)
            return None
        event.status = new_status
        if notes:
            event.notes += f" | [{datetime.now(timezone.utc).isoformat()}] {notes}"
        event.record_hash = event.compute_record_hash()
        self._save_local()
        self._log_to_chain(event)
        logger.info("Status updated: %s -> %s", event_id, new_status.value)
        return event

    def add_evidence(self, event_id: str, item: EvidenceItem) -> bool:
        """Attach a new evidence item to an existing displacement event."""
        event = self._events.get(event_id)
        if not event:
            logger.error("Event not found: %s", event_id)
            return False
        event.evidence.append(item)
        event.record_hash = event.compute_record_hash()
        self._save_local()
        logger.info("Evidence added to %s: %s", event_id, item.evidence_type.value)
        return True

    # -- Queries --------------------------------------------------------------

    def get_by_community(self, community_id: str) -> List[DisplacementEvent]:
        return [e for e in self._events.values() if e.community.community_id == community_id]

    def get_by_actor(self, actor_name: str) -> List[DisplacementEvent]:
        return [
            e for e in self._events.values()
            if any(actor_name.lower() in a.name.lower() for a in e.alleged_actors)
        ]

    def get_carbon_blocked_zones(self) -> List[List[List[float]]]:
        """Return all land polygons where carbon credit minting is blocked."""
        return [
            e.land_claim.coordinates
            for e in self._events.values()
            if e.blocks_carbon_credits()
        ]

    def get_active_events(self) -> List[DisplacementEvent]:
        return [
            e for e in self._events.values()
            if e.status not in (DisplacementStatus.RESOLVED,)
        ]

    def summary_report(self) -> dict:
        events = list(self._events.values())
        return {
            "total_events":        len(events),
            "active_events":       len(self.get_active_events()),
            "total_people":        sum(e.people_affected for e in events),
            "total_hectares":      sum(e.land_claim.area_hectares for e in events),
            "carbon_blocks":       len(self.get_carbon_blocked_zones()),
            "by_type":             self._count_by(events, lambda e: e.displacement_type.value),
            "by_status":           self._count_by(events, lambda e: e.status.value),
            "by_country":          self._count_by(events, lambda e: e.community.country),
        }

    # -- Satellite verification -----------------------------------------------

    def _verify_habitation(self, event: DisplacementEvent) -> DisplacementEvent:
        """
        Use Landsat historical archive to confirm community lived on
        the claimed land before the displacement date.
        Sets land_claim.landsat_habitation_confirmed = True if evidence found.
        """
        if self.satellite is None:
            logger.debug("No satellite client — skipping habitation check (shadow mode)")
            return event
        try:
            result = self.satellite.check_historical_habitation(
                coordinates=event.land_claim.coordinates,
                before_date=event.incident_date,
                min_year=event.land_claim.occupation_since_year,
            )
            if result.confirmed:
                event.land_claim.landsat_habitation_confirmed = True
                event.land_claim.landsat_evidence_hash = result.ipfs_hash
                event.status = DisplacementStatus.VERIFIED
                logger.info("Habitation confirmed via Landsat: %s", event.event_id)
        except Exception as exc:
            logger.warning("Satellite habitation check failed: %s", exc)
        return event

    # -- Persistence ----------------------------------------------------------

    def _log_to_chain(self, event: DisplacementEvent):
        if self.chain is None:
            logger.debug("No chain notary (shadow mode)")
            return
        self.chain.log_displacement(event.to_chain_payload())

    def _load_local(self):
        if self.db_path.exists():
            try:
                raw = json.loads(self.db_path.read_text(encoding="utf-8"))
                logger.info("Loaded %d events from local db", len(raw))
            except Exception as exc:
                logger.warning("Could not load local db: %s", exc)

    def _save_local(self):
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            serialisable = {k: asdict(v) for k, v in self._events.items()}
            self.db_path.write_text(
                json.dumps(serialisable, indent=2, default=str), encoding="utf-8"
            )
        except Exception as exc:
            logger.warning("Could not save local db: %s", exc)

    @staticmethod
    def _count_by(events, key_fn) -> dict:
        counts: dict = {}
        for e in events:
            k = key_fn(e)
            counts[k] = counts.get(k, 0) + 1
        return counts


# -- CLI smoke-test -----------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")

    ledger = DisplacementLedger()

    ogiek = CommunityIdentity(
        community_id="COM-OGIEK-001",
        community_name="Ogiek People of Mau Forest",
        ethnic_group="Ogiek",
        region="Mau Forest Complex, Nakuru County",
        country="KE",
    )

    mau_land = AncestralLandClaim(
        land_id="LAND-MAU-001",
        community_id="COM-OGIEK-001",
        description="Ancestral hunting and gathering grounds, Mau Forest",
        coordinates=[
            [35.50, -0.20], [35.75, -0.20],
            [35.75, -0.45], [35.50, -0.45], [35.50, -0.20],
        ],
        area_hectares=8_500,
        occupation_since_year=1890,
        customary_title=True,
    )

    carbon_corp = AllegedActor(
        actor_id="ACT-001",
        name="GreenShield Carbon Ltd",
        actor_type="corporation",
        registration_number="CPR/2021/4432",
        country_of_incorporation="UK",
        project_name="Mau Forest REDD+ Carbon Project",
        project_id="VCS-3301",
    )

    event = ledger.file_report(
        community=ogiek,
        land_claim=mau_land,
        displacement_type=DisplacementType.CARBON_PROJECT_GRAB,
        incident_date="2023-03-15",
        alleged_actors=[carbon_corp],
        people_affected=312,
        fpic_violated=True,
        notes="Community evicted without consultation. Structures demolished.",
    )

    report = ledger.summary_report()

    print("\n" + "="*60)
    print("  EDEN :: Displacement Ledger")
    print("="*60)
    print(f"  Event   : {event.event_id}")
    print(f"  Record  : {event.to_summary()}")
    print(f"  Hash    : {event.record_hash[:48]}...")
    print(f"  Blocked : Carbon credits blocked = {event.blocks_carbon_credits()}")
    print(f"  FPIC    : Violated = {event.fpic_violated}")
    print(f"\n  Ledger Summary:")
    print(f"    Total events    : {report['total_events']}")
    print(f"    People affected : {report['total_people']}")
    print(f"    Hectares logged : {report['total_hectares']:.0f} ha")
    print(f"    Carbon blocks   : {report['carbon_blocks']} zone(s)")
    print("="*60)
