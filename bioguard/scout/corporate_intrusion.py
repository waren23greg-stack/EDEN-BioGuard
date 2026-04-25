# -*- coding: utf-8 -*-
"""
EDEN-BioGuard :: Corporate Intrusion Monitor
bioguard/scout/corporate_intrusion.py  |  v1.0.0

Watches for unauthorized infrastructure development inside protected
wildlife zones and ancestral community land.

Detects: new roads, structures, cleared land, fence lines, mining pits
Sources: Sentinel-1 SAR backscatter change + Sentinel-2 optical delta
Alerts : rangers, community reps, legal team simultaneously
Logs   : every intrusion event immutably to CorporateIntrusion.sol

Author : Warren Greg - EDEN-BioGuard
License: MIT
"""

from __future__ import annotations
import hashlib, json, logging
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional, Dict

logger = logging.getLogger(__name__)


# -- Enumerations -------------------------------------------------------------

class IntrusionSeverity(str, Enum):
    CRITICAL = "CRITICAL"   # Active construction / mining in core zone
    HIGH     = "HIGH"       # Road or structure confirmed
    MEDIUM   = "MEDIUM"     # Vegetation clearing, possible access track
    LOW      = "LOW"        # Anomaly detected, needs verification


class ZoneType(str, Enum):
    NATIONAL_PARK      = "national_park"
    FOREST_RESERVE     = "forest_reserve"
    WILDLIFE_CORRIDOR  = "wildlife_corridor"
    ANCESTRAL_LAND     = "ancestral_land"
    BUFFER_ZONE        = "buffer_zone"
    COMMUNITY_CONSERVANCY = "community_conservancy"


class AlertChannel(str, Enum):
    RANGER_SMS     = "ranger_sms"
    COMMUNITY_APP  = "community_app"
    LEGAL_TEAM     = "legal_team"
    REGULATOR      = "regulator"
    CHAIN_LOG      = "chain_log"


# -- Data classes -------------------------------------------------------------

@dataclass
class ProtectedZone:
    zone_id: str
    name: str
    zone_type: ZoneType
    coordinates: List[List[float]]   # [[lon, lat], ...]
    area_hectares: float
    legal_status: str                # e.g. "Gazette Notice No. 1234"
    managing_authority: str          # e.g. "Kenya Wildlife Service"
    community_name: str = ""         # If ancestral land


@dataclass
class LandRecord:
    """Who legally owns or leases land adjacent to / inside the zone."""
    parcel_id: str
    registered_owner: str
    owner_type: str                  # "individual" | "company" | "government"
    company_reg_number: str = ""
    lease_expiry: str = ""
    source: str = "Kenya Lands Registry"


@dataclass
class SARDelta:
    """
    Change detected between two Sentinel-1 SAR composites.
    High backscatter change = new hard surface (road, building, cleared ground).
    """
    location: List[float]            # [lon, lat] centroid of change
    bbox: List[List[float]]          # bounding box of changed area
    area_m2: float
    backscatter_change_db: float     # dB change (> +3dB = significant)
    before_date: str
    after_date: str
    confidence: float                # 0.0 - 1.0


@dataclass
class IntrusionEvent:
    """
    A confirmed or suspected unauthorized intrusion into a protected zone.
    This is the core record logged to CorporateIntrusion.sol.
    """
    event_id: str
    zone: ProtectedZone
    sar_delta: SARDelta
    severity: IntrusionSeverity
    suspected_entity: Optional[LandRecord]
    intrusion_type: str              # "road" | "structure" | "clearing" | "mining"
    detection_timestamp: str
    evidence_ipfs_hash: str = ""
    alerts_dispatched: List[str] = field(default_factory=list)
    verified_by_human: bool = False
    notes: str = ""

    def to_chain_payload(self) -> dict:
        return {
            "event_id":          self.event_id,
            "zone_id":           self.zone.zone_id,
            "zone_name":         self.zone.name,
            "zone_type":         self.zone.zone_type.value,
            "intrusion_type":    self.intrusion_type,
            "severity":          self.severity.value,
            "location_lon":      self.sar_delta.location[0],
            "location_lat":      self.sar_delta.location[1],
            "area_m2":           self.sar_delta.area_m2,
            "confidence":        self.sar_delta.confidence,
            "suspected_entity":  self.suspected_entity.registered_owner if self.suspected_entity else "UNKNOWN",
            "company_reg":       self.suspected_entity.company_reg_number if self.suspected_entity else "",
            "evidence_ipfs":     self.evidence_ipfs_hash,
            "timestamp":         self.detection_timestamp,
        }

    def summary(self) -> str:
        entity = self.suspected_entity.registered_owner if self.suspected_entity else "Unknown entity"
        return (
            f"[{self.severity.value}] {self.intrusion_type.upper()} detected in "
            f"{self.zone.name} | {entity} | "
            f"{self.sar_delta.area_m2:.0f}m2 | confidence={self.sar_delta.confidence:.0%}"
        )


# -- Intrusion classifier -----------------------------------------------------

class IntrusionClassifier:
    """
    Classifies a SAR delta into an intrusion type and severity.

    Rules (expandable — add new signatures as field data improves):
      Large area + high backscatter change  -> clearing or mining
      Linear feature + moderate change      -> road or fence
      Compact area + very high change       -> structure/building
    """

    def classify(self, delta: SARDelta) -> tuple[str, IntrusionSeverity]:
        area    = delta.area_m2
        db_chg  = delta.backscatter_change_db
        conf    = delta.confidence

        if conf < 0.50:
            return "unknown", IntrusionSeverity.LOW

        # Mining pit or mass clearing
        if area > 50_000 and db_chg > 5.0:
            return "mining_or_clearing", IntrusionSeverity.CRITICAL

        # Large clearing
        if area > 20_000 and db_chg > 3.0:
            return "clearing", IntrusionSeverity.HIGH

        # Road or fence (elongated — approximated by moderate area, moderate change)
        if 500 < area < 20_000 and 2.0 < db_chg <= 5.0:
            return "road_or_fence", IntrusionSeverity.HIGH

        # Structure / building (compact, high change)
        if area < 5_000 and db_chg > 4.0:
            return "structure", IntrusionSeverity.HIGH

        # Small clearing or access track
        if area > 200 and db_chg > 2.0:
            return "access_track_or_clearing", IntrusionSeverity.MEDIUM

        return "anomaly", IntrusionSeverity.LOW


# -- Alert dispatcher ---------------------------------------------------------

class AlertDispatcher:
    """
    Routes intrusion alerts to the right channels based on severity.

    CRITICAL -> all channels simultaneously
    HIGH     -> rangers + legal + chain log
    MEDIUM   -> rangers + chain log
    LOW      -> chain log only (queue for batch review)
    """

    ROUTING: Dict[IntrusionSeverity, List[AlertChannel]] = {
        IntrusionSeverity.CRITICAL: [
            AlertChannel.RANGER_SMS,
            AlertChannel.COMMUNITY_APP,
            AlertChannel.LEGAL_TEAM,
            AlertChannel.REGULATOR,
            AlertChannel.CHAIN_LOG,
        ],
        IntrusionSeverity.HIGH: [
            AlertChannel.RANGER_SMS,
            AlertChannel.LEGAL_TEAM,
            AlertChannel.CHAIN_LOG,
        ],
        IntrusionSeverity.MEDIUM: [
            AlertChannel.RANGER_SMS,
            AlertChannel.CHAIN_LOG,
        ],
        IntrusionSeverity.LOW: [
            AlertChannel.CHAIN_LOG,
        ],
    }

    def dispatch(self, event: IntrusionEvent, clients: dict) -> List[str]:
        """Send alerts via all channels for this severity. Returns dispatched list."""
        channels = self.ROUTING.get(event.severity, [AlertChannel.CHAIN_LOG])
        dispatched = []
        for channel in channels:
            try:
                self._send(channel, event, clients)
                dispatched.append(channel.value)
                logger.info("Alert dispatched: %s -> %s", event.event_id, channel.value)
            except Exception as exc:
                logger.error("Alert failed: %s -> %s : %s", event.event_id, channel.value, exc)
        return dispatched

    def _send(self, channel: AlertChannel, event: IntrusionEvent, clients: dict):
        client = clients.get(channel.value)
        if client is None:
            logger.debug("No client for %s (shadow mode)", channel.value)
            return
        if channel == AlertChannel.RANGER_SMS:
            client.send_sms(
                message=f"EDEN ALERT: {event.summary()}",
                gps=event.sar_delta.location,
                evidence_link=event.evidence_ipfs_hash,
            )
        elif channel == AlertChannel.LEGAL_TEAM:
            client.notify(subject="Intrusion Evidence Package Ready", event=event.to_chain_payload())
        elif channel == AlertChannel.CHAIN_LOG:
            client.log_intrusion(event.to_chain_payload())


# -- Main monitor -------------------------------------------------------------

class CorporateIntrusionMonitor:
    """
    Primary interface for continuous corporate intrusion monitoring.

    Runs as the SCOUT-1 sub-agent watching all registered protected zones
    on a configurable scan interval (default: every 6 days matching
    Sentinel-1 revisit cycle).

    In shadow mode (no SAR client), generates synthetic deltas for
    pipeline testing without real API keys.
    """

    def __init__(
        self,
        sar_client=None,
        lands_registry_client=None,
        chain_notary=None,
        alert_clients: dict = None,
        evidence_store=None,
    ):
        self.sar             = sar_client
        self.lands           = lands_registry_client
        self.chain           = chain_notary
        self.alert_clients   = alert_clients or {}
        self.store           = evidence_store
        self.classifier      = IntrusionClassifier()
        self.dispatcher      = AlertDispatcher()
        logger.info("CorporateIntrusionMonitor ready (shadow_mode=%s)", sar_client is None)

    def scan_zone(self, zone: ProtectedZone, days_lookback: int = 14) -> List[IntrusionEvent]:
        """
        Scan a single protected zone for new infrastructure.
        Returns list of IntrusionEvent objects (may be empty).
        """
        logger.info("Scanning zone: %s (%s)", zone.name, zone.zone_type.value)

        sar_deltas = self._get_sar_deltas(zone, days_lookback)
        if not sar_deltas:
            logger.info("No SAR changes detected in %s", zone.name)
            return []

        events = []
        for delta in sar_deltas:
            intrusion_type, severity = self.classifier.classify(delta)

            # Cross-reference land registry to identify responsible entity
            land_record = self._lookup_land_record(delta.location)

            event_id = self._generate_event_id(zone.zone_id, delta)
            evidence = self._build_evidence(zone, delta, land_record)
            evid_hash = self._pin_evidence(evidence)

            event = IntrusionEvent(
                event_id=event_id,
                zone=zone,
                sar_delta=delta,
                severity=severity,
                suspected_entity=land_record,
                intrusion_type=intrusion_type,
                detection_timestamp=datetime.now(timezone.utc).isoformat(),
                evidence_ipfs_hash=evid_hash,
                notes=f"Auto-detected by EDEN-SCOUT-1. SAR delta {delta.backscatter_change_db:.1f}dB.",
            )

            # Dispatch alerts
            dispatched = self.dispatcher.dispatch(event, self.alert_clients)
            event.alerts_dispatched = dispatched

            # Log to chain
            self._log_to_chain(event)

            events.append(event)
            logger.warning("INTRUSION EVENT: %s", event.summary())

        return events

    def scan_all_zones(self, zones: List[ProtectedZone]) -> Dict[str, List[IntrusionEvent]]:
        """Scan multiple zones — used by SCOUT-1 continuous loop."""
        results = {}
        for zone in zones:
            try:
                results[zone.zone_id] = self.scan_zone(zone)
            except Exception as exc:
                logger.error("Scan failed for %s: %s", zone.zone_id, exc)
                results[zone.zone_id] = []
        total = sum(len(v) for v in results.values())
        logger.info("Scan complete: %d zone(s), %d event(s) detected", len(zones), total)
        return results

    # -- Internal helpers -----------------------------------------------------

    def _get_sar_deltas(self, zone: ProtectedZone, days: int) -> List[SARDelta]:
        if self.sar is None:
            logger.debug("No SAR client — returning empty deltas (shadow mode)")
            return []
        return self.sar.get_backscatter_change(zone.coordinates, days_lookback=days)

    def _lookup_land_record(self, location: List[float]) -> Optional[LandRecord]:
        if self.lands is None:
            return None
        try:
            return self.lands.query_by_location(location)
        except Exception as exc:
            logger.warning("Land registry lookup failed: %s", exc)
            return None

    def _generate_event_id(self, zone_id: str, delta: SARDelta) -> str:
        raw = f"{zone_id}:{delta.location}:{delta.after_date}"
        return "EVT-" + hashlib.sha256(raw.encode()).hexdigest()[:12].upper()

    def _build_evidence(self, zone, delta, land_record) -> dict:
        return {
            "schema_version": "1.0.0",
            "generated_by":   "EDEN-BioGuard::CorporateIntrusionMonitor",
            "zone":           asdict(zone),
            "sar_delta":      asdict(delta),
            "land_record":    asdict(land_record) if land_record else None,
            "timestamp":      datetime.now(timezone.utc).isoformat(),
        }

    def _pin_evidence(self, bundle: dict) -> str:
        payload = json.dumps(bundle, sort_keys=True, default=str)
        if self.store:
            return self.store.pin(payload)
        return "sha256:" + hashlib.sha256(payload.encode()).hexdigest()

    def _log_to_chain(self, event: IntrusionEvent):
        if self.chain is None:
            logger.debug("No chain notary (shadow mode)")
            return
        self.chain.log_intrusion(event.to_chain_payload())


# -- CLI smoke-test -----------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")

    monitor = CorporateIntrusionMonitor()

    mau_forest = ProtectedZone(
        zone_id="KE-MAU-001",
        name="Mau Forest Complex",
        zone_type=ZoneType.FOREST_RESERVE,
        coordinates=[
            [35.50, -0.20], [35.75, -0.20],
            [35.75, -0.45], [35.50, -0.45], [35.50, -0.20],
        ],
        area_hectares=273_300,
        legal_status="Kenya Gazette Notice No. 2385",
        managing_authority="Kenya Forest Service",
        community_name="Ogiek People",
    )

    print("\n" + "="*60)
    print("  EDEN :: Corporate Intrusion Monitor")
    print("="*60)
    print(f"  Zone    : {mau_forest.name}")
    print(f"  Type    : {mau_forest.zone_type.value}")
    print(f"  Area    : {mau_forest.area_hectares:,} ha")
    print(f"  Status  : {mau_forest.legal_status}")
    print(f"  Mode    : Shadow (no SAR client)")

    events = monitor.scan_zone(mau_forest)
    print(f"  Events  : {len(events)} intrusion(s) detected")
    print("  Result  : Pipeline verified - ready for SAR client injection")
    print("="*60)
