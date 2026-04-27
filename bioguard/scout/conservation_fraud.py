# -*- coding: utf-8 -*-
"""
EDEN-BioGuard :: Conservation Fraud Detector
bioguard/scout/conservation_fraud.py  |  v1.0.0

Exposes the conservation lie.
Author : Warren Greg � EDEN-BioGuard
License: MIT
"""
from __future__ import annotations
import hashlib, json, logging
from dataclasses import dataclass, field, asdict
from datetime import datetime, date, timezone
from enum import Enum
from typing import List, Optional

logger = logging.getLogger(__name__)

class FraudVerdict(str, Enum):
    VERIFIED          = "VERIFIED"
    SUSPICIOUS        = "SUSPICIOUS"
    FRAUDULENT        = "FRAUDULENT"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"

class InfrastructureType(str, Enum):
    ROAD       = "road"
    STRUCTURE  = "structure"
    CLEARING   = "clearing"
    FENCE_LINE = "fence_line"
    MINING_PIT = "mining_pit"
    UNKNOWN    = "unknown"

@dataclass
class GeoPolygon:
    name: str
    coordinates: List[List[float]]
    area_hectares: float
    country: str = "KE"

    def centroid(self) -> List[float]:
        lons = [c[0] for c in self.coordinates]
        lats = [c[1] for c in self.coordinates]
        return [sum(lons)/len(lons), sum(lats)/len(lats)]

@dataclass
class DateRange:
    start: str
    end: str

    def duration_months(self) -> int:
        s = date.fromisoformat(self.start)
        e = date.fromisoformat(self.end)
        return (e.year - s.year) * 12 + (e.month - s.month)

@dataclass
class NDVIReading:
    timestamp: str
    mean_ndvi: float
    coverage_pct: float
    source: str = "Sentinel-2"

    def is_healthy_forest(self) -> bool:
        return self.mean_ndvi > 0.55

@dataclass
class InfrastructureAnomaly:
    location: List[float]
    infra_type: InfrastructureType
    area_m2: float
    detected_date: str
    confidence: float
    sar_evidence_hash: str = ""

@dataclass
class ConservationClaim:
    entity_id: str
    entity_name: str
    region: GeoPolygon
    claim_period: DateRange
    claimed_type: str
    carbon_credits_issued: int = 0
    source_document_hash: str = ""

@dataclass
class FraudAssessment:
    claim: ConservationClaim
    verdict: FraudVerdict
    fraud_score: float
    ndvi_before: Optional[NDVIReading] = None
    ndvi_after: Optional[NDVIReading] = None
    ndvi_delta: float = 0.0
    infrastructure_detected: List[InfrastructureAnomaly] = field(default_factory=list)
    assessment_timestamp: str = ""
    evidence_ipfs_hash: str = ""
    assessor: str = "EDEN-SCOUT-1"
    notes: str = ""

    def is_carbon_credit_blocked(self) -> bool:
        """Lex-0 rule: no CarbonCreditNFT minted for FRAUDULENT zones."""
        return self.verdict == FraudVerdict.FRAUDULENT

    def to_chain_payload(self) -> dict:
        return {
            "entity_id":             self.claim.entity_id,
            "entity_name":           self.claim.entity_name,
            "region_name":           self.claim.region.name,
            "region_centroid":       self.claim.region.centroid(),
            "claim_period_start":    self.claim.claim_period.start,
            "claim_period_end":      self.claim.claim_period.end,
            "carbon_credits_issued": self.claim.carbon_credits_issued,
            "fraud_score":           round(self.fraud_score, 2),
            "verdict":               self.verdict.value,
            "ndvi_delta":            round(self.ndvi_delta, 4),
            "infra_anomalies":       len(self.infrastructure_detected),
            "evidence_ipfs":         self.evidence_ipfs_hash,
            "timestamp":             self.assessment_timestamp,
        }

class FraudScoringEngine:
    NDVI_WEIGHT       = 40.0
    INFRA_WEIGHT      = 30.0
    CARBON_GAP_WEIGHT = 20.0
    TEMPORAL_WEIGHT   = 10.0
    NDVI_SUSPICIOUS   = -0.05
    NDVI_FRAUDULENT   = -0.15

    def score(self, claim, ndvi_before, ndvi_after, anomalies):
        notes = []
        score = 0.0

        if ndvi_before and ndvi_after:
            delta = ndvi_after.mean_ndvi - ndvi_before.mean_ndvi
            if delta <= self.NDVI_FRAUDULENT:
                score += self.NDVI_WEIGHT
                notes.append(f"NDVI dropped {delta:.3f} � severe vegetation loss in claimed zone.")
            elif delta <= self.NDVI_SUSPICIOUS:
                score += self.NDVI_WEIGHT * 0.5
                notes.append(f"NDVI dropped {delta:.3f} � moderate degradation detected.")
            elif delta > 0.05:
                notes.append(f"NDVI improved +{delta:.3f} � vegetation recovery confirmed.")
            else:
                score += self.NDVI_WEIGHT * 0.1
                notes.append(f"NDVI stable ({delta:+.3f}).")
        else:
            score += self.NDVI_WEIGHT * 0.3
            notes.append("Missing NDVI � insufficient satellite coverage.")

        high_conf = [a for a in anomalies if a.confidence >= 0.75]
        if high_conf:
            score += min(self.INFRA_WEIGHT, len(high_conf) * (self.INFRA_WEIGHT / 3))
            types = {a.infra_type.value for a in high_conf}
            notes.append(f"{len(high_conf)} infrastructure anomaly detected: {', '.join(types)}.")

        if claim.carbon_credits_issued > 0 and ndvi_before and ndvi_after:
            if (ndvi_after.mean_ndvi - ndvi_before.mean_ndvi) < 0:
                score += self.CARBON_GAP_WEIGHT
                notes.append(f"{claim.carbon_credits_issued:,} tCO2 credits issued but forest is declining � carbon fraud.")

        if claim.claim_period.duration_months() < 12:
            score += self.TEMPORAL_WEIGHT
            notes.append("Claim period under 12 months � unverifiable.")

        return min(round(score, 2), 100.0), " | ".join(notes)

    def verdict_from_score(self, score: float) -> FraudVerdict:
        if score >= 65:   return FraudVerdict.FRAUDULENT
        elif score >= 35: return FraudVerdict.SUSPICIOUS
        else:             return FraudVerdict.VERIFIED

class ConservationFraudDetector:
    def __init__(self, satellite_client=None, sar_client=None, chain_notary=None, evidence_store=None):
        self.satellite = satellite_client
        self.sar       = sar_client
        self.chain     = chain_notary
        self.store     = evidence_store
        self.scorer    = FraudScoringEngine()
        logger.info("ConservationFraudDetector initialised (shadow_mode=%s)", satellite_client is None)

    def assess_claim(self, claim: ConservationClaim) -> FraudAssessment:
        logger.info("Assessing: %s / %s", claim.entity_name, claim.region.name)
        ndvi_before = self._get_ndvi(claim.region, claim.claim_period.start)
        ndvi_after  = self._get_ndvi(claim.region, claim.claim_period.end)
        anomalies   = self._detect_infrastructure(claim.region, claim.claim_period)
        ndvi_delta  = (ndvi_after.mean_ndvi - ndvi_before.mean_ndvi) if ndvi_before and ndvi_after else 0.0
        fraud_score, notes = self.scorer.score(claim, ndvi_before, ndvi_after, anomalies)
        verdict     = self.scorer.verdict_from_score(fraud_score)
        bundle      = self._build_evidence_bundle(claim, ndvi_before, ndvi_after, anomalies)
        evid_hash   = self._pin_evidence(bundle)
        assessment  = FraudAssessment(
            claim=claim, verdict=verdict, fraud_score=fraud_score,
            ndvi_before=ndvi_before, ndvi_after=ndvi_after, ndvi_delta=ndvi_delta,
            infrastructure_detected=anomalies,
            assessment_timestamp=datetime.now(timezone.utc).isoformat(),
            evidence_ipfs_hash=evid_hash, notes=notes,
        )
        self._log_to_chain(assessment)
        if verdict == FraudVerdict.FRAUDULENT:
            self._raise_fraud_alert(assessment)
        logger.info("Done: score=%.1f verdict=%s", fraud_score, verdict.value)
        return assessment

    def batch_assess(self, claims):
        results = []
        for c in claims:
            try:    results.append(self.assess_claim(c))
            except Exception as e: logger.error("Failed %s: %s", c.entity_id, e)
        return results

    def _get_ndvi(self, region, date_str):
        if self.satellite is None: return None
        return self.satellite.get_ndvi(region.coordinates, date_str)

    def _detect_infrastructure(self, region, period):
        if self.sar is None: return []
        return self.sar.detect_changes(region.coordinates, period.start, period.end)

    def _build_evidence_bundle(self, claim, ndvi_before, ndvi_after, anomalies):
        return {
            "schema_version": "1.0.0",
            "generated_by":   "EDEN-BioGuard::ConservationFraudDetector",
            "claim":          asdict(claim),
            "ndvi_before":    asdict(ndvi_before) if ndvi_before else None,
            "ndvi_after":     asdict(ndvi_after)  if ndvi_after  else None,
            "infrastructure": [asdict(a) for a in anomalies],
            "timestamp":      datetime.now(timezone.utc).isoformat(),
        }

    def _pin_evidence(self, bundle):
        payload = json.dumps(bundle, sort_keys=True, default=str)
        if self.store: return self.store.pin(payload)
        return "sha256:" + hashlib.sha256(payload.encode()).hexdigest()

    def _log_to_chain(self, assessment):
        if self.chain is None: return
        self.chain.log_fraud_assessment(assessment.to_chain_payload())

    def _raise_fraud_alert(self, assessment):
        logger.warning("FRAUD ALERT | entity=%s | region=%s | score=%.1f | evidence=%s",
            assessment.claim.entity_name, assessment.claim.region.name,
            assessment.fraud_score, assessment.evidence_ipfs_hash)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
    detector = ConservationFraudDetector()
    demo = ConservationClaim(
        entity_id="CORP-001", entity_name="GreenShield Carbon Ltd",
        region=GeoPolygon(
            name="Mau Forest North Block",
            coordinates=[[35.50,-0.20],[35.75,-0.20],[35.75,-0.45],[35.50,-0.45],[35.50,-0.20]],
            area_hectares=12000,
        ),
        claim_period=DateRange(start="2022-01-01", end="2024-12-31"),
        claimed_type="carbon_project", carbon_credits_issued=45000,
    )
    r = detector.assess_claim(demo)
    print("\n" + "="*60)
    print("  EDEN :: Conservation Fraud Assessment")
    print("="*60)
    print(f"  Entity  : {r.claim.entity_name}")
    print(f"  Region  : {r.claim.region.name}")
    print(f"  Score   : {r.fraud_score} / 100")
    print(f"  Verdict : {r.verdict.value}")
    print(f"  Blocked : {r.is_carbon_credit_blocked()}")
    print(f"  Notes   : {r.notes}")
    print("="*60)
