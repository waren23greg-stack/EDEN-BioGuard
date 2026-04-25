# -*- coding: utf-8 -*-
"""
EDEN-BioGuard :: Legal Evidence Packager
bioguard/legal/evidence_packager.py  |  v1.0.0

Compiles satellite data, blockchain logs, displacement records,
fraud assessments and community testimony into structured evidence
packages ready for:

  - Kenya National Land Commission (NLC)
  - NEMA (National Environment Management Authority)
  - ODPP (Director of Public Prosecutions)
  - ICC / UN Special Rapporteur on Indigenous Rights
  - Investigative journalists (structured for publication)
  - International court submissions

This is the module that turns data into justice.

Author : Warren Greg - EDEN-BioGuard
License: MIT
"""

from __future__ import annotations
import hashlib, json, logging, uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import List, Optional, Dict, Any

logger = logging.getLogger(__name__)


# -- Enumerations -------------------------------------------------------------

class CaseType(str, Enum):
    CONSERVATION_FRAUD     = "conservation_fraud"
    CORPORATE_INTRUSION    = "corporate_intrusion"
    COMMUNITY_DISPLACEMENT = "community_displacement"
    POACHING_NETWORK       = "poaching_network"
    COMBINED               = "combined"


class TargetAuthority(str, Enum):
    KENYA_NLC          = "kenya_national_land_commission"
    NEMA               = "nema_kenya"
    ODPP               = "kenya_odpp"
    KWS                = "kenya_wildlife_service"
    UN_SPECIAL_RAP     = "un_special_rapporteur_indigenous"
    ICC                = "international_criminal_court"
    JOURNALIST         = "investigative_journalist"
    INTERNAL           = "eden_internal"


class PackageStatus(str, Enum):
    DRAFT      = "DRAFT"
    SEALED     = "SEALED"      # Hashed, ready to submit
    SUBMITTED  = "SUBMITTED"   # Sent to authority
    ACCEPTED   = "ACCEPTED"
    REJECTED   = "REJECTED"


# -- Data classes -------------------------------------------------------------

@dataclass
class SatelliteEvidence:
    scene_id: str
    source: str                  # "Sentinel-2" | "Landsat-9" | "Sentinel-1"
    capture_date: str
    region_name: str
    finding: str                 # Human-readable: "NDVI dropped 0.21 — 40% canopy loss"
    ipfs_hash: str               # Pinned image/GeoTIFF
    coordinates: List[List[float]]
    cloud_cover_pct: float = 0.0
    resolution_m: int = 10


@dataclass
class BlockchainRecord:
    tx_hash: str
    contract: str                # e.g. "ThreatAlert.sol" | "DisplacementLedger.sol"
    network: str                 # "polygon-mainnet" | "polygon-mumbai"
    block_number: int
    timestamp: str
    event_type: str
    payload_summary: str         # Human-readable summary of on-chain event
    explorer_url: str = ""       # e.g. polygonscan.com/tx/...


@dataclass
class WitnessStatement:
    statement_id: str
    witness_type: str            # "community_member" | "ranger" | "journalist" | "expert"
    statement_date: str
    summary: str                 # Non-identifying summary for public package
    full_statement_hash: str     # IPFS hash of full statement (may be redacted)
    language: str = "en"
    verified_by: str = ""
    witness_anonymous: bool = True


@dataclass
class EvidencePackage:
    """
    A complete, sealed evidence package ready for legal submission.
    All components are hashed together — any tampering is detectable.
    """
    package_id: str
    case_type: CaseType
    case_title: str
    target_authority: TargetAuthority
    status: PackageStatus

    # Evidence components
    satellite_evidence: List[SatelliteEvidence] = field(default_factory=list)
    blockchain_records: List[BlockchainRecord]  = field(default_factory=list)
    witness_statements: List[WitnessStatement]  = field(default_factory=list)
    fraud_assessments: List[dict]               = field(default_factory=list)
    intrusion_events: List[dict]                = field(default_factory=list)
    displacement_events: List[dict]             = field(default_factory=list)
    supporting_documents: List[dict]            = field(default_factory=list)

    # Metadata
    compiled_by: str = "EDEN-BioGuard::LegalEvidencePackager"
    compiled_at: str = ""
    geographic_scope: str = ""
    time_period_start: str = ""
    time_period_end: str = ""
    executive_summary: str = ""
    package_hash: str = ""       # SHA-256 of entire package — tamper detection
    ipfs_hash: str = ""          # IPFS CID after pinning

    def compute_hash(self) -> str:
        payload = json.dumps(asdict(self), sort_keys=True, default=str)
        return hashlib.sha256(payload.encode()).hexdigest()

    def evidence_count(self) -> dict:
        return {
            "satellite":    len(self.satellite_evidence),
            "blockchain":   len(self.blockchain_records),
            "witnesses":    len(self.witness_statements),
            "fraud_cases":  len(self.fraud_assessments),
            "intrusions":   len(self.intrusion_events),
            "displacements":len(self.displacement_events),
            "documents":    len(self.supporting_documents),
            "total":        (len(self.satellite_evidence) + len(self.blockchain_records) +
                            len(self.witness_statements) + len(self.fraud_assessments) +
                            len(self.intrusion_events) + len(self.displacement_events)),
        }

    def to_submission_header(self) -> dict:
        """Cover sheet for formal legal submission."""
        return {
            "package_id":         self.package_id,
            "case_title":         self.case_title,
            "case_type":          self.case_type.value,
            "target_authority":   self.target_authority.value,
            "status":             self.status.value,
            "compiled_by":        self.compiled_by,
            "compiled_at":        self.compiled_at,
            "geographic_scope":   self.geographic_scope,
            "time_period":        f"{self.time_period_start} to {self.time_period_end}",
            "evidence_count":     self.evidence_count(),
            "executive_summary":  self.executive_summary,
            "package_integrity":  self.package_hash,
            "ipfs_archive":       self.ipfs_hash,
        }


# -- Authority format adapters ------------------------------------------------

class AuthorityFormatter:
    """
    Formats evidence packages for specific authority requirements.
    Each authority has different submission formats and requirements.
    """

    def format(self, package: EvidencePackage, authority: TargetAuthority) -> dict:
        formatters = {
            TargetAuthority.KENYA_NLC:      self._format_nlc,
            TargetAuthority.NEMA:           self._format_nema,
            TargetAuthority.ODPP:           self._format_odpp,
            TargetAuthority.UN_SPECIAL_RAP: self._format_un,
            TargetAuthority.JOURNALIST:     self._format_journalist,
            TargetAuthority.INTERNAL:       self._format_internal,
        }
        formatter = formatters.get(authority, self._format_internal)
        return formatter(package)

    def _format_nlc(self, p: EvidencePackage) -> dict:
        """Kenya National Land Commission format."""
        return {
            "submission_type":   "Land Rights Complaint",
            "act_reference":     "National Land Commission Act 2012, Section 14",
            "complainant":       p.compiled_by,
            "affected_communities": [d.get("community_name") for d in p.displacement_events],
            "land_parcels":      [d.get("land_id") for d in p.displacement_events],
            "satellite_proof":   [{"date": s.capture_date, "finding": s.finding,
                                   "ipfs": s.ipfs_hash} for s in p.satellite_evidence],
            "blockchain_proof":  [r.tx_hash for r in p.blockchain_records],
            "relief_sought":     "Immediate halt to evictions; restoration of land rights; compensation",
            "package_integrity": p.package_hash,
        }

    def _format_nema(self, p: EvidencePackage) -> dict:
        """NEMA Kenya environmental enforcement format."""
        return {
            "submission_type":     "Environmental Violation Report",
            "emca_reference":      "Environmental Management and Co-ordination Act 1999",
            "violation_type":      p.case_type.value,
            "geographic_scope":    p.geographic_scope,
            "satellite_evidence":  [asdict(s) for s in p.satellite_evidence],
            "corporate_actors":    [i.get("suspected_entity") for i in p.intrusion_events],
            "fraud_findings":      p.fraud_assessments,
            "enforcement_request": "Investigation, stop order, and penalty proceedings",
            "package_integrity":   p.package_hash,
        }

    def _format_odpp(self, p: EvidencePackage) -> dict:
        """Director of Public Prosecutions format."""
        return {
            "submission_type":    "Criminal Complaint",
            "offences_alleged":   self._infer_offences(p),
            "evidence_summary":   p.executive_summary,
            "satellite_timeline": [{"date": s.capture_date, "source": s.source,
                                    "finding": s.finding} for s in p.satellite_evidence],
            "blockchain_audit":   [{"contract": r.contract, "tx": r.tx_hash,
                                    "event": r.event_type} for r in p.blockchain_records],
            "witness_count":      len(p.witness_statements),
            "anonymous_witnesses": sum(1 for w in p.witness_statements if w.witness_anonymous),
            "package_integrity":  p.package_hash,
            "ipfs_archive":       p.ipfs_hash,
        }

    def _format_un(self, p: EvidencePackage) -> dict:
        """UN Special Rapporteur on the Rights of Indigenous Peoples format."""
        return {
            "submission_to":       "UN Special Rapporteur on the Rights of Indigenous Peoples",
            "undrip_articles":     ["Article 10 (no forced relocation)",
                                    "Article 19 (free, prior, informed consent)",
                                    "Article 26 (land rights)"],
            "affected_peoples":    list({d.get("community_name") for d in p.displacement_events}),
            "total_affected":      sum(d.get("people_affected", 0) for d in p.displacement_events),
            "fpic_violations":     sum(1 for d in p.displacement_events if d.get("fpic_violated")),
            "satellite_evidence":  [{"date": s.capture_date, "finding": s.finding,
                                     "ipfs": s.ipfs_hash} for s in p.satellite_evidence],
            "state_actors":        [a for d in p.displacement_events
                                    for a in d.get("alleged_actors", [])],
            "remedies_requested":  ["Cessation of evictions", "Land restitution",
                                    "Meaningful FPIC process", "Reparations"],
            "package_integrity":   p.package_hash,
        }

    def _format_journalist(self, p: EvidencePackage) -> dict:
        """Structured briefing for investigative journalists."""
        return {
            "story_angle":        p.case_title,
            "executive_summary":  p.executive_summary,
            "key_findings":       self._extract_key_findings(p),
            "data_sources":       list({s.source for s in p.satellite_evidence}),
            "verifiable_claims":  [{"claim": s.finding, "evidence": s.ipfs_hash,
                                    "date": s.capture_date} for s in p.satellite_evidence],
            "blockchain_audit_trail": [r.explorer_url for r in p.blockchain_records if r.explorer_url],
            "affected_communities": [d.get("community_name") for d in p.displacement_events],
            "corporate_actors":   list({i.get("suspected_entity") for i in p.intrusion_events}),
            "evidence_archive":   p.ipfs_hash,
            "contact":            "warren.greg@cuk.ac.ke",
        }

    def _format_internal(self, p: EvidencePackage) -> dict:
        return asdict(p)

    def _infer_offences(self, p: EvidencePackage) -> List[str]:
        offences = []
        if p.fraud_assessments:
            offences.append("Fraud - Carbon credit misrepresentation")
        if p.intrusion_events:
            offences.append("Trespass - Unauthorized entry into protected land")
        if p.displacement_events:
            offences.append("Forcible displacement - Land grabbing")
        return offences

    def _extract_key_findings(self, p: EvidencePackage) -> List[str]:
        findings = []
        for s in p.satellite_evidence[:5]:
            findings.append(f"{s.capture_date}: {s.finding} ({s.source})")
        for d in p.displacement_events[:3]:
            findings.append(
                f"{d.get('incident_date','?')}: {d.get('people_affected',0)} people displaced "
                f"from {d.get('area_hectares',0):.0f}ha in {d.get('region','?')}"
            )
        return findings


# -- Main packager ------------------------------------------------------------

class LegalEvidencePackager:
    """
    Primary interface. Assembles evidence from all EDEN modules
    into sealed, authority-specific submission packages.
    """

    def __init__(
        self,
        chain_notary=None,
        evidence_store=None,
        output_dir: str = "output/legal_packages",
    ):
        self.chain      = chain_notary
        self.store      = evidence_store
        self.output_dir = Path(output_dir)
        self.formatter  = AuthorityFormatter()
        logger.info("LegalEvidencePackager ready")

    def build_package(
        self,
        case_title: str,
        case_type: CaseType,
        target_authority: TargetAuthority,
        satellite_evidence: List[SatelliteEvidence] = None,
        blockchain_records: List[BlockchainRecord] = None,
        witness_statements: List[WitnessStatement] = None,
        fraud_assessments: List[dict] = None,
        intrusion_events: List[dict] = None,
        displacement_events: List[dict] = None,
        geographic_scope: str = "",
        time_period_start: str = "",
        time_period_end: str = "",
        executive_summary: str = "",
    ) -> EvidencePackage:
        """Build and seal a complete evidence package."""

        package_id = "PKG-" + uuid.uuid4().hex[:10].upper()
        now = datetime.now(timezone.utc).isoformat()

        package = EvidencePackage(
            package_id=package_id,
            case_type=case_type,
            case_title=case_title,
            target_authority=target_authority,
            status=PackageStatus.DRAFT,
            satellite_evidence=satellite_evidence or [],
            blockchain_records=blockchain_records or [],
            witness_statements=witness_statements or [],
            fraud_assessments=fraud_assessments or [],
            intrusion_events=intrusion_events or [],
            displacement_events=displacement_events or [],
            compiled_at=now,
            geographic_scope=geographic_scope,
            time_period_start=time_period_start,
            time_period_end=time_period_end,
            executive_summary=executive_summary,
        )

        # Seal: compute integrity hash
        package.package_hash = package.compute_hash()
        package.status = PackageStatus.SEALED

        # Pin to IPFS
        package.ipfs_hash = self._pin_package(package)

        logger.info("Package sealed: %s | %d evidence items | authority=%s",
                    package_id, package.evidence_count()["total"],
                    target_authority.value)
        return package

    def export(
        self,
        package: EvidencePackage,
        formats: List[str] = None,
    ) -> Dict[str, Path]:
        """
        Export package in requested formats.
        formats: ["json", "nlc", "nema", "odpp", "un", "journalist"]
        """
        formats = formats or ["json"]
        self.output_dir.mkdir(parents=True, exist_ok=True)
        exported = {}

        for fmt in formats:
            try:
                if fmt == "json":
                    data = asdict(package)
                    path = self.output_dir / f"{package.package_id}_full.json"
                else:
                    authority_map = {
                        "nlc":        TargetAuthority.KENYA_NLC,
                        "nema":       TargetAuthority.NEMA,
                        "odpp":       TargetAuthority.ODPP,
                        "un":         TargetAuthority.UN_SPECIAL_RAP,
                        "journalist": TargetAuthority.JOURNALIST,
                    }
                    authority = authority_map.get(fmt, TargetAuthority.INTERNAL)
                    data = self.formatter.format(package, authority)
                    path = self.output_dir / f"{package.package_id}_{fmt}.json"

                path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
                exported[fmt] = path
                logger.info("Exported: %s -> %s", fmt, path)
            except Exception as exc:
                logger.error("Export failed for format %s: %s", fmt, exc)

        return exported

    def _pin_package(self, package: EvidencePackage) -> str:
        payload = json.dumps(asdict(package), sort_keys=True, default=str)
        if self.store:
            return self.store.pin(payload)
        return "sha256:" + hashlib.sha256(payload.encode()).hexdigest()


# -- CLI smoke-test -----------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")

    packager = LegalEvidencePackager()

    sat_ev = SatelliteEvidence(
        scene_id="S2-2024-MAU-001",
        source="Sentinel-2",
        capture_date="2024-06-15",
        region_name="Mau Forest North Block",
        finding="NDVI dropped 0.21 between Jan 2022 and Jun 2024 — 40% canopy loss in claimed conservation zone",
        ipfs_hash="sha256:abc123",
        coordinates=[[35.50,-0.20],[35.75,-0.45]],
        cloud_cover_pct=4.2,
    )

    displacement = {
        "event_id": "DISP-001",
        "community_name": "Ogiek People of Mau Forest",
        "region": "Mau Forest Complex, Nakuru County",
        "land_id": "LAND-MAU-001",
        "area_hectares": 8500,
        "displacement_type": "carbon_project_grab",
        "incident_date": "2023-03-15",
        "people_affected": 312,
        "fpic_violated": True,
        "alleged_actors": ["GreenShield Carbon Ltd"],
    }

    package = packager.build_package(
        case_title="GreenShield Carbon Ltd - Mau Forest Fraud and Displacement",
        case_type=CaseType.COMBINED,
        target_authority=TargetAuthority.KENYA_NLC,
        satellite_evidence=[sat_ev],
        displacement_events=[displacement],
        geographic_scope="Mau Forest Complex, Nakuru County, Kenya",
        time_period_start="2022-01-01",
        time_period_end="2024-12-31",
        executive_summary=(
            "Satellite evidence confirms 40% canopy loss in a zone for which "
            "GreenShield Carbon Ltd issued 45,000 tCO2 carbon credits. "
            "312 Ogiek people were evicted without FPIC consultation."
        ),
    )

    exported = packager.export(package, formats=["json", "nlc", "un", "journalist"])

    print("\n" + "="*60)
    print("  EDEN :: Legal Evidence Packager")
    print("="*60)
    print(f"  Package  : {package.package_id}")
    print(f"  Case     : {package.case_title}")
    print(f"  Status   : {package.status.value}")
    print(f"  Evidence : {package.evidence_count()}")
    print(f"  Hash     : {package.package_hash[:48]}...")
    print(f"  Exported :")
    for fmt, path in exported.items():
        print(f"    [{fmt}] -> {path}")
    print("="*60)
