# EDEN-BioGuard

> **Ecological Defence & Enforcement Network** — AI-powered conservation accountability platform.
> Exposes conservation fraud, corporate land grabs, and community displacement using satellite data, blockchain, and law.

---

## The Problem

Conservation is being weaponised:
- **The Conservation Lie** — corporations and NGOs sell carbon credits for forests they never protected
- **Corporate Intrusion** — investors and businesses build roads and structures inside protected wildlife zones
- **Community Displacement** — indigenous people are evicted from ancestral land under cover of "conservation"

EDEN makes these crimes impossible to hide.

---

## Architecture

### Python Modules (`bioguard/`)

| Module | Path | Purpose |
|--------|------|---------|
| Conservation Fraud Detector | `bioguard/scout/conservation_fraud.py` | Verifies conservation claims against Sentinel-2 NDVI satellite data. Scores 0-100. Blocks carbon credit minting for FRAUDULENT zones. |
| Corporate Intrusion Monitor | `bioguard/scout/corporate_intrusion.py` | Detects unauthorized roads, structures, and clearings inside protected zones using Sentinel-1 SAR change detection. |
| Displacement Ledger | `bioguard/community/displacement_ledger.py` | Immutable record of communities displaced from ancestral land. Landsat archive proves habitation back to 1984. |
| Legal Evidence Packager | `bioguard/legal/evidence_packager.py` | Compiles satellite data, blockchain logs, and testimony into court-ready packages for Kenya NLC, NEMA, ODPP, UN, and journalists. |
| Lex-0 Ethics Engine | `bioguard/ethics/lex0_rules.py` | Constitutional ruleset. 7 hard rules no agent or operator can override. Every action must pass Lex-0 before execution. |

### Smart Contracts (`contracts/`)

| Contract | Purpose |
|----------|---------|
| `DisplacementLedger.sol` | Immutable displacement event log. Active events block carbon credit minting (Lex-0 LEX-001). |
| `ConservationFraud.sol` | Fraud assessment records. FRAUDULENT verdict blocks minting (Lex-0 LEX-002). |
| `CorporateIntrusion.sol` | Unauthorized infrastructure log. Immutable, publicly queryable. |
| `WhistleblowerReward.sol` | Anonymous bounty payments: fraud (0.5 ETH), intrusion (0.3 ETH), displacement (0.5 ETH). |

---

## Lex-0 Hard Rules

No AI agent, operator, government, or corporation can override these:

| Rule | Enforcement |
|------|-------------|
| LEX-001 | No `CarbonCreditNFT` minted on land with active displacement event |
| LEX-002 | No `CarbonCreditNFT` minted for zones with FRAUDULENT fraud verdict |
| LEX-003 | No hardware deployed on indigenous land without completed FPIC |
| LEX-004 | No insurance payout before model accuracy >= 80% for 6 months |
| LEX-005 | No alert suppression — there are no protected actors |
| LEX-006 | No deletion or modification of sealed records |
| LEX-007 | No invasive species deployment |

---

## Satellite Data Sources

- **Sentinel-2** — NDVI vegetation index, fraud verification
- **Sentinel-1 SAR** — Infrastructure change detection (penetrates cloud cover)
- **Landsat archive** — Historical habitation proof back to 1984
- **MODIS** — Large-scale ecosystem monitoring

---

## Shadow Mode

All modules run without live API keys. Inject real clients at init:

```python
from bioguard.scout.conservation_fraud import ConservationFraudDetector

detector = ConservationFraudDetector(
    satellite_client=your_sentinel2_client,
    sar_client=your_sar_client,
    chain_notary=your_polygon_client,
    evidence_store=your_ipfs_client,
)
```

---

## Author

Warren Greg — EDEN-BioGuard  
License: MIT
