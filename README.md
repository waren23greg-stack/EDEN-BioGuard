# 🦠 EDEN-BioGuard

> **Data-Driven Biosecurity for East Africa**  
> Democratizing biological threat surveillance through affordable, open-source data pipelines.

## Vision
To empower low-resource healthcare settings with real-time, actionable intelligence
to detect, track, and mitigate biological threats through integrated data analytics
and community-led restoration.

## Pipeline Architecture
Live Feeds (WHO AFRO, Africa CDC)
↓
Lab Ingestion Engine          ← validates & standardises records
↓
BTU Risk Scoring Model        ← NDVI + case count + source credibility
↓
Geospatial Dashboard          ← interactive heatmap across East Africa

## Features
- **Real-time ingestion** — WHO AFRO + Africa CDC Epidemic Intelligence feeds
- **Risk scoring** — Bio-Threat Unit (BTU) model combining satellite NDVI, case counts, and source type
- **Interactive map** — Folium heatmap with clustered markers, coloured by risk tier
- **Synthetic dataset** — 500-row baseline covering Kenya, Uganda, Tanzania, Ethiopia, DRC, Somalia, Rwanda
- **EDEN cross-link** — Sentinel-2 NDVI used as ecosystem health proxy (healthy vegetation = lower zoonotic risk)

## Quick Start
```bash
pip install -r requirements.txt
python data/synthetic/generate_outbreak.py      # generate baseline
python -m src.modeling.risk_model               # score incidents
python -m src.ingestion.feed_intake             # pull live alerts
python -m src.visualization.geo_dashboard       # build map
start dashboards/btu_map.html                   # view in browser
```

## Data Sources
| Source | Type | Coverage |
|--------|------|----------|
| WHO AFRO | RSS feed | Africa-wide |
| Africa CDC Epidemic Intelligence | RSS feed | Africa-wide |
| Sentinel-2 NDVI (Planetary Computer) | Satellite | East Africa |
| Synthetic baseline | Generated | East Africa |

## Roadmap
- [ ] 30-day outbreak forecasting model
- [ ] NDVI reforestation overlay on dashboard  
- [ ] Kenya/Uganda/Tanzania national lab data integration
- [ ] AGARI genomic data linkage (Africa CDC platform)
- [ ] REST API for partner health systems

## License
MIT
