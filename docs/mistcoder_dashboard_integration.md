# MISTCODER Dashboard Integration (Serah Njogu Deliverables)

This repository now includes a professional dashboard UI for unified **software security** and **ecological/health** events.

## Files added

- `/home/runner/work/EDEN-BioGuard/EDEN-BioGuard/dashboards/software_ecological_dashboard.html`
- `/home/runner/work/EDEN-BioGuard/EDEN-BioGuard/dashboards/software_ecological_dashboard.js`
- `/home/runner/work/EDEN-BioGuard/EDEN-BioGuard/dashboards/mistcoder-client.js`
- `/home/runner/work/EDEN-BioGuard/EDEN-BioGuard/dashboards/dashboard.config.js`
- `/home/runner/work/EDEN-BioGuard/EDEN-BioGuard/src/visualization/generate_dashboard_config.py`

## Capabilities implemented

- KPI summary cards
- Filters (date range, region/county, event type, severity)
- Timeline/event feed
- Map panel placeholder for existing map integration
- Responsive, accessible layout
- Loading/empty/error states
- Live refresh polling with exponential backoff
- In-memory cache to reduce flicker
- Mock fallback events when API is unreachable or not configured

## MISTCODER API configuration (env-driven)

Set environment variables before generating dashboard config:

```bash
export MISTCODER_BASE_URL="https://your-mistcoder-host"
export MISTCODER_REFRESH_MS="45000"
export MISTCODER_TIMEOUT_MS="10000"
export MISTCODER_CACHE_TTL_MS="30000"
```

Generate the runtime config file:

```bash
cd /home/runner/work/EDEN-BioGuard/EDEN-BioGuard
python3 -m src.visualization.generate_dashboard_config
```

This writes:

- `dashboards/dashboard.config.js`

## Run the dashboard

Open this file in a browser:

- `/home/runner/work/EDEN-BioGuard/EDEN-BioGuard/dashboards/software_ecological_dashboard.html`

### Behavior

- If `MISTCODER_BASE_URL` is set and reachable, live data is fetched from MISTCODER endpoints.
- If not set or unreachable, the dashboard automatically shows mock events.

## Endpoint strategy

The client tries these paths against `MISTCODER_BASE_URL`:

- `/api/v1/dashboard/events`
- `/api/v1/events`
- `/api/events`
- `/events`

Returned payloads are normalized into a unified event model for rendering.
