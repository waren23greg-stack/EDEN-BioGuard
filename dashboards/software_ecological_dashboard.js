import { createMistcoderClient } from "./mistcoder-client.js";

const MOCK_EVENTS = [
  {
    id: "sec-001",
    domain: "software",
    eventType: "vulnerability",
    severity: "high",
    title: "Critical dependency vulnerability detected",
    summary: "MISTCODER flagged CVE-like package risk in field telemetry service.",
    region: "Nairobi",
    county: "Nairobi",
    source: "MISTCODER",
    detectedAt: "2026-05-14T09:20:00Z",
  },
  {
    id: "sec-002",
    domain: "software",
    eventType: "threat_alert",
    severity: "medium",
    title: "Suspicious authentication spike",
    summary: "Anomalous login attempts observed against response coordination dashboard.",
    region: "Kisumu",
    county: "Kisumu",
    source: "MISTCODER",
    detectedAt: "2026-05-14T14:05:00Z",
  },
  {
    id: "eco-001",
    domain: "ecological",
    eventType: "outbreak",
    severity: "high",
    title: "Localized cholera outbreak alert",
    summary: "Field team incident report indicates rapid escalation in vulnerable settlements.",
    region: "Mombasa",
    county: "Mombasa",
    source: "Field Incident Feed",
    detectedAt: "2026-05-13T10:00:00Z",
  },
  {
    id: "eco-002",
    domain: "ecological",
    eventType: "ndvi",
    severity: "low",
    title: "NDVI decline watchpoint",
    summary: "Vegetation index dropped below seasonal baseline in protected area corridor.",
    region: "Rift Valley",
    county: "Nakuru",
    source: "NDVI Monitor",
    detectedAt: "2026-05-12T08:10:00Z",
  },
  {
    id: "eco-003",
    domain: "ecological",
    eventType: "field_incident",
    severity: "critical",
    title: "Wildlife-livestock interface incident",
    summary: "A field responder logged cross-species exposure with immediate containment required.",
    region: "Garissa",
    county: "Garissa",
    source: "Field Ops",
    detectedAt: "2026-05-15T06:45:00Z",
  },
];

const config = window.EDEN_DASHBOARD_CONFIG || {};
const client = createMistcoderClient({
  baseUrl: config.apiBaseUrl || "",
  timeoutMs: Number(config.timeoutMs || 10000),
  cacheTtlMs: Number(config.cacheTtlMs || 30000),
});

const state = {
  events: [],
  filters: {
    startDate: "",
    endDate: "",
    region: "",
    eventType: "",
    severity: "",
  },
  pollingDelayMs: Number(config.refreshMs || 45000),
  pollingBackoffMs: Number(config.refreshMs || 45000),
  maxBackoffMs: 5 * 60 * 1000,
};

const timelineEl = document.getElementById("timeline");
const eventsStateEl = document.getElementById("eventsState");
const statusMessageEl = document.getElementById("statusMessage");
const refreshButton = document.getElementById("refreshButton");
const kpiGrid = document.getElementById("kpiGrid");

const controls = {
  startDate: document.getElementById("startDate"),
  endDate: document.getElementById("endDate"),
  region: document.getElementById("regionFilter"),
  eventType: document.getElementById("eventTypeFilter"),
  severity: document.getElementById("severityFilter"),
};

function asDateOnly(value) {
  if (!value) return "";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "" : parsed.toISOString().slice(0, 10);
}

function sortedByDate(events) {
  return [...events].sort((a, b) => new Date(b.detectedAt).getTime() - new Date(a.detectedAt).getTime());
}

function formatDateTime(value) {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "Unknown date" : parsed.toLocaleString();
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function updateFilterOptions(events) {
  const regions = [...new Set(events.map((event) => event.region).filter(Boolean))].sort();
  const eventTypes = [...new Set(events.map((event) => event.eventType).filter(Boolean))].sort();
  const severities = ["critical", "high", "medium", "low"];

  setSelectOptions(controls.region, "All regions", regions);
  setSelectOptions(controls.eventType, "All event types", eventTypes);
  setSelectOptions(controls.severity, "All severities", severities);
}

function setSelectOptions(selectEl, defaultLabel, values) {
  const currentValue = selectEl.value;
  const options = [`<option value="">${escapeHtml(defaultLabel)}</option>`]
    .concat(values.map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`))
    .join("");
  selectEl.innerHTML = options;
  selectEl.value = currentValue;
}

function filterEvents(events) {
  return events.filter((event) => {
    const dateOnly = asDateOnly(event.detectedAt);

    if (state.filters.startDate && dateOnly && dateOnly < state.filters.startDate) return false;
    if (state.filters.endDate && dateOnly && dateOnly > state.filters.endDate) return false;
    if (state.filters.region && event.region !== state.filters.region) return false;
    if (state.filters.eventType && event.eventType !== state.filters.eventType) return false;
    if (state.filters.severity && event.severity !== state.filters.severity) return false;

    return true;
  });
}

function renderKpis(filteredEvents) {
  const softwareCount = filteredEvents.filter((event) => event.domain === "software").length;
  const ecologicalCount = filteredEvents.filter((event) => event.domain === "ecological").length;
  const criticalCount = filteredEvents.filter((event) => ["critical", "high"].includes(event.severity)).length;

  const latest = sortedByDate(filteredEvents)[0];
  const latestText = latest ? formatDateTime(latest.detectedAt) : "No events";

  const cards = [
    { label: "Total Events", value: String(filteredEvents.length) },
    { label: "Software Security Events", value: String(softwareCount) },
    { label: "Ecological / Health Events", value: String(ecologicalCount) },
    { label: "High/Critical Events", value: String(criticalCount) },
    { label: "Latest Event Time", value: latestText },
  ];

  kpiGrid.innerHTML = cards
    .map(
      (card) =>
        `<article class="kpi-card"><div class="kpi-label">${card.label}</div><div class="kpi-value">${card.value}</div></article>`
    )
    .join("");
}

function renderTimeline(filteredEvents) {
  if (filteredEvents.length === 0) {
    timelineEl.hidden = true;
    eventsStateEl.hidden = false;
    eventsStateEl.className = "state";
    eventsStateEl.textContent = "No events match the selected filters.";
    return;
  }

  timelineEl.hidden = false;
  eventsStateEl.hidden = true;

  timelineEl.innerHTML = sortedByDate(filteredEvents)
    .map(
      (event) => `
        <li class="event">
          <div class="event-meta">
            <span>${formatDateTime(event.detectedAt)}</span>
            <span>${escapeHtml(event.region || "Unknown region")}</span>
            <span>${escapeHtml(event.source || "Unknown source")}</span>
            <span class="pill severity-${escapeHtml(event.severity)}">${escapeHtml(event.severity)}</span>
            <span class="pill">${escapeHtml(event.domain)}</span>
            <span class="pill">${escapeHtml(event.eventType)}</span>
          </div>
          <h3 class="event-title">${escapeHtml(event.title)}</h3>
          <p>${escapeHtml(event.summary)}</p>
        </li>`
    )
    .join("");
}

function applyAndRender() {
  const filtered = filterEvents(state.events);
  renderKpis(filtered);
  renderTimeline(filtered);
}

function setStatus(message) {
  statusMessageEl.textContent = message;
}

function showErrorState(message) {
  timelineEl.hidden = true;
  eventsStateEl.hidden = false;
  eventsStateEl.className = "state error";
  eventsStateEl.textContent = message;
}

async function loadEvents() {
  setStatus("Loading events...");
  eventsStateEl.hidden = false;
  eventsStateEl.className = "state";
  eventsStateEl.textContent = "Loading events...";

  try {
    const { events, fromCache, endpoint } = await client.fetchLiveEvents();
    state.events = sortedByDate(events);
    updateFilterOptions(state.events);
    applyAndRender();

    state.pollingBackoffMs = state.pollingDelayMs;
    setStatus(
      fromCache
        ? "Showing cached MISTCODER data."
        : `Live data loaded from ${config.apiBaseUrl || "MISTCODER"}${endpoint || ""}.`
    );

    return true;
  } catch (error) {
    if (client.hasCache()) {
      state.events = sortedByDate(client.readCache());
      updateFilterOptions(state.events);
      applyAndRender();
      setStatus(`Live refresh failed (${error.message}). Showing cached data.`);
      return false;
    }

    state.events = sortedByDate(MOCK_EVENTS);
    updateFilterOptions(state.events);
    applyAndRender();

    if (config.apiBaseUrl) {
      setStatus(`API unavailable (${error.message}). Showing fallback mock data.`);
    } else {
      setStatus("MISTCODER API not configured. Showing fallback mock data.");
    }

    return false;
  }
}

function scheduleNextPoll(wasSuccess) {
  if (!wasSuccess) {
    state.pollingBackoffMs = Math.min(state.pollingBackoffMs * 2, state.maxBackoffMs);
  }

  window.setTimeout(async () => {
    const success = await loadEvents();
    scheduleNextPoll(success);
  }, state.pollingBackoffMs);
}

function attachFilterHandlers() {
  controls.startDate.addEventListener("change", (event) => {
    state.filters.startDate = event.target.value;
    applyAndRender();
  });

  controls.endDate.addEventListener("change", (event) => {
    state.filters.endDate = event.target.value;
    applyAndRender();
  });

  controls.region.addEventListener("change", (event) => {
    state.filters.region = event.target.value;
    applyAndRender();
  });

  controls.eventType.addEventListener("change", (event) => {
    state.filters.eventType = event.target.value;
    applyAndRender();
  });

  controls.severity.addEventListener("change", (event) => {
    state.filters.severity = event.target.value;
    applyAndRender();
  });

  refreshButton.addEventListener("click", async () => {
    client.resetCache();
    const success = await loadEvents();
    if (!success) {
      showErrorState("Live refresh failed. Using cached/mock data displayed below.");
      applyAndRender();
    }
  });
}

async function init() {
  attachFilterHandlers();
  const success = await loadEvents();
  scheduleNextPoll(success);
}

init().catch((error) => {
  showErrorState(`Dashboard failed to initialize: ${error.message}`);
  setStatus("Dashboard initialization error.");
});
