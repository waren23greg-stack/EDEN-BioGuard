const DEFAULT_TIMEOUT_MS = 10000;
const DEFAULT_CACHE_TTL_MS = 30000;

const SOFTWARE_TYPES = ["vulnerability", "threat_alert", "cve", "security", "software_security"];
const ECOLOGICAL_TYPES = ["outbreak", "ndvi", "land_indicator", "field_incident", "ecological", "health"];

function safeDate(value) {
  const date = value ? new Date(value) : null;
  return date && !Number.isNaN(date.getTime()) ? date.toISOString() : null;
}

function inferDomain(typeValue = "") {
  const normalized = String(typeValue).toLowerCase();
  if (SOFTWARE_TYPES.some((item) => normalized.includes(item))) {
    return "software";
  }
  if (ECOLOGICAL_TYPES.some((item) => normalized.includes(item))) {
    return "ecological";
  }
  return "ecological";
}

function normalizeSeverity(raw = "") {
  const severity = String(raw || "medium").toLowerCase();
  if (["critical", "high", "medium", "low"].includes(severity)) {
    return severity;
  }
  if (["severe", "urgent"].includes(severity)) {
    return "high";
  }
  if (["moderate", "warning"].includes(severity)) {
    return "medium";
  }
  return "low";
}

function normalizeEvent(event, index = 0) {
  const eventType = String(event.eventType || event.type || event.category || "field_incident").toLowerCase();
  const detectedAt =
    safeDate(event.detectedAt || event.timestamp || event.occurredAt || event.date || event.createdAt) ||
    new Date().toISOString();

  return {
    id: String(event.id || event.eventId || `mock-${index}`),
    domain: inferDomain(eventType),
    eventType,
    severity: normalizeSeverity(event.severity || event.riskLevel || event.priority),
    title: event.title || event.name || "Unnamed event",
    summary: event.summary || event.description || "No summary provided.",
    region: event.region || event.county || event.locationName || "Unknown",
    county: event.county || event.region || null,
    source: event.source || event.sourceName || "MISTCODER",
    latitude: Number(event.latitude ?? event.lat ?? event.location_lat ?? NaN),
    longitude: Number(event.longitude ?? event.lon ?? event.location_lon ?? NaN),
    detectedAt,
  };
}

function ensureArray(payload) {
  if (Array.isArray(payload)) {
    return payload;
  }

  if (Array.isArray(payload?.events)) {
    return payload.events;
  }

  if (Array.isArray(payload?.data)) {
    return payload.data;
  }

  if (Array.isArray(payload?.items)) {
    return payload.items;
  }

  return [];
}

async function fetchWithTimeout(url, timeoutMs) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, { signal: controller.signal });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    return await response.json();
  } finally {
    clearTimeout(timeout);
  }
}

export function createMistcoderClient(options = {}) {
  const baseUrl = String(options.baseUrl || "").trim().replace(/\/$/, "");
  const timeoutMs = Number(options.timeoutMs || DEFAULT_TIMEOUT_MS);
  const cacheTtlMs = Number(options.cacheTtlMs || DEFAULT_CACHE_TTL_MS);

  let cache = { expiresAt: 0, events: [] };

  const endpointPaths = [
    "/api/v1/dashboard/events",
    "/api/v1/events",
    "/api/events",
    "/events",
  ];

  async function fetchLiveEvents() {
    if (!baseUrl) {
      throw new Error("MISTCODER base URL is not configured");
    }

    const now = Date.now();
    if (cache.expiresAt > now && cache.events.length > 0) {
      return { events: cache.events, fromCache: true };
    }

    let lastError = null;
    for (const path of endpointPaths) {
      const url = `${baseUrl}${path}`;
      try {
        const payload = await fetchWithTimeout(url, timeoutMs);
        const events = ensureArray(payload).map(normalizeEvent);
        if (events.length === 0) {
          continue;
        }

        cache = {
          events,
          expiresAt: Date.now() + cacheTtlMs,
        };

        return { events, fromCache: false, endpoint: path };
      } catch (error) {
        lastError = error;
      }
    }

    throw lastError || new Error("No MISTCODER endpoints returned usable event data");
  }

  return {
    fetchLiveEvents,
    normalizeEvent,
    hasCache: () => cache.events.length > 0,
    readCache: () => cache.events,
    resetCache: () => {
      cache = { expiresAt: 0, events: [] };
    },
  };
}
