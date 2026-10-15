
const API_BASE_URL = "http://127.0.0.1:8000";

const state = {
    events: [],
    incidents: [],
    statistics: {}
};

async function apiRequest(endpoint, options = {}) {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
        ...options,
        headers: {
            "Content-Type": "application/json",
            ...(options.headers || {})
        }
    });

    if (!response.ok) {
        throw new Error(`API request failed: ${response.status}`);
    }

    return response.json();
}

/* THEME */

function setupTheme() {
    const savedTheme = localStorage.getItem("honeywatch-theme") || "dark";
    applyTheme(savedTheme);

    document.querySelectorAll(".theme-button").forEach(button => {
        button.addEventListener("click", () => {
            const theme = button.dataset.theme;
            applyTheme(theme);
            localStorage.setItem("honeywatch-theme", theme);
        });
    });
}

function applyTheme(theme) {
    document.body.classList.toggle("light-theme", theme === "light");

    document.querySelectorAll(".theme-button").forEach(button => {
        button.classList.toggle("active", button.dataset.theme === theme);
    });
}

/* DATA LOADING */

async function loadStatistics() {
    const data = await apiRequest("/statistics");
    state.statistics = data;

    updateStatistics(data);
    updateAttackDistribution(data.attack_distribution || []);
    updateSeverityDistribution(data.severity_distribution || []);
}

async function loadEvents() {
    const data = await apiRequest("/events");
    state.events = Array.isArray(data) ? data : (data.events || []);

    updateEventsTable(state.events);
    updateRecentActivity(state.events);
}

async function loadIncidents() {
    const data = await apiRequest("/incidents");
    state.incidents = Array.isArray(data) ? data : (data.incidents || []);

    updateIncidentTable(state.incidents);
    updateAllIncidentsTable(state.incidents);
    updateThreatSummary(state.incidents);
}

/* STATISTICS */

function updateStatistics(data) {
    setText("total-events", data.total_events || 0);
    setText("total-incidents", data.total_incidents || 0);
    setText("average-score", Math.round(Number(data.average_threat_score) || 0));
}

function setText(id, value) {
    const element = document.getElementById(id);
    if (element) element.textContent = value;
}

function updateAttackDistribution(items) {
    const container = document.getElementById("attack-distribution");
    if (!container) return;

    if (!items.length) {
        container.innerHTML = '<div class="empty-state">No attack data yet.</div>';
        return;
    }

    const total = items.reduce((sum, item) => sum + (Number(item.count) || 0), 0);

    container.innerHTML = items.map(item => {
        const count = Number(item.count) || 0;
        const percentage = total ? Math.round(count / total * 100) : 0;

        return `
            <div class="distribution-row">
                <div class="distribution-label">
                    <span>${escapeHtml(formatAttackType(item.attack_type))}</span>
                    <strong>${count}</strong>
                </div>
                <div class="distribution-bar">
                    <div class="distribution-fill" style="width: ${percentage}%"></div>
                </div>
            </div>
        `;
    }).join("");
}

function updateSeverityDistribution(items) {
    const container = document.getElementById("severity-distribution");
    if (!container) return;

    const counts = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };

    items.forEach(item => {
        const severity = String(item.severity || "").toUpperCase();
        if (Object.prototype.hasOwnProperty.call(counts, severity)) {
            counts[severity] = Number(item.count) || 0;
        }
    });

    const total = Object.values(counts).reduce((sum, value) => sum + value, 0);
    const score = Math.max(0, Math.min(Number(state.statistics.average_threat_score) || 0, 100));

    setText("threat-score", Math.round(score));
    setText("severity-total", `${total} incidents`);

    const ring = document.getElementById("threat-ring");
    if (ring) ring.style.setProperty("--score", score);

    container.innerHTML = Object.entries(counts).map(([severity, count]) => `
        <div class="severity-item">
            <span class="severity-dot ${severity.toLowerCase()}"></span>
            <span>${severity}</span>
            <strong>${count}</strong>
        </div>
    `).join("");
}

/* INCIDENT TABLES */
/* INCIDENT TABLES */

function incidentActionButtons(incident, showInvestigate = true) {
    const id = escapeHtml(String(incident.id));
    const isOpen = String(incident.status || "").toUpperCase() === "OPEN";

    const investigateButton = showInvestigate
        ? `
            <button type="button" class="incident-action-button"
                data-investigate-id="${id}">Investigate</button>
        `
        : "";

    return `
        ${investigateButton}
        ${isOpen ? `
            <button type="button" class="incident-action-button"
                data-close-incident-id="${id}">Close</button>
        ` : '<span class="incident-closed">Closed</span>'}
    `;
}

function updateIncidentTable(incidents) {
    const body = document.getElementById("incident-table-body");
    if (!body) return;

    if (!incidents.length) {
        body.innerHTML = '<tr><td colspan="8" class="table-empty">No incidents recorded.</td></tr>';
        return;
    }

    body.innerHTML = incidents.slice(0, 10).map(incident => `
        <tr>
            <td>#${escapeHtml(String(incident.id))}</td>
            <td>${escapeHtml(incident.source_ip || "Unknown")}</td>
            <td>${escapeHtml(formatAttackType(incident.attack_type))}</td>
            <td><span class="severity-badge">${escapeHtml(incident.severity || "-")}</span></td>
            <td><strong>${Number(incident.threat_score) || 0}</strong></td>
            <td>${escapeHtml(formatDateTime(incident.start_time))}</td>
            <td><span class="status-badge">${escapeHtml(incident.status || "-")}</span></td>
            <td>${incidentActionButtons(incident)}</td>
        </tr>
    `).join("");
}

function updateAllIncidentsTable(incidents) {
    const body = document.getElementById("all-incidents-body");
    if (!body) return;

    if (!incidents.length) {
        body.innerHTML = '<tr><td colspan="8" class="table-empty">No incidents recorded.</td></tr>';
        return;
    }

    body.innerHTML = incidents.map(incident => `
        <tr>
            <td>#${escapeHtml(String(incident.id))}</td>
            <td>${escapeHtml(incident.source_ip || "Unknown")}</td>
            <td>${escapeHtml(formatDateTime(incident.start_time))}</td>
            <td>${escapeHtml(formatAttackType(incident.attack_type))}</td>
            <td><span class="severity-badge">${escapeHtml(incident.severity || "-")}</span></td>
            <td><strong>${Number(incident.threat_score) || 0}</strong></td>
            <td><span class="status-badge">${escapeHtml(incident.status || "-")}</span></td>
            <td>${incidentActionButtons(incident, false)}</td>
        </tr>
    `).join("");
}

/* INCIDENT INVESTIGATION */
function setupIncidentActions() {
    document.addEventListener("click", async event => {
        const target = event.target;

        if (!(target instanceof Element)) {
            return;
        }

        const investigateButton = target.closest("[data-investigate-id]");

        if (investigateButton) {
            event.preventDefault();

            const incidentId = investigateButton.dataset.investigateId;
            showIncidentGuidance(incidentId);
            return;
        }

        const closeButton = target.closest("[data-close-incident-id]");

        if (closeButton) {
            event.preventDefault();

            await closeIncident(
                closeButton.dataset.closeIncidentId,
                closeButton
            );
        }
    }, true);
}

function showIncidentGuidance(id) {
    const incident = state.incidents.find(item => String(item.id) === String(id));

    if (!incident) {
        showToast("Incident not found. Refresh and try again.", "error");
        return;
    }

    navigateToSection("incidents");

    const section = document.getElementById("incidents");
    if (!section) return;

    let panel = document.getElementById("incident-guidance-panel");

    if (!panel) {
        panel = document.createElement("article");
        panel.id = "incident-guidance-panel";
        panel.className = "panel incident-guidance-panel";
        section.insertBefore(panel, section.firstElementChild.nextElementSibling);
    }

    const guidance = getInvestigationGuidance(incident.attack_type);

    panel.innerHTML = `
        <div class="panel-header">
            <div>
                <h3>Investigation Guide — #${escapeHtml(String(incident.id))}</h3>
                <p>Review the incident details and recommended checks.</p>
            </div>
            <button type="button" id="close-guidance-panel" class="text-button">Close ✕</button>
        </div>

        <div class="incident-guidance-details">
            <div><span>Source IP</span><strong>${escapeHtml(incident.source_ip || "Unknown")}</strong></div>
            <div><span>Attack Type</span><strong>${escapeHtml(formatAttackType(incident.attack_type))}</strong></div>
            <div><span>Severity</span><strong>${escapeHtml(incident.severity || "Unknown")}</strong></div>
            <div><span>Threat Score</span><strong>${Number(incident.threat_score) || 0}/100</strong></div>
            <div><span>Status</span><strong>${escapeHtml(incident.status || "Unknown")}</strong></div>
            <div><span>Start Time</span><strong>${escapeHtml(formatDateTime(incident.start_time))}</strong></div>
        </div>

        <div class="incident-guidance-content">
            <h4>What this detection may indicate</h4>
            <p>${escapeHtml(guidance.description)}</p>
            <h4>Recommended investigation steps</h4>
            <ol>${guidance.steps.map(step => `<li>${escapeHtml(step)}</li>`).join("")}</ol>
            <h4>Suggested response</h4>
            <p>${escapeHtml(guidance.response)}</p>
            <p class="guidance-note">This is advisory guidance for simulated or local honeypot activity. Verify event evidence before taking action.</p>
        </div>
    `;

    document.getElementById("close-guidance-panel").addEventListener("click", () => panel.remove());
    panel.scrollIntoView({ behavior: "smooth", block: "start" });
}

function getInvestigationGuidance(attackType) {
    const type = String(attackType || "").toLowerCase();

    if (type.includes("brute") || type.includes("login") || type.includes("auth")) {
        return {
            description: "Repeated authentication attempts may indicate password guessing.",
            steps: [
                "Review repeated login failures from the source IP.",
                "Check timestamps and the affected service.",
                "Look for any successful login after the failures.",
                "Compare activity with your configured detection threshold."
            ],
            response: "Verify the evidence and follow your incident-response policy."
        };
    }

    if (type.includes("scan") || type.includes("port")) {
        return {
            description: "Requests to multiple ports or services may indicate service discovery.",
            steps: [
                "Review events associated with the source IP.",
                "Identify the ports or services contacted.",
                "Check event timing and frequency.",
                "Compare activity with your port-scan detection rule."
            ],
            response: "Document the targeted services and verify whether the activity is expected."
        };
    }

    if (type.includes("dos") || type.includes("traffic") || type.includes("http")) {
        return {
            description: "Unusual request volume may indicate automated or abnormal traffic.",
            steps: [
                "Review event timestamps and request frequency.",
                "Identify the receiving service.",
                "Check whether events share a source IP.",
                "Compare activity with your traffic detection threshold."
            ],
            response: "Record the observed pattern and verify it before taking action."
        };
    }

    return {
        description: "HoneyWatch classified this event as a security incident. Review the associated events to understand why.",
        steps: [
            "Review the source IP, attack type, severity, and score.",
            "Open Activity Monitor and inspect related events.",
            "Check the affected service and event timestamps.",
            "Compare the evidence with the applicable detection rule."
        ],
        response: "Validate the evidence and record your findings before deciding on a response."
    };
}

/* CLOSE INCIDENT */

async function closeIncident(id, button) {
    try {
        button.disabled = true;
        button.textContent = "Closing...";

        const result = await apiRequest(`/incidents/${encodeURIComponent(id)}/close`, {
            method: "PATCH"
        });

        if (result && result.success === false) {
            throw new Error(result.message || "Unable to close incident.");
        }

        showToast(`Incident #${id} closed successfully.`);
        await refreshDashboard();
    } catch (error) {
        console.error("Close incident failed:", error);
        button.disabled = false;
        button.textContent = "Close";
        showToast("Failed to close incident.", "error");
    }
}

/* EVENTS AND ACTIVITY */

function updateEventsTable(events) {
    const body = document.getElementById("events-table-body");
    if (!body) return;

    if (!events.length) {
        body.innerHTML = '<tr><td colspan="6" class="table-empty">No events recorded.</td></tr>';
        return;
    }

    body.innerHTML = events.map(event => `
        <tr>
            <td>#${escapeHtml(String(event.id ?? ""))}</td>
            <td>${escapeHtml(formatDateTime(event.timestamp))}</td>
            <td>${escapeHtml(event.source_ip || "Unknown")}</td>
            <td>${escapeHtml(event.service || "-")}</td>
            <td>${escapeHtml(formatEventType(event.event_type))}</td>
            <td>${escapeHtml(event.details || "-")}</td>
        </tr>
    `).join("");
}

function updateRecentActivity(events) {
    const container = document.getElementById("recent-activity");
    if (!container) return;

    const recent = events.slice(0, 6);

    if (!recent.length) {
        container.innerHTML = '<div class="empty-state">No recent activity.</div>';
        return;
    }

    container.innerHTML = recent.map(event => `
        <div class="activity-item">
            <div class="activity-marker"></div>
            <div class="activity-content">
                <strong>${escapeHtml(formatEventType(event.event_type))}</strong>
                <span>${escapeHtml(event.source_ip || "Unknown")} → ${escapeHtml(event.service || "Unknown")}</span>
                <small>${escapeHtml(formatDateTime(event.timestamp))}</small>
            </div>
        </div>
    `).join("");
}

/* THREAT SUMMARY */

function updateThreatSummary(incidents) {
    const highest = incidents.length
        ? Math.max(...incidents.map(item => Number(item.threat_score) || 0))
        : 0;

    setText("highest-threat-score", highest);

    const label = document.getElementById("threat-label");
    if (!label) return;

    if (!incidents.length) {
        label.textContent = "No active threats";
        return;
    }

    const score = Number(state.statistics.average_threat_score) || 0;

    if (score >= 80) label.textContent = "Critical threat level";
    else if (score >= 60) label.textContent = "High threat level";
    else if (score >= 40) label.textContent = "Medium threat level";
    else label.textContent = "Low threat level";
}

/* DETECTION AND SIMULATION */

async function runDetection() {
    try {
        showToast("Running attack detection...");
        const result = await apiRequest("/detect", { method: "POST" });
        showToast(`Detection completed: ${Number(result.count) || 0} incident(s) processed.`);
        await refreshDashboard();
    } catch (error) {
        console.error("Detection failed:", error);
        showToast("Detection failed. Check that the backend is running.", "error");
    }
}

async function runSimulation() {
    try {
        showToast("Generating simulated activity...");
        await apiRequest("/simulate", { method: "POST" });
        showToast("Simulation completed successfully.");
        await refreshDashboard();
    } catch (error) {
        console.error("Simulation failed:", error);
        showToast("Simulation failed. Check that the backend is running.", "error");
    }
}

/* REFRESH */

async function refreshDashboard() {
    try {
        await Promise.all([loadStatistics(), loadEvents(), loadIncidents()]);
        updateLastUpdatedTime();
        updateSystemStatus("ONLINE");
    } catch (error) {
        console.error("Dashboard refresh failed:", error);
        updateSystemStatus("OFFLINE");
        showToast("Unable to connect to HoneyWatch backend.", "error");
    }
}

function updateLastUpdatedTime() {
    setText("last-updated", new Date().toLocaleTimeString());
}

function updateSystemStatus(status) {
    document.querySelectorAll(".system-status").forEach(element => {
        const strong = element.querySelector("strong");
        if (strong) {
            strong.textContent = status === "ONLINE" ? "System Operational" : "System Offline";
        }
        element.classList.toggle("offline", status !== "ONLINE");
    });
}

/* NAVIGATION */

function navigateToSection(target) {
    const section = document.getElementById(target);
    if (!section) return;

    document.querySelectorAll(".page-section").forEach(item => {
        item.classList.toggle("active", item.id === target);
    });

    document.querySelectorAll(".nav-item[data-section]").forEach(item => {
        item.classList.toggle("active", item.dataset.section === target);
    });

    const titles = {
        overview: "Security Overview",
        activity: "Activity Monitor",
        incidents: "Security Incidents",
        services: "Monitored Services",
        rules: "Detection Rules",
        settings: "Settings"
    };

    setText("page-title", titles[target] || "HoneyWatch");
    setText("heading-title", titles[target] || "HoneyWatch");

    const breadcrumb = document.querySelector(".breadcrumb strong");
    if (breadcrumb) breadcrumb.textContent = titles[target] || target;
}

function setupNavigation() {
    document.querySelectorAll(".nav-item[data-section]").forEach(item => {
        item.addEventListener("click", () => navigateToSection(item.dataset.section));
    });

    document.querySelectorAll("[data-section-link]").forEach(link => {
        link.addEventListener("click", () => navigateToSection(link.dataset.sectionLink));
    });
}

/* FORMATTING */

function formatAttackType(value) {
    return String(value || "")
        .replace(/_/g, " ")
        .toLowerCase()
        .replace(/\b\w/g, character => character.toUpperCase());
}

function formatEventType(value) {
    return formatAttackType(value);
}

function formatDateTime(value) {
    if (!value) return "-";

    const date = new Date(String(value).replace(" ", "T"));
    return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

function escapeHtml(value) {
    return String(value == null ? "" : value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

/* TOAST */

function showToast(message, type = "success") {
    const toast = document.getElementById("toast");
    if (!toast) return;

    toast.textContent = message;
    toast.className = "toast";

    if (type === "error") toast.classList.add("error");
    toast.classList.add("show");

    setTimeout(() => toast.classList.remove("show"), 3000);
}

/* START APPLICATION */

document.addEventListener("DOMContentLoaded", () => {
    setupNavigation();
    setupTheme();
    setupIncidentActions();

    const detectionButton = document.getElementById("run-detection");
    if (detectionButton) detectionButton.addEventListener("click", runDetection);

    const simulationButton = document.getElementById("run-simulation");
    if (simulationButton) simulationButton.addEventListener("click", runSimulation);

    const refreshButton = document.getElementById("refresh-button");
    if (refreshButton) refreshButton.addEventListener("click", refreshDashboard);

    refreshDashboard();
    setInterval(refreshDashboard, 10000);
});
