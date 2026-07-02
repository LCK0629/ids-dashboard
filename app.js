const initialAlerts = [
  {
    id: "AL-1001",
    timestamp: "09:12:44",
    severity: "Critical",
    sourceIp: "185.23.44.91",
    destinationIp: "10.0.0.15",
    protocol: "TCP",
    port: 22,
    attackType: "SSH Brute Force",
    confidence: 94,
    baseRiskScore: 92,
    status: "Unreviewed",
    feedback: null,
    similarityKey: "auth-ssh-bruteforce",
    triggerReason:
      "Multiple failed SSH login attempts were detected from the same external IP within a short time window.",
    riskFactors: [
      "Repeated authentication failures",
      "External source IP",
      "Targeting SSH port 22",
      "High confidence signature match",
    ],
    evidence:
      "Source IP 185.23.44.91 attempted 42 SSH logins against 10.0.0.15 in 3 minutes.",
    recommendedAction:
      "Review authentication logs, check whether any login succeeded, and block the source IP if malicious.",
  },
  {
    id: "AL-1002",
    timestamp: "09:18:03",
    severity: "High",
    sourceIp: "185.23.44.91",
    destinationIp: "10.0.0.16",
    protocol: "TCP",
    port: 22,
    attackType: "SSH Brute Force",
    confidence: 87,
    baseRiskScore: 83,
    status: "Unreviewed",
    feedback: null,
    similarityKey: "auth-ssh-bruteforce",
    triggerReason:
      "The same external IP continued authentication attempts against another internal server.",
    riskFactors: [
      "Repeated source IP",
      "Lateral targeting pattern",
      "Authentication failure spike",
    ],
    evidence:
      "31 failed SSH attempts were observed from 185.23.44.91 to 10.0.0.16 after the first alert.",
    recommendedAction:
      "Correlate this alert with AL-1001 and review whether the source should be blocked at the perimeter.",
  },
  {
    id: "AL-1003",
    timestamp: "09:25:17",
    severity: "Critical",
    sourceIp: "203.0.113.45",
    destinationIp: "10.0.1.23",
    protocol: "HTTP",
    port: 80,
    attackType: "SQL Injection",
    confidence: 91,
    baseRiskScore: 89,
    status: "Unreviewed",
    feedback: null,
    similarityKey: "web-sql-injection",
    triggerReason:
      "HTTP query parameters matched a SQL injection signature with encoded union-select payloads.",
    riskFactors: [
      "Known SQL injection signature",
      "Public-facing web service",
      "Repeated payload variations",
      "Database error response observed",
    ],
    evidence:
      "12 requests contained 'UNION SELECT' patterns and triggered abnormal 500 responses from 10.0.1.23.",
    recommendedAction:
      "Inspect web server logs, verify input validation, and check database access logs for unauthorized queries.",
  },
  {
    id: "AL-1004",
    timestamp: "09:33:52",
    severity: "Medium",
    sourceIp: "10.0.2.18",
    destinationIp: "10.0.1.23",
    protocol: "HTTP",
    port: 443,
    attackType: "SQL Injection",
    confidence: 63,
    baseRiskScore: 58,
    status: "Unreviewed",
    feedback: null,
    similarityKey: "web-sql-injection",
    triggerReason:
      "A low-volume request pattern resembled SQL injection testing, but the traffic originated internally.",
    riskFactors: [
      "Suspicious query syntax",
      "Internal source host",
      "Lower confidence match",
    ],
    evidence:
      "4 internal HTTPS requests contained quote-based probing strings against the customer search endpoint.",
    recommendedAction:
      "Confirm whether this source belongs to QA testing or a vulnerability scanner before escalating.",
  },
  {
    id: "AL-1005",
    timestamp: "09:41:06",
    severity: "High",
    sourceIp: "91.240.118.77",
    destinationIp: "10.0.0.22",
    protocol: "TCP",
    port: 445,
    attackType: "SMB Scan",
    confidence: 88,
    baseRiskScore: 81,
    status: "Unreviewed",
    feedback: null,
    similarityKey: "smb-recon",
    triggerReason:
      "Rapid connection attempts to SMB services indicate reconnaissance against file sharing systems.",
    riskFactors: [
      "External source",
      "Targeting SMB port 445",
      "Short burst of connection attempts",
    ],
    evidence:
      "The source attempted 67 TCP connections to SMB-enabled hosts in under 2 minutes.",
    recommendedAction:
      "Check firewall exposure for SMB services and review whether the destination accepted any session.",
  },
  {
    id: "AL-1006",
    timestamp: "09:49:31",
    severity: "Medium",
    sourceIp: "10.0.3.40",
    destinationIp: "10.0.0.22",
    protocol: "TCP",
    port: 445,
    attackType: "SMB Scan",
    confidence: 57,
    baseRiskScore: 52,
    status: "Unreviewed",
    feedback: null,
    similarityKey: "smb-recon",
    triggerReason:
      "Internal SMB enumeration behavior was detected, which may be legitimate administration or reconnaissance.",
    riskFactors: [
      "Internal source",
      "SMB enumeration",
      "Moderate confidence",
    ],
    evidence:
      "Host 10.0.3.40 queried 19 SMB shares across finance file servers.",
    recommendedAction:
      "Verify whether the host is an approved admin workstation or scheduled asset inventory tool.",
  },
  {
    id: "AL-1007",
    timestamp: "10:03:10",
    severity: "Critical",
    sourceIp: "198.51.100.9",
    destinationIp: "10.0.4.11",
    protocol: "HTTPS",
    port: 443,
    attackType: "Data Exfiltration",
    confidence: 82,
    baseRiskScore: 90,
    status: "Unreviewed",
    feedback: null,
    similarityKey: "data-egress-anomaly",
    triggerReason:
      "Outbound traffic volume exceeded the normal baseline for this host and used a rare external destination.",
    riskFactors: [
      "Large outbound transfer",
      "Rare destination",
      "Outside normal working pattern",
      "Sensitive subnet source",
    ],
    evidence:
      "10.0.4.11 transferred 3.8 GB to 198.51.100.9 over HTTPS within 11 minutes.",
    recommendedAction:
      "Validate the destination, inspect endpoint activity, and isolate the host if the transfer is unauthorized.",
  },
  {
    id: "AL-1008",
    timestamp: "10:08:38",
    severity: "High",
    sourceIp: "10.0.4.11",
    destinationIp: "198.51.100.9",
    protocol: "DNS",
    port: 53,
    attackType: "DNS Tunneling",
    confidence: 76,
    baseRiskScore: 78,
    status: "Unreviewed",
    feedback: null,
    similarityKey: "data-egress-anomaly",
    triggerReason:
      "DNS queries contained unusually long subdomains and high entropy strings consistent with tunneling.",
    riskFactors: [
      "High entropy DNS labels",
      "Large number of queries",
      "Same host as exfiltration anomaly",
    ],
    evidence:
      "Host 10.0.4.11 generated 486 DNS queries with labels longer than 50 characters.",
    recommendedAction:
      "Review DNS logs, block the suspicious domain, and correlate with endpoint process activity.",
  },
  {
    id: "AL-1009",
    timestamp: "10:16:22",
    severity: "Low",
    sourceIp: "10.0.5.20",
    destinationIp: "10.0.6.25",
    protocol: "ICMP",
    port: 0,
    attackType: "Ping Sweep",
    confidence: 49,
    baseRiskScore: 38,
    status: "Unreviewed",
    feedback: null,
    similarityKey: "icmp-discovery",
    triggerReason:
      "A host sent ICMP probes to several internal addresses, which may indicate discovery activity.",
    riskFactors: ["Internal source", "Low confidence", "Limited target range"],
    evidence:
      "10.0.5.20 sent ICMP probes to 14 hosts in the engineering subnet.",
    recommendedAction:
      "Confirm whether the activity belongs to approved network monitoring before taking action.",
  },
  {
    id: "AL-1010",
    timestamp: "10:20:11",
    severity: "Medium",
    sourceIp: "172.16.8.14",
    destinationIp: "10.0.7.31",
    protocol: "RDP",
    port: 3389,
    attackType: "RDP Login Anomaly",
    confidence: 69,
    baseRiskScore: 64,
    status: "Unreviewed",
    feedback: null,
    similarityKey: "rdp-login-anomaly",
    triggerReason:
      "An RDP login occurred from an unusual subnet for the user account and outside its normal login window.",
    riskFactors: [
      "Unusual source subnet",
      "Administrative protocol",
      "Out-of-hours login",
    ],
    evidence:
      "Account svc-backup initiated RDP to 10.0.7.31 at 10:20 from a subnet not seen in the last 30 days.",
    recommendedAction:
      "Validate the user session, check MFA logs, and confirm whether the account activity is expected.",
  },
  {
    id: "AL-1011",
    timestamp: "10:27:04",
    severity: "High",
    sourceIp: "45.133.1.12",
    destinationIp: "10.0.8.44",
    protocol: "HTTP",
    port: 8080,
    attackType: "Command Injection",
    confidence: 84,
    baseRiskScore: 86,
    status: "Unreviewed",
    feedback: null,
    similarityKey: "web-command-injection",
    triggerReason:
      "Request payload matched command injection patterns using shell metacharacters and system commands.",
    riskFactors: [
      "Known exploit pattern",
      "Public service",
      "Suspicious shell command payload",
    ],
    evidence:
      "The request included '; cat /etc/passwd' and triggered an application error response.",
    recommendedAction:
      "Review application logs, validate WAF rules, and check whether the command executed on the server.",
  },
  {
    id: "AL-1012",
    timestamp: "10:35:49",
    severity: "Medium",
    sourceIp: "10.0.9.19",
    destinationIp: "10.0.8.44",
    protocol: "HTTP",
    port: 8080,
    attackType: "Command Injection",
    confidence: 61,
    baseRiskScore: 56,
    status: "Unreviewed",
    feedback: null,
    similarityKey: "web-command-injection",
    triggerReason:
      "Internal testing traffic resembled command injection payloads but did not produce a successful response.",
    riskFactors: [
      "Command-like input",
      "Internal source host",
      "No success indicator",
    ],
    evidence:
      "Two requests from 10.0.9.19 contained shell metacharacters during a staging validation window.",
    recommendedAction:
      "Check whether this source is part of a security test or developer validation before escalation.",
  },
];

const severityColors = {
  Critical: "var(--red)",
  High: "var(--amber)",
  Medium: "var(--blue)",
  Low: "var(--green)",
};

let alerts = structuredClone(initialAlerts);
let selectedAlertId = alerts[0].id;
let lastImpact = "Waiting for analyst feedback";
let currentView = "operations";

const byId = (id) => document.getElementById(id);
const clamp = (value, min, max) => Math.min(max, Math.max(min, value));
const selectedAlert = () => alerts.find((alert) => alert.id === selectedAlertId) || alerts[0];

function riskColor(score) {
  if (score >= 85) return "var(--red)";
  if (score >= 70) return "var(--amber)";
  if (score >= 50) return "var(--blue)";
  return "var(--green)";
}

function scoreFor(alert) {
  return alert.riskScore ?? alert.baseRiskScore;
}

function similarAlerts(alert) {
  return alerts.filter(
    (item) => item.similarityKey === alert.similarityKey && item.id !== alert.id,
  );
}

function statusForFeedback(feedback) {
  return {
    truePositive: "Confirmed Threat",
    falsePositive: "False Positive",
    suspicious: "Under Review",
    benign: "Benign",
  }[feedback];
}

function feedbackLabel(feedback) {
  return {
    truePositive: "True Positive",
    falsePositive: "False Positive",
    suspicious: "Suspicious",
    benign: "Benign",
  }[feedback];
}

function applyFeedback(alertId, feedback) {
  const target = alerts.find((alert) => alert.id === alertId);
  if (!target) return;

  const selectedDelta = {
    truePositive: 8,
    falsePositive: -18,
    suspicious: 2,
    benign: -28,
  }[feedback];

  const similarDelta = {
    truePositive: 6,
    falsePositive: -12,
    suspicious: 1,
    benign: -15,
  }[feedback];

  let adjustedSimilar = 0;
  alerts = alerts.map((alert) => {
    if (alert.id === alertId) {
      return {
        ...alert,
        feedback,
        status: statusForFeedback(feedback),
        riskScore: clamp(scoreFor(alert) + selectedDelta, 5, 99),
      };
    }

    if (alert.similarityKey === target.similarityKey) {
      adjustedSimilar += 1;
      return {
        ...alert,
        riskScore: clamp(scoreFor(alert) + similarDelta, 5, 99),
        learnedInfluence: `${feedbackLabel(feedback)} feedback from ${target.id}`,
      };
    }

    return alert;
  });

  lastImpact = `Adjusted ${adjustedSimilar} similar alerts based on ${feedbackLabel(feedback)} feedback`;
  render();
}

function filteredAlerts() {
  const severity = byId("severityFilter").value;
  const status = byId("statusFilter").value;

  return alerts
    .filter((alert) => severity === "all" || alert.severity === severity)
    .filter((alert) => status === "all" || alert.status === status)
    .sort((a, b) => scoreFor(b) - scoreFor(a));
}

function renderKpis() {
  const reviewed = alerts.filter((alert) => alert.feedback).length;
  const critical = alerts.filter((alert) => scoreFor(alert) >= 85).length;
  const falsePositive = alerts.filter((alert) => alert.status === "False Positive").length;
  const averageRisk = Math.round(
    alerts.reduce((sum, alert) => sum + scoreFor(alert), 0) / alerts.length,
  );
  const noiseReduction = Math.round(
    alerts.reduce((sum, alert) => sum + Math.max(0, alert.baseRiskScore - scoreFor(alert)), 0) /
      alerts.length,
  );

  byId("kpiGrid").innerHTML = [
    ["Total Alerts", alerts.length, "Hardcoded IDS events"],
    ["Critical Queue", critical, "Score 85 or above"],
    ["Reviewed", reviewed, "Analyst feedback submitted"],
    ["False Positives", falsePositive, "Marked by analyst"],
    ["Noise Reduction", `${noiseReduction}%`, `Average risk ${averageRisk}`],
  ]
    .map(
      ([label, value, note]) => `
        <article class="kpi-card">
          <span>${label}</span>
          <strong>${value}</strong>
          <p>${note}</p>
        </article>
      `,
    )
    .join("");

  byId("criticalCount").textContent = `${critical} critical`;
  byId("feedbackCount").textContent = `${reviewed} reviewed`;
  byId("modelConfidence").textContent = `${84 + Math.min(10, reviewed * 2)}%`;
  byId("impactMessage").textContent = lastImpact;
}

function countBy(items, key) {
  return items.reduce((counts, item) => {
    const value = typeof key === "function" ? key(item) : item[key];
    counts[value] = (counts[value] || 0) + 1;
    return counts;
  }, {});
}

function metrics() {
  const reviewed = alerts.filter((alert) => alert.feedback).length;
  const confirmed = alerts.filter((alert) => alert.status === "Confirmed Threat").length;
  const falsePositive = alerts.filter((alert) => alert.status === "False Positive").length;
  const underReview = alerts.filter((alert) => alert.status === "Under Review").length;
  const benign = alerts.filter((alert) => alert.status === "Benign").length;
  const critical = alerts.filter((alert) => scoreFor(alert) >= 85).length;
  const noiseReduction = Math.round(
    alerts.reduce((sum, alert) => sum + Math.max(0, alert.baseRiskScore - scoreFor(alert)), 0) /
      alerts.length,
  );
  return { reviewed, confirmed, falsePositive, underReview, benign, critical, noiseReduction };
}

function renderBarChart(elementId, data, colorFor) {
  const max = Math.max(1, ...data.map((item) => item.value));
  byId(elementId).innerHTML = data
    .map(
      (item) => `
        <div class="bar-row">
          <span>${item.label}</span>
          <div class="bar-track">
            <div class="bar-fill" style="width:${(item.value / max) * 100}%; background:${colorFor(
              item.label,
            )}"></div>
          </div>
          <strong>${item.value}</strong>
        </div>
      `,
    )
    .join("");
}

function renderCharts() {
  const severityCounts = countBy(alerts, "severity");
  const severityData = ["Critical", "High", "Medium", "Low"].map((label) => ({
    label,
    value: severityCounts[label] || 0,
  }));

  renderBarChart("severityChart", severityData, (label) => severityColors[label]);

  const categoryCounts = countBy(alerts, "attackType");
  const categoryData = Object.entries(categoryCounts)
    .map(([label, value]) => ({ label, value }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 5);
  byId("categoryCount").textContent = `${Object.keys(categoryCounts).length} types`;
  renderBarChart("categoryChart", categoryData, () => "var(--cyan)");

  const feedbackCounts = {
    "True Positive": alerts.filter((alert) => alert.feedback === "truePositive").length,
    "False Positive": alerts.filter((alert) => alert.feedback === "falsePositive").length,
    Suspicious: alerts.filter((alert) => alert.feedback === "suspicious").length,
    Benign: alerts.filter((alert) => alert.feedback === "benign").length,
  };
  const max = Math.max(1, ...Object.values(feedbackCounts));
  byId("feedbackChart").innerHTML = Object.entries(feedbackCounts)
    .map(
      ([label, value]) => `
        <div class="impact-column">
          <div class="bar" style="height:${18 + (value / max) * 92}px"></div>
          <strong>${value}</strong>
          <span>${label}</span>
        </div>
      `,
    )
    .join("");
}

function renderRows() {
  const rows = filteredAlerts();
  byId("alertRows").innerHTML = rows
    .map((alert) => {
      const score = scoreFor(alert);
      const severityClass = alert.severity.toLowerCase();
      return `
        <tr class="${alert.id === selectedAlertId ? "selected" : ""}" data-alert-id="${alert.id}">
          <td>${alert.timestamp}</td>
          <td><span class="badge ${severityClass}">${alert.severity}</span></td>
          <td>${alert.attackType}</td>
          <td>${alert.sourceIp}</td>
          <td>${alert.destinationIp}:${alert.port}</td>
          <td>
            <div class="risk-meter">
              <span class="risk-score" style="color:${riskColor(score)}">${score}</span>
              <div class="risk-line"><span style="width:${score}%; background:${riskColor(score)}"></span></div>
            </div>
          </td>
          <td class="reason-cell">${alert.triggerReason}</td>
          <td><span class="status">${alert.status}</span></td>
        </tr>
      `;
    })
    .join("");

  document.querySelectorAll("[data-alert-id]").forEach((row) => {
    row.addEventListener("click", () => {
      selectedAlertId = row.dataset.alertId;
      render();
    });
  });
}

function renderDetail() {
  const alert = selectedAlert();
  const score = scoreFor(alert);
  const similar = similarAlerts(alert);
  const feedbackInfluence = alert.feedback
    ? `<p><strong>Feedback influence:</strong> Analyst marked this alert as ${feedbackLabel(
        alert.feedback,
      )}, so the adaptive model recalculated its risk score.</p>`
    : alert.learnedInfluence
      ? `<p><strong>Feedback influence:</strong> ${alert.learnedInfluence} adjusted this alert's risk score.</p>`
      : "";

  byId("detailPanel").innerHTML = `
    <div class="detail-header">
      <div>
        <p class="eyebrow">Selected alert</p>
        <h2>${alert.id} - ${alert.attackType}</h2>
        <span class="badge ${alert.severity.toLowerCase()}">${alert.severity}</span>
      </div>
      <div class="risk-meter">
        <span class="risk-score" style="color:${riskColor(score)}">${score}</span>
        <div class="risk-line"><span style="width:${score}%; background:${riskColor(score)}"></span></div>
      </div>
    </div>

    <div class="detail-meta">
      <div class="meta-box"><span>Source</span><strong>${alert.sourceIp}</strong></div>
      <div class="meta-box"><span>Destination</span><strong>${alert.destinationIp}:${alert.port}</strong></div>
      <div class="meta-box"><span>Protocol</span><strong>${alert.protocol}</strong></div>
      <div class="meta-box"><span>Confidence</span><strong>${alert.confidence}%</strong></div>
    </div>

    <section class="explain-card">
      <span>Trigger reason</span>
      <p>${alert.triggerReason}</p>
      ${feedbackInfluence}
    </section>

    <section class="explain-card">
      <span>Risk factors</span>
      <ul>${alert.riskFactors.map((factor) => `<li>${factor}</li>`).join("")}</ul>
    </section>

    <section class="explain-card">
      <span>Evidence</span>
      <p>${alert.evidence}</p>
    </section>

    <section class="explain-card">
      <span>Similar alerts</span>
      <p>${similar.length} related alerts share the pattern key <strong>${alert.similarityKey}</strong>.</p>
      <p class="small-muted">${similar
        .map((item) => `${item.id}: ${item.status}, risk ${scoreFor(item)}`)
        .join(" | ")}</p>
    </section>

    <section class="explain-card">
      <span>Recommended action</span>
      <p>${alert.recommendedAction}</p>
    </section>

    <section class="explain-card">
      <span>Human feedback</span>
      <div class="feedback-grid">
        <button class="feedback-button true" data-feedback="truePositive" type="button">True Positive</button>
        <button class="feedback-button false" data-feedback="falsePositive" type="button">False Positive</button>
        <button class="feedback-button suspicious" data-feedback="suspicious" type="button">Suspicious</button>
        <button class="feedback-button benign" data-feedback="benign" type="button">Benign</button>
      </div>
      <p class="feedback-note">
        Current status: <strong>${alert.status}</strong>. Feedback updates this alert, adjusts similar alerts, and refreshes dashboard metrics immediately.
      </p>
    </section>
  `;

  document.querySelectorAll("[data-feedback]").forEach((button) => {
    button.addEventListener("click", () => applyFeedback(alert.id, button.dataset.feedback));
  });
}

function groupedPatterns() {
  return Object.entries(countBy(alerts, "similarityKey")).map(([key, count]) => {
    const group = alerts.filter((alert) => alert.similarityKey === key);
    const avgRisk = Math.round(group.reduce((sum, alert) => sum + scoreFor(alert), 0) / group.length);
    const reviewed = group.filter((alert) => alert.feedback).length;
    const dominantType = group[0].attackType;
    return { key, count, group, avgRisk, reviewed, dominantType };
  });
}

function renderInvestigations() {
  const topCases = [...alerts]
    .sort((a, b) => scoreFor(b) - scoreFor(a))
    .slice(0, 5);
  const active = alerts.filter((alert) =>
    ["Unreviewed", "Confirmed Threat", "Under Review"].includes(alert.status),
  );
  const selected = selectedAlert();

  return `
    <section class="panel chart-panel">
      <div class="panel-header">
        <div>
          <h2>Investigations</h2>
          <p>Prioritized cases generated from the highest-risk alert patterns</p>
        </div>
        <div class="impact-pill">${active.length} active cases</div>
      </div>
      <div class="view-grid two">
        <div class="work-card">
          <h3>Case Queue</h3>
          <div class="case-list">
            ${topCases
              .map(
                (alert) => `
                  <article class="case-item" data-case-id="${alert.id}">
                    <div class="case-top">
                      <strong>${alert.id} - ${alert.attackType}</strong>
                      <span class="badge ${alert.severity.toLowerCase()}">${scoreFor(alert)}</span>
                    </div>
                    <p>${alert.triggerReason}</p>
                    <span class="small-muted">${alert.sourceIp} to ${alert.destinationIp}:${alert.port} | ${alert.status}</span>
                  </article>
                `,
              )
              .join("")}
          </div>
        </div>
        <div class="work-card">
          <h3>Investigation Timeline</h3>
          <div class="timeline">
            <div class="timeline-step"><span>${selected.timestamp}</span><strong>${selected.attackType} detected</strong></div>
            <div class="timeline-step"><span>+1 min</span><strong>Evidence collected: ${selected.evidence}</strong></div>
            <div class="timeline-step"><span>+3 min</span><strong>${similarAlerts(selected).length} similar alerts correlated</strong></div>
            <div class="timeline-step"><span>Now</span><strong>Recommended action: ${selected.recommendedAction}</strong></div>
          </div>
        </div>
      </div>
    </section>
  `;
}

function renderFeedbackModel() {
  const patterns = groupedPatterns().sort((a, b) => b.avgRisk - a.avgRisk);
  const m = metrics();
  return `
    <section class="panel chart-panel">
      <div class="panel-header">
        <div>
          <h2>Feedback Model</h2>
          <p>Explainable rule-based adaptation driven by analyst labels</p>
        </div>
        <div class="impact-pill">${lastImpact}</div>
      </div>
      <div class="matrix">
        <div class="matrix-cell"><span>Reviewed Alerts</span><strong>${m.reviewed}</strong></div>
        <div class="matrix-cell"><span>Confirmed Threats</span><strong>${m.confirmed}</strong></div>
        <div class="matrix-cell"><span>False Positives</span><strong>${m.falsePositive}</strong></div>
        <div class="matrix-cell"><span>Noise Reduction</span><strong>${m.noiseReduction}%</strong></div>
      </div>
      <div class="view-grid two" style="margin-top:14px">
        <div class="work-card">
          <h3>Pattern Weights</h3>
          <div class="rule-list">
            ${patterns
              .map(
                (pattern) => `
                  <article class="rule-item">
                    <div class="case-top">
                      <strong>${pattern.dominantType}</strong>
                      <span>Avg risk ${pattern.avgRisk}</span>
                    </div>
                    <p>${pattern.count} alerts share key <strong>${pattern.key}</strong>; ${pattern.reviewed} reviewed by analyst.</p>
                    <div class="progress-track"><span style="width:${pattern.avgRisk}%"></span></div>
                  </article>
                `,
              )
              .join("")}
          </div>
        </div>
        <div class="work-card">
          <h3>Adaptation Rules</h3>
          <div class="rule-list">
            <article class="rule-item"><strong>True Positive</strong><p>Increase selected alert risk by 8 and similar alert risk by 6.</p></article>
            <article class="rule-item"><strong>False Positive</strong><p>Lower selected alert risk by 18 and similar alert risk by 12.</p></article>
            <article class="rule-item"><strong>Suspicious</strong><p>Keep alert visible for review and slightly increase similar pattern attention.</p></article>
            <article class="rule-item"><strong>Benign</strong><p>Strongly lower selected and similar alerts to reduce operational noise.</p></article>
          </div>
        </div>
      </div>
    </section>
  `;
}

function renderReports() {
  const m = metrics();
  const severityCounts = countBy(alerts, "severity");
  const highest = [...alerts].sort((a, b) => scoreFor(b) - scoreFor(a))[0];
  return `
    <section class="panel chart-panel">
      <div class="panel-header">
        <div>
          <h2>Reports</h2>
          <p>Demo-ready summary of alert workload, feedback impact, and current risk posture</p>
        </div>
        <button class="ghost-button" id="prepareReportButton" type="button">Prepare report</button>
      </div>
      <div class="view-grid">
        <article class="work-card">
          <h3>Executive Summary</h3>
          <p>The dashboard currently tracks ${alerts.length} IDS alerts. Analyst feedback reviewed ${m.reviewed} alerts and reduced simulated alert noise by ${m.noiseReduction}%.</p>
          <p>Highest current risk: <strong>${highest.id} ${highest.attackType}</strong> with score <strong>${scoreFor(highest)}</strong>.</p>
        </article>
        <article class="work-card">
          <h3>Severity Breakdown</h3>
          <div class="rule-list">
            ${["Critical", "High", "Medium", "Low"]
              .map(
                (severity) => `
                  <div class="report-row">
                    <span>${severity}</span>
                    <strong>${severityCounts[severity] || 0}</strong>
                  </div>
                `,
              )
              .join("")}
          </div>
        </article>
        <article class="work-card">
          <h3>Feedback Outcome</h3>
          <div class="rule-list">
            <div class="report-row"><span>Confirmed Threat</span><strong>${m.confirmed}</strong></div>
            <div class="report-row"><span>False Positive</span><strong>${m.falsePositive}</strong></div>
            <div class="report-row"><span>Under Review</span><strong>${m.underReview}</strong></div>
            <div class="report-row"><span>Benign</span><strong>${m.benign}</strong></div>
          </div>
        </article>
      </div>
      <div class="work-card" id="reportStatus" style="margin-top:14px">
        <h3>Report Notes</h3>
        <p>This view can be used in the FYP demo to explain how human feedback changes operational metrics without requiring a backend database.</p>
      </div>
    </section>
  `;
}

function renderAlternateView() {
  const alternate = byId("alternateView");
  if (currentView === "operations") {
    byId("kpiGrid").hidden = false;
    document.querySelector(".workspace").hidden = false;
    alternate.hidden = true;
    alternate.innerHTML = "";
    return;
  }

  byId("kpiGrid").hidden = true;
  document.querySelector(".workspace").hidden = true;
  alternate.hidden = false;

  if (currentView === "investigations") alternate.innerHTML = renderInvestigations();
  if (currentView === "feedback") alternate.innerHTML = renderFeedbackModel();
  if (currentView === "reports") alternate.innerHTML = renderReports();

  document.querySelectorAll("[data-case-id]").forEach((card) => {
    card.addEventListener("click", () => {
      selectedAlertId = card.dataset.caseId;
      currentView = "operations";
      render();
    });
  });

  const reportButton = byId("prepareReportButton");
  if (reportButton) {
    reportButton.addEventListener("click", () => {
      const status = byId("reportStatus");
      status.innerHTML = `
        <h3>Report Prepared</h3>
        <p>Summary generated for ${alerts.length} alerts with ${metrics().reviewed} analyst-reviewed decisions. This is a simulated export state for the prototype demo.</p>
      `;
    });
  }
}

function render() {
  renderKpis();
  renderCharts();
  renderRows();
  renderDetail();
  renderAlternateView();
}

byId("severityFilter").addEventListener("change", render);
byId("statusFilter").addEventListener("change", render);
document.querySelectorAll("[data-view]").forEach((button) => {
  button.addEventListener("click", () => {
    currentView = button.dataset.view;
    document
      .querySelectorAll("[data-view]")
      .forEach((item) => item.classList.toggle("active", item.dataset.view === currentView));
    render();
  });
});
byId("resetButton").addEventListener("click", () => {
  alerts = structuredClone(initialAlerts);
  selectedAlertId = alerts[0].id;
  currentView = "operations";
  document
    .querySelectorAll("[data-view]")
    .forEach((item) => item.classList.toggle("active", item.dataset.view === currentView));
  byId("severityFilter").value = "all";
  byId("statusFilter").value = "all";
  lastImpact = "Waiting for analyst feedback";
  render();
});

render();
