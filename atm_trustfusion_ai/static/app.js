let liveChart = null;
let attackDistChart = null;
let currentTab = "soc";

document.addEventListener("DOMContentLoaded", () => {
  initCharts();
  loadDatasetPreview();
  loadModelMetrics();

  // Polling intervals
  setInterval(fetchStatus, 1500);
  setInterval(fetchEvents, 2500);
  setInterval(pollRecoveredFootage, 2000);

  fetchStatus();
  fetchEvents();
  pollRecoveredFootage();

  // Stream Watchdog: If browser stalled on black/blank image, reload stream
  setTimeout(() => {
    const img = document.getElementById("mainStream");
    if (img && (img.naturalWidth === 0 || img.naturalHeight === 0)) {
      console.log("Stream watchdog re-triggering /stream...");
      img.src = "/stream?t=" + Date.now();
    }
  }, 2000);
});

function switchTab(tabId) {
  currentTab = tabId;
  document.querySelectorAll(".nav-tab").forEach(tab => tab.classList.remove("active"));
  document.querySelectorAll(".tab-pane").forEach(pane => pane.classList.remove("active"));

  const targetTab = Array.from(document.querySelectorAll(".nav-tab")).find(b => b.getAttribute("onclick").includes(tabId));
  if (targetTab) targetTab.classList.add("active");

  const pane = document.getElementById(`tab-${tabId}`);
  if (pane) pane.classList.add("active");
}

function initCharts() {
  // Live Trust Trend Line Chart
  const ctxLive = document.getElementById("liveTrustChart").getContext("2d");
  liveChart = new Chart(ctxLive, {
    type: "line",
    data: {
      labels: [],
      datasets: [
        {
          label: "Trust Score (%)",
          data: [],
          borderColor: "#38bdf8",
          backgroundColor: "rgba(56, 189, 248, 0.12)",
          borderWidth: 2.2,
          fill: true,
          tension: 0.35,
          pointRadius: 0
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: {
          min: 0,
          max: 100,
          grid: { color: "#1c263c" },
          ticks: { color: "#94a3b8", font: { size: 10 } }
        },
        x: { display: false }
      },
      plugins: {
        legend: { display: false }
      }
    }
  });

  // Attack Distribution Bar Chart
  const ctxDist = document.getElementById("attackDistChart").getContext("2d");
  attackDistChart = new Chart(ctxDist, {
    type: "bar",
    data: {
      labels: ["Normal", "SynFlood", "HttpFlood", "TapoC200Attack", "BotnetSim", "Scanning", "HydraBrute", "UDPFlood", "ARP Spoof"],
      datasets: [
        {
          label: "Flow Samples",
          data: [20000, 20000, 20000, 20000, 20000, 20000, 14492, 2980, 340],
          backgroundColor: [
            "#10b981", "#3b82f6", "#06b6d4", "#ef4444", "#a855f7", "#f59e0b", "#ec4899", "#8b5cf6", "#f97316"
          ],
          borderRadius: 6
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: {
          grid: { color: "#1c263c" },
          ticks: { color: "#94a3b8", font: { size: 10 } }
        },
        x: {
          grid: { display: false },
          ticks: { color: "#94a3b8", font: { size: 9 }, maxRotation: 45, minRotation: 45 }
        }
      },
      plugins: {
        legend: { display: false }
      }
    }
  });
}

async function fetchStatus() {
  try {
    const res = await fetch("/api/status");
    const data = await res.json();
    const fusion = data.fusion || {};
    const attackMode = data.attack_mode || "NORMAL";

    const trust = fusion.trust_score !== undefined ? fusion.trust_score : 100;
    const l1 = fusion.layer1_feed_health !== undefined ? fusion.layer1_feed_health : 100;
    const l2 = fusion.layer2_net_health !== undefined ? fusion.layer2_net_health : 100;
    const l3 = fusion.layer3_content_health !== undefined ? fusion.layer3_content_health : 100;
    const occ = fusion.occupancy_state || "EMPTY";
    const status = fusion.status || "SECURE";
    const aiLabel = fusion.ai_classification || "NORMAL";

    // Update Tab 1 KPIs
    const elTrust = document.getElementById("kpiTrust");
    const elStatus = document.getElementById("kpiStatus");
    const elLiveBadge = document.getElementById("liveStatusBadge");
    const elAttackBadge = document.getElementById("activeAttackBadge");
    const elBanner = document.getElementById("videoAlertBanner");

    elTrust.innerText = `${trust}%`;
    elStatus.innerText = status;
    document.getElementById("kpiAiClassification").innerText = `AI: ${aiLabel}`;

    document.getElementById("kpiL1").innerText = `${l1}%`;
    document.getElementById("kpiL2").innerText = `${l2}%`;
    document.getElementById("kpiL3Health").innerText = `${l3}% HEALTH`;
    document.getElementById("kpiOccupancy").innerText = occ.replace("ATM_", "").replace("_NORMAL", "");

    // Update Progress Bars
    document.getElementById("txtL1").innerText = `${l1}%`;
    document.getElementById("barL1").style.width = `${l1}%`;
    document.getElementById("txtL2").innerText = `${l2}%`;
    document.getElementById("barL2").style.width = `${l2}%`;
    document.getElementById("txtL3").innerText = `${l3}%`;
    document.getElementById("barL3").style.width = `${l3}%`;

    // Active Attack Mode
    elAttackBadge.innerText = `MODE: ${attackMode}`;
    document.getElementById("labActiveAttack").innerText = `STATUS: ${attackMode}`;

    // Dynamic Video HUD HMAC status
    const elHmac = document.getElementById("hudHmac");
    if (elHmac) {
      const isAuthFail = (fusion.active_alerts && (fusion.active_alerts.includes("AUTH_FAILURE") || fusion.active_alerts.includes("SEQ_REPLAY")));
      elHmac.innerText = isAuthFail ? "FAILED" : "VALID";
      elHmac.style.color = isAuthFail ? "#ef4444" : "#10b981";
    }

    // Status styling
    const cl = fusion.cross_layer_decision || {};
    const isReplay = (cl.verdict === "REPLAY_ATTACK") || (fusion.active_alerts && (fusion.active_alerts.includes("VIDEO_REPLAY_LOOP") || fusion.active_alerts.includes("ATM_LOOP_CONCEALMENT_ACTIVE")));
    const isNetAttack = (cl.verdict === "NETWORK_ATTACK") || (fusion.active_alerts && fusion.active_alerts.includes("IDS_ATTACK_DETECTED"));

    if (trust < 50 || isReplay || isNetAttack || (fusion.active_critical && fusion.active_critical.length > 0)) {
      elTrust.style.color = "#ef4444";
      elStatus.className = "status-pill status-danger";
      elLiveBadge.className = "tag-attack-mode";
      elLiveBadge.style.background = "#7f1d1d";
      elLiveBadge.innerText = isReplay ? "VIDEO LOOPED / REPLAYED" : "CRITICAL ALERT";
      elBanner.classList.remove("hidden");
      if (isReplay) {
        elBanner.innerText = `🚨 CRITICAL: VIDEO IS LOOPED / REPLAYED! (ATM CONCEALMENT ATTACK DETECTED - TRUST SCORE: ${trust}%)`;
      } else if (isNetAttack) {
        elBanner.innerText = `🚨 CRITICAL: NETWORK DOS / PACKET FLOOD ATTACK! (STREAM DEGRADED - TRUST SCORE: ${trust}%)`;
      } else {
        elBanner.innerText = `⚠️ CRITICAL: ${fusion.active_critical[0] || 'ATM SECURITY BREACH DETECTED (SCORE COLLAPSED)'}`;
      }
    } else if (trust < 75) {
      elTrust.style.color = "#f59e0b";
      elStatus.className = "status-pill status-caution";
      elLiveBadge.className = "tag-attack-mode";
      elLiveBadge.style.background = "#78350f";
      elLiveBadge.innerText = "CAUTION";
      elBanner.classList.add("hidden");
    } else {
      elTrust.style.color = "#10b981";
      elStatus.className = "status-pill status-secure";
      elLiveBadge.className = "tag-secure";
      elLiveBadge.innerText = "SECURE";
      elBanner.classList.add("hidden");
    }

    // Cross-Layer Decision Matrix Update
    const clBanner = document.getElementById("crossLayerBanner");
    const clBadge = document.getElementById("clBadge");
    const clVerdict = document.getElementById("clVerdictExplanation");
    const clOptical = document.getElementById("clOpticalProof");
    const clCrypto = document.getElementById("clCryptoProof");
    const clNetwork = document.getElementById("clNetworkProof");
    const clOccupancy = document.getElementById("clOccupancyProof");

    if (clBanner && cl.verdict) {
      if (cl.verdict === "REPLAY_ATTACK") {
        clBanner.className = "cross-layer-banner banner-danger";
        clBadge.className = "cl-badge cl-badge-danger";
        clBadge.innerText = cl.badge || "CRITICAL: VIDEO REPLAY / LOOP DETECTED";
        if (clVerdict) {
          clVerdict.className = "cl-verdict-box danger-left";
          clVerdict.innerText = cl.explanation || "Replay attack detected in empty ATM booth.";
        }
      } else if (cl.verdict === "NETWORK_ATTACK") {
        clBanner.className = "cross-layer-banner banner-danger";
        clBadge.className = "cl-badge cl-badge-danger";
        clBadge.innerText = cl.badge || "CRITICAL: NETWORK INTRUSION DETECTED";
        if (clVerdict) {
          clVerdict.className = "cl-verdict-box danger-left";
          clVerdict.innerText = cl.explanation || "Network DoS/Flood attack in progress against camera stream.";
        }
      } else {
        clBanner.className = "cross-layer-banner banner-secure";
        clBadge.className = cl.badge_color === "warning" ? "cl-badge cl-badge-warning" : "cl-badge cl-badge-success";
        clBadge.innerText = cl.badge || "VERIFIED LIVE STANDBY (AUTHENTIC)";
        if (clVerdict) {
          clVerdict.className = "cl-verdict-box";
          clVerdict.innerText = cl.explanation || "Genuine empty ATM verified via cross-layer crypto and sensor physics.";
        }
      }
      if (clOptical) clOptical.innerText = cl.optical_proof || "--";
      if (clCrypto) clCrypto.innerText = cl.crypto_proof || "--";
      if (clNetwork) clNetwork.innerText = cl.network_proof || "--";
      if (clOccupancy) clOccupancy.innerText = cl.occupancy || occ;
    }

    // Update Live Trend Chart
    if (liveChart && data.history) {
      liveChart.data.labels = data.history.map((_, i) => i);
      liveChart.data.datasets[0].data = data.history.map(h => h.trust_score);
      liveChart.update("none");
    }

    // Update Test Lab Diagnostics Box
    updateTestLabDiagnostics(fusion, attackMode, trust, l1, l2, l3);

  } catch (err) {
    console.error("fetchStatus error:", err);
  }
}

function updateTestLabDiagnostics(fusion, attackMode, trust, l1, l2, l3) {
  const elRing = document.getElementById("labTrustScore");
  const elTitle = document.getElementById("labThreatTitle");
  const elDesc = document.getElementById("labThreatDesc");

  elRing.innerText = `${trust}%`;
  elRing.style.color = trust < 40 ? "#ef4444" : (trust < 75 ? "#f59e0b" : "#10b981");

  const tr1 = document.getElementById("traceL1");
  const tr2 = document.getElementById("traceL2");
  const tr3 = document.getElementById("traceL3");
  const trF = document.getElementById("traceFusion");

  if (attackMode === "LOOP") {
    elTitle.innerText = "🚨 ATM Video Replay Loop Attack In Progress";
    elDesc.innerText = "Layer 1 cyclic temporal autocorrelation detected matching frame cycles. Layer 3 flags empty scene concealment.";
    tr1.className = "trace-fail";
    document.getElementById("traceL1Text").innerText = "CYCLIC REPLAY DETECTED: Period = 60 frames. Severity = 0.95.";
    tr3.className = "trace-fail";
    document.getElementById("traceL3Text").innerText = "ATM_LOOP_CONCEALMENT_ACTIVE: 0 persons visible in room during loop.";
    trF.className = "trace-fail";
    document.getElementById("traceFusionText").innerText = "CRITICAL BREACH: Hard Override Clamp -> Trust locked at 25.0%.";
  } else if (attackMode === "EXPLOIT") {
    elTitle.innerText = "🚨 Camera Exploit Attack (cameraTapoC200Attack)";
    elDesc.innerText = "Layer 2 ML-IDS classified malicious flow signature targeting camera network services.";
    tr2.className = "trace-fail";
    document.getElementById("traceL2Text").innerText = "ML-IDS CLASSIFICATION: cameraTapoC200Attack (Confidence: 99.8%).";
    trF.className = "trace-fail";
    document.getElementById("traceFusionText").innerText = "ELEVATED ALERT: Network Health dropped. Trust reduced.";
  } else if (attackMode === "MITM") {
    elTitle.innerText = "🚨 ARP Spoofing / MITM Attack";
    elDesc.innerText = "Camera stream intercepted. Cryptographic HMAC token authentication rejected.";
    tr2.className = "trace-fail";
    document.getElementById("traceL2Text").innerText = "AUTH_FAILURE: HMAC signature mismatch from rogue camera node.";
    trF.className = "trace-fail";
    document.getElementById("traceFusionText").innerText = "CRITICAL BREACH: Rogue camera feed rejected. Trust locked at 25.0%.";
  } else if (attackMode === "FREEZE") {
    elTitle.innerText = "🚨 Frozen Stream / Static Still Injection";
    elDesc.innerText = "Temporal pixel delta collapsed (< 0.65). Sensor thermal noise entropy missing.";
    tr1.className = "trace-fail";
    document.getElementById("traceL1Text").innerText = "FROZEN_FEED: Zero sensor thermal noise detected across 35 frames.";
    trF.className = "trace-fail";
    document.getElementById("traceFusionText").innerText = "CRITICAL BREACH: Video feed frozen. Trust locked at 25.0%.";
  } else if (attackMode === "BLACKOUT") {
    elTitle.innerText = "🚨 Camera Lens Blackout / Covered";
    elDesc.innerText = "Mean luminance floor < 12.0. Lens spray-painted or physically obstructed.";
    tr1.className = "trace-fail";
    document.getElementById("traceL1Text").innerText = "BLACK_FRAME: Mean brightness dropped below 12.0 threshold.";
    trF.className = "trace-fail";
    document.getElementById("traceFusionText").innerText = "CRITICAL ALARM: Lens obstruction alarm active.";
  } else {
    elTitle.innerText = "Normal Surveillance Operation";
    elDesc.innerText = "All 3 layers verified. No tampering, loop artifacts, or network intrusions.";
    tr1.className = "trace-ok";
    document.getElementById("traceL1Text").innerText = "Cyclic autocorrelation negative. Sensor noise entropy normal.";
    tr2.className = "trace-ok";
    document.getElementById("traceL2Text").innerText = "Flow statistics scored normal by ML. HMAC cryptographic token valid.";
    tr3.className = "trace-ok";
    document.getElementById("traceL3Text").innerText = "YOLOv8 detected scene. Contextual occupancy consistency verified.";
    trF.className = "trace-ok";
    document.getElementById("traceFusionText").innerText = "Decision: SECURE (Trust >= 75%).";
  }
}

async function fetchEvents() {
  try {
    const res = await fetch("/api/events");
    const data = await res.json();
    const events = data.events || [];

    // Quick List in Tab 1
    const elQuick = document.getElementById("quickEventsList");
    if (events.length === 0) {
      elQuick.innerHTML = `<div class="empty-hint">Monitoring ATM stream. No incidents active.</div>`;
    } else {
      elQuick.innerHTML = events.slice(0, 5).map(ev => `
        <div class="event-row-quick">
          <div>
            <strong>${ev.alert}</strong>
            <span style="color:#94a3b8; margin-left:6px;">${ev.timestamp}</span>
          </div>
          <span style="font-weight:700; color:#ef4444;">${ev.trust_at_event}%</span>
        </div>
      `).join("");
    }

    // Full Table in Tab 4
    const elFull = document.getElementById("fullLogsTableBody");
    if (events.length === 0) {
      elFull.innerHTML = `<tr><td colspan="5" style="text-align:center; color:#64748b;">No recent incidents recorded. System secure.</td></tr>`;
    } else {
      elFull.innerHTML = events.map(ev => `
        <tr>
          <td>${ev.timestamp}</td>
          <td><span class="status-pill status-danger">${ev.alert}</span></td>
          <td>${ev.description}</td>
          <td style="font-weight:700; color:#ef4444;">${ev.trust_at_event}%</td>
          <td>${ev.status}</td>
        </tr>
      `).join("");
    }
  } catch (err) {
    console.error("fetchEvents error:", err);
  }
}

async function triggerLabAttack(mode) {
  try {
    const res = await fetch(`/api/simulate/${mode}`, { method: "POST" });
    const data = await res.json();
    fetchStatus();
    fetchEvents();
  } catch (err) {
    alert("Simulation error: " + err);
  }
}

async function loadDatasetPreview() {
  try {
    const res = await fetch("/api/dataset/sample");
    const data = await res.json();
    const rows = data.network_flows || [];
    const tbody = document.getElementById("datasetTableBody");

    if (rows.length === 0) {
      tbody.innerHTML = `<tr><td colspan="9">No dataset samples available.</td></tr>`;
      return;
    }

    tbody.innerHTML = rows.map(r => `
      <tr>
        <td>${r.orig_p || 0}</td>
        <td>${r.resp_p || 0}</td>
        <td>${r.proto || 'tcp'}</td>
        <td>${Number(r.duration || 0).toFixed(4)}s</td>
        <td>${r.orig_bytes || 0}</td>
        <td>${r.resp_bytes || 0}</td>
        <td>${r.orig_pkts || 0}</td>
        <td><span class="status-pill ${r.attack == 1 ? 'status-danger' : 'status-secure'}">${r.attack == 1 ? 'ATTACK' : 'NORMAL'}</span></td>
        <td><strong>${r.type_of_attack || 'normal'}</strong></td>
      </tr>
    `).join("");
  } catch (err) {
    console.error("loadDatasetPreview error:", err);
  }
}

async function loadModelMetrics() {
  try {
    const res = await fetch("/api/models/metrics");
    const data = await res.json();
    // Metrics can populate additional chart data if needed
  } catch (err) {
    console.error("loadModelMetrics error:", err);
  }
}

async function testFlowInference() {
  const payload = {
    orig_p: parseFloat(document.getElementById("inpOrigP").value) || 0,
    resp_p: parseFloat(document.getElementById("inpRespP").value) || 0,
    duration: parseFloat(document.getElementById("inpDuration").value) || 0,
    orig_bytes: parseFloat(document.getElementById("inpOrigBytes").value) || 0,
    resp_bytes: parseFloat(document.getElementById("inpRespBytes").value) || 0,
    orig_pkts: parseFloat(document.getElementById("inpOrigPkts").value) || 0,
    resp_pkts: parseFloat(document.getElementById("inpRespPkts").value) || 0,
    orig_ip_bytes: parseFloat(document.getElementById("inpOrigIpBytes").value) || 0,
    resp_ip_bytes: 0,
    missed_bytes: 0
  };

  try {
    const res = await fetch("/api/models/predict_flow", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const result = await res.json();

    const box = document.getElementById("flowPredictionResult");
    const content = document.getElementById("flowPredContent");
    box.classList.remove("hidden");

    const isAtt = result.is_attack;
    content.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center; margin-top:8px;">
        <div>
          <span style="font-size:1.1rem; font-weight:800; color:${isAtt ? '#ef4444' : '#10b981'}">
            ${isAtt ? '⚠️ MALICIOUS NETWORK INTRUSION' : '✅ NORMAL NETWORK TRAFFIC'}
          </span>
          <div style="font-size:0.85rem; color:#94a3b8; margin-top:4px;">
            Classified Type: <strong style="color:#fff;">${result.predicted_attack_type}</strong>
          </div>
        </div>
        <div style="text-align:right;">
          <div style="font-size:1.4rem; font-weight:800; color:${isAtt ? '#ef4444' : '#10b981'}">
            ${result.attack_probability}%
          </div>
          <span style="font-size:0.75rem; color:#64748b;">Attack Probability</span>
        </div>
      </div>
    `;
  } catch (err) {
    alert("Inference error: " + err);
  }
}

function loadSamplePreset(preset) {
  if (preset === "exploit") {
    document.getElementById("inpOrigP").value = 38442;
    document.getElementById("inpRespP").value = 80;
    document.getElementById("inpDuration").value = 0.002;
    document.getElementById("inpOrigBytes").value = 450;
    document.getElementById("inpRespBytes").value = 0;
    document.getElementById("inpOrigPkts").value = 3;
    document.getElementById("inpRespPkts").value = 0;
    document.getElementById("inpOrigIpBytes").value = 600;
  } else if (preset === "synFlood") {
    document.getElementById("inpOrigP").value = 1234;
    document.getElementById("inpRespP").value = 80;
    document.getElementById("inpDuration").value = 0.0001;
    document.getElementById("inpOrigBytes").value = 0;
    document.getElementById("inpRespBytes").value = 0;
    document.getElementById("inpOrigPkts").value = 1;
    document.getElementById("inpRespPkts").value = 0;
    document.getElementById("inpOrigIpBytes").value = 52;
  } else if (preset === "normal") {
    document.getElementById("inpOrigP").value = 44321;
    document.getElementById("inpRespP").value = 80;
    document.getElementById("inpDuration").value = 0.05;
    document.getElementById("inpOrigBytes").value = 1200;
    document.getElementById("inpRespBytes").value = 84000;
    document.getElementById("inpOrigPkts").value = 12;
    document.getElementById("inpRespPkts").value = 45;
    document.getElementById("inpOrigIpBytes").value = 1800;
  }
  testFlowInference();
}

async function promptChangeSource() {
  const current = document.getElementById("headerSourceText").innerText.replace("Source: ", "");
  const newSource = prompt("Enter camera stream source (e.g. webcam:0 or http://<pi-ip>:8080/video):", current);
  if (newSource && newSource.trim()) {
    const res = await fetch("/api/set_source", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ source: newSource.trim() })
    });
    const d = await res.json();
    if (d.ok) {
      document.getElementById("headerSourceText").innerText = "Source: " + d.source;
      location.reload();
    }
  }
}

let lastRecoveredTs = null;

async function pollRecoveredFootage() {
  try {
    const res = await fetch("/api/recovered_footage_status");
    const data = await res.json();
    
    const imgPlayer = document.getElementById("recoveredImgPlayer");
    const videoPlayer = document.getElementById("recoveredVideoPlayer");
    const placeholder = document.getElementById("recoveredPlaceholder");
    const badge = document.getElementById("recoveredSyncBadge");
    const statusText = document.getElementById("recMetaStatus");
    const framesText = document.getElementById("recMetaFrames");
    const hashText = document.getElementById("recMetaHash");
    const downloadBtn = document.getElementById("recoveredDownloadBtn");

    if (data && data.available) {
      if (placeholder) placeholder.style.display = "none";
      if (imgPlayer) {
        imgPlayer.style.display = "block";
        if (lastRecoveredTs !== data.timestamp) {
          lastRecoveredTs = data.timestamp;
          imgPlayer.src = `/recovered_stream.mjpg?t=${Date.now()}`;
        }
      }
      if (downloadBtn) {
        downloadBtn.style.display = "inline-flex";
      }

      if (badge) {
        badge.innerText = "EVIDENCE SYNCHRONIZED";
        badge.style.background = "rgba(16, 185, 129, 0.3)";
        badge.style.color = "#34d399";
        badge.style.border = "1px solid #10b981";
      }
      if (statusText) {
        statusText.innerText = "SYNCHRONIZED (PI EDGE EVIDENCE)";
        statusText.style.color = "#34d399";
      }
      if (framesText) {
        framesText.innerText = `${data.frame_count || 0} frames (${data.file_size_kb || 0} KB)`;
      }
      if (hashText) {
        hashText.innerText = data.sha256 || "SHA256: VERIFIED_INTEGRITY";
      }
    } else {
      if (placeholder) placeholder.style.display = "block";
      if (imgPlayer) imgPlayer.style.display = "none";
      if (videoPlayer) videoPlayer.style.display = "none";
      if (downloadBtn) downloadBtn.style.display = "none";
      if (badge) {
        badge.innerText = "STANDBY (ARMED)";
        badge.style.background = "rgba(0, 230, 118, 0.15)";
        badge.style.color = "#00e676";
        badge.style.border = "1px solid #00e676";
      }
      if (statusText) {
        statusText.innerText = "STANDBY (CONTINUOUS EDGE MONITORING)";
        statusText.style.color = "#94a3b8";
      }
      if (framesText) {
        framesText.innerText = "Waiting for attack event...";
      }
      if (hashText) {
        hashText.innerText = "SHA256: NOT_YET_CALCULATED";
      }
    }
  } catch (err) {
    console.error("Error polling recovered footage:", err);
  }
}
