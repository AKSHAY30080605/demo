document.addEventListener("DOMContentLoaded", () => {
  setInterval(pollTargetDefender, 1500);
  pollTargetDefender();
});

async function pollTargetDefender() {
  try {
    const res = await fetch("/api/target/status");
    const data = await res.json();
    const dot = document.getElementById("targetDot");
    const statusText = document.getElementById("targetStatusText");

    if (!data.online) {
      dot.className = "target-dot dot-offline";
      statusText.innerText = "Target Defender: UNREACHABLE (Check IP)";
      return;
    }

    dot.className = "target-dot dot-online";
    statusText.innerText = `Target Defender: ONLINE (${data.latency_ms} ms ping)`;

    const fusion = data.fusion || {};
    const trust = fusion.trust_score !== undefined ? fusion.trust_score : 100;
    const l1 = fusion.layer1_feed_health !== undefined ? fusion.layer1_feed_health : 100;
    const l2 = fusion.layer2_net_health !== undefined ? fusion.layer2_net_health : 100;
    const status = fusion.status || "SECURE";
    const aiLabel = fusion.ai_classification || "NORMAL";
    const activeMode = data.attack_mode || "NORMAL";

    const elTrust = document.getElementById("dispTrust");
    const elStatus = document.getElementById("dispStatus");
    const elModeTag = document.getElementById("activeModeTag");
    const alertsBar = document.getElementById("targetAlertsBar");
    const alertsList = document.getElementById("targetAlertsList");

    elTrust.innerText = `${trust}%`;
    elStatus.innerText = status;
    document.getElementById("dispL1").innerText = `${l1}%`;
    document.getElementById("dispL2").innerText = `${l2}%`;
    document.getElementById("dispAiClass").innerText = aiLabel;
    elModeTag.innerText = `DEFENDER MODE: ${activeMode}`;

    // Color code trust score on Laptop 2
    if (trust < 40) {
      elTrust.style.color = "#ef4444";
      elStatus.style.color = "#f87171";
    } else if (trust < 75) {
      elTrust.style.color = "#f59e0b";
      elStatus.style.color = "#fbbf24";
    } else {
      elTrust.style.color = "#10b981";
      elStatus.style.color = "#34d399";
    }

    // Alerts display
    if (fusion.active_critical && fusion.active_critical.length > 0) {
      alertsBar.classList.remove("hidden");
      alertsList.innerText = `DEFENDER ACTIVE ALARMS: ${fusion.active_critical.join(", ")}`;
    } else if (fusion.active_alerts && fusion.active_alerts.length > 0) {
      alertsBar.classList.remove("hidden");
      alertsList.innerText = `DEFENDER WARNINGS: ${fusion.active_alerts.join(", ")}`;
    } else {
      alertsBar.classList.add("hidden");
    }

  } catch (err) {
    console.error("pollTargetDefender error:", err);
  }
}

async function executeAttack(scenario) {
  try {
    const res = await fetch(`/api/attack/launch/${scenario}`, { method: "POST" });
    const data = await res.json();
    if (data.ok) {
      pollTargetDefender();
    } else {
      alert("Attack dispatch error: " + (data.error || "Unknown"));
    }
  } catch (err) {
    alert("Connection error: " + err);
  }
}

async function saveTargetConfig() {
  const defUrl = document.getElementById("inpDefenderUrl").value.trim();
  const camUrl = document.getElementById("inpCameraUrl").value.trim();

  try {
    const res = await fetch("/api/target/config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ defender_hub_url: defUrl, camera_node_url: camUrl })
    });
    const data = await res.json();
    if (data.ok) {
      alert("Target network configuration updated successfully!");
      pollTargetDefender();
    }
  } catch (err) {
    alert("Save error: " + err);
  }
}

async function runBenchmark(preset) {
  try {
    const res = await fetch("/api/benchmark/flow", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ preset })
    });
    const data = await res.json();
    const box = document.getElementById("benchResultBox");
    const content = document.getElementById("benchContent");
    box.classList.remove("hidden");

    if (data.ok) {
      content.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <div>
            <strong>Attack Vector:</strong> <span style="color:#fb7185">${data.preset}</span><br>
            <strong>Classified As:</strong> <span style="color:#38bdf8">${data.predicted_attack_type}</span>
          </div>
          <div style="text-align:right;">
            <div style="font-size:1.3rem; font-weight:800; color:#10b981;">${data.inference_time_ms} ms</div>
            <span style="font-size:0.75rem; color:#94a3b8;">Detection Latency</span>
          </div>
        </div>
      `;
    } else {
      content.innerHTML = `<span style="color:#ef4444">Benchmark failed: ${data.error || 'Server error'}</span>`;
    }
  } catch (err) {
    alert("Benchmark error: " + err);
  }
}

async function runNetworkScan() {
  const btn = document.getElementById("btnScanNet");
  const area = document.getElementById("scanResultsArea");
  const grid = document.getElementById("scanDevicesGrid");
  const alertBanner = document.getElementById("honeypotTouchAlert");
  
  btn.innerHTML = "<span>⏳ Scanning Subnet (Nmap ARP / SYN Sweep)...</span>";
  btn.disabled = true;
  alertBanner.classList.add("hidden");

  try {
    const res = await fetch("/api/network/scan");
    const data = await res.json();
    
    btn.innerHTML = "<span>🔍 Re-Scan Network</span>";
    btn.disabled = false;
    area.classList.remove("hidden");

    document.getElementById("scanSubnetText").innerText = `Subnet: ${data.subnet} | Scan Latency: ${data.scan_time_ms} ms`;
    document.getElementById("scanHostsCount").innerText = `● ${data.devices.length} Hosts Discovered`;

    grid.innerHTML = data.devices.map(d => {
      const isHp = d.is_honeypot;
      const cardClass = isHp ? "device-card honeypot-target" : "device-card real-node";
      const actionBtn = isHp 
        ? `<button class="btn-touch-trap" onclick="touchHoneypot('${d.trap_type}')">⚠️ Touch / Attack This Decoy (${d.trap_type.toUpperCase()})</button>`
        : `<span style="font-size:0.76rem; color:#10b981;">🛡️ Hardware Protected</span>`;

      return `
        <div class="${cardClass}">
          <div>
            <div class="device-header">
              <div>
                <div class="device-ip">${d.ip}</div>
                <div class="device-role">${d.role}</div>
              </div>
              <span class="device-badge ${d.badge_type}">${d.badge}</span>
            </div>
            <div class="device-ports" style="margin-top:10px;">
              <strong>Open Ports:</strong> <span>${d.open_ports}</span>
            </div>
            <div style="font-size:0.75rem; color:#64748b; margin-top:6px; line-height:1.4;">
              ${d.description}
            </div>
          </div>
          <div style="margin-top:12px; border-top:1px solid #1e293b; padding-top:10px;">
            ${actionBtn}
          </div>
        </div>
      `;
    }).join("");

  } catch (err) {
    btn.innerHTML = "<span>🔍 Scan Network for Devices & Honeypots</span>";
    btn.disabled = false;
    alert("Network scan failed: " + err);
  }
}

async function touchHoneypot(trapType) {
  const alertBanner = document.getElementById("honeypotTouchAlert");
  const alertText = document.getElementById("honeypotTouchText");

  try {
    const res = await fetch("/api/honeypot/touch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ trap_type: trapType })
    });
    const data = await res.json();

    alertBanner.classList.remove("hidden");
    alertText.innerHTML = `
      <div style="font-size:1.05rem; font-weight:800; color:#f87171; margin-bottom:6px;">
        🚨 CAUGHT IN HONEYPOT! PC 1 DEFENDER HAS DETECTED YOU!
      </div>
      <div>
        <strong>Target Decoy:</strong> ${trapType.toUpperCase()} Honeypot Trap<br>
        <strong>Defender Verdict:</strong> <span style="color:#ef4444; font-weight:700;">${data.defender_status}</span> (Trust collapsed to <strong>${data.defender_trust}%</strong>)<br>
        <strong>Tripwire Latency:</strong> ${data.latency_ms} ms<br>
        <span style="color:#fca5a5; margin-top:4px; display:inline-block;">${data.defender_message}</span>
      </div>
    `;

    // Immediately update live defender status metrics
    pollTargetDefender();

  } catch (err) {
    alert("Honeypot probe error: " + err);
  }
}
