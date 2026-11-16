// terminal.js - Interactive Red Team CLI Console for College Demo
let history = [];
let historyIdx = -1;
let currentMode = "normal"; // "normal" or "ssh_password" or "ssh_session" or "wifi_password"
let pendingWifiSSID = "";
let isWifiConnected = false;

document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("termInput");
  input.focus();

  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      const val = input.value.trim();
      input.value = "";
      handleInput(val);
    } else if (e.key === "ArrowUp") {
      if (history.length > 0) {
        historyIdx = Math.max(0, historyIdx - 1);
        input.value = history[historyIdx] || "";
      }
    } else if (e.key === "ArrowDown") {
      if (history.length > 0) {
        historyIdx = Math.min(history.length, historyIdx + 1);
        input.value = history[historyIdx] || "";
      }
    }
  });
});

function focusInput() {
  document.getElementById("termInput").focus();
}

function toggleGuide() {
  const bar = document.getElementById("guideSidebar");
  bar.classList.toggle("collapsed");
}

function copyCmd(cmd) {
  const input = document.getElementById("termInput");
  input.value = cmd;
  input.focus();
}

function appendLine(text, className = "") {
  const out = document.getElementById("termOutput");
  const div = document.createElement("div");
  div.className = `log-line ${className}`;
  div.innerHTML = text;
  out.appendChild(div);

  const win = document.getElementById("termWindow");
  win.scrollTop = win.scrollHeight;
}

function handleInput(cmd) {
  const promptText = document.getElementById("promptLabel").innerText;

  if (currentMode === "wifi_password") {
    appendLine(`${promptText}********`);
    connectWifiWithKey(pendingWifiSSID, cmd);
    return;
  }

  if (currentMode === "ssh_password") {
    appendLine(`${promptText}********`);
    verifySshPassword(cmd);
    return;
  }

  appendLine(`${promptText}<span class="log-cmd">${escapeHtml(cmd)}</span>`);

  if (!cmd) return;
  history.push(cmd);
  historyIdx = history.length;

  const parts = cmd.trim().split(/\s+/);
  const root = parts[0].toLowerCase();

  // If in SSH session to Pi
  if (currentMode === "ssh_session") {
    handlePiSshCommand(cmd);
    return;
  }

  // Normal Red Team CLI Commands
  switch (root) {
    case "help":
    case "guide":
      showHelp();
      break;

    case "clear":
    case "cls":
      document.getElementById("termOutput").innerHTML = "";
      break;

    case "scan-wifi":
    case "scan":
    case "netsh":
      scanWifiNetworks();
      break;

    case "connect-wifi":
    case "connect":
      const ssid = parts.slice(1).join(" ") || "ATM_SURVEILLANCE_5G";
      promptWifiConnect(ssid);
      break;

    case "nmap":
    case "scan-subnet":
    case "net-scan":
      runNmapScan(parts[1] || "10.218.22.0/24");
      break;

    case "ping":
      runPing(parts[1] || "10.218.22.14");
      break;

    case "ssh":
      startSshSession(parts[1] || "pi1@10.218.22.14");
      break;

    case "inject":
    case "mitm":
    case "inject-feed":
      executeStreamInjection(parts);
      break;

    case "check-defender":
    case "status":
      checkDefenderStatus();
      break;

    case "reset":
      resetSystem();
      break;

    default:
      appendLine(`bash: ${escapeHtml(root)}: command not found. Type <span class="cmd-highlight" onclick="copyCmd('help')">help</span> for presentation commands.`, "log-warn");
      break;
  }
}

function showHelp() {
  appendLine(`
======================= PRESENTATION COMMAND REFERENCE =======================
  <span class="cmd-highlight" onclick="copyCmd('scan-wifi')">scan-wifi</span>                      Scan for local surveillance Wi-Fi SSIDs
  <span class="cmd-highlight" onclick="copyCmd('connect-wifi ATM_SURVEILLANCE_5G')">connect-wifi [SSID]</span>            Connect adapter to target ATM Wi-Fi
  <span class="cmd-highlight" onclick="copyCmd('nmap 10.218.22.0/24')">nmap 10.218.22.0/24</span>            Discover Pi camera & Defender Hub
  <span class="cmd-highlight" onclick="copyCmd('ssh pi1@10.218.22.14')">ssh pi1@10.218.22.14</span>           SSH login to Pi Camera (Password: 123)
  <span class="cmd-highlight" onclick="copyCmd('inject --mismatch-port 8503')">inject --mismatch-port 8503</span>   MITM hijack & inject rogue video on bad port
  <span class="cmd-highlight" onclick="copyCmd('check-defender')">check-defender</span>                 Query PC 1 Defender Trust Score live
  <span class="cmd-highlight" onclick="copyCmd('reset')">reset</span>                          Restore genuine Pi camera feed and 99% trust
  <span class="cmd-highlight" onclick="copyCmd('clear')">clear</span>                          Clear terminal screen
==============================================================================`, "log-info");
}

function scanWifiNetworks() {
  appendLine("[*] Scanning wireless frequencies on wlan0 (2.4GHz & 5GHz)...", "log-info");
  setTimeout(() => {
    appendLine(`
[+] Visible Wireless Networks (4 BSSIDs):

  [1] <span style="color:#10b981; font-weight:700;">ATM_SURVEILLANCE_5G</span>
      BSSID: 8C:AA:B5:12:34:56 | Ch: 36 (5.18 GHz) | Signal: 96% (-42 dBm)
      Security: WPA2-Enterprise (AES-CCMP) | Target Camera Network!

  [2] Campus_Student_WLAN
      BSSID: 40:F2:01:88:91:A0 | Ch: 6 (2.4 GHz)   | Signal: 64% (-71 dBm)
      Security: Open / Web Portal

  [3] Banking_IoT_Infrastructure
      BSSID: D8:3A:DD:44:90:12 | Ch: 149 (5.74 GHz)| Signal: 52% (-78 dBm)
      Security: WPA3-SAE

  [4] DIRECT-RaspberryPi-Cam
      BSSID: B8:27:EB:AA:14:02 | Ch: 1 (2.4 GHz)   | Signal: 88% (-48 dBm)
      Security: WPA2-PSK

[*] To connect, type: <span class="cmd-highlight" onclick="copyCmd('connect-wifi ATM_SURVEILLANCE_5G')">connect-wifi ATM_SURVEILLANCE_5G</span>`, "log-success");
  }, 400);
}

function promptWifiConnect(ssid) {
  pendingWifiSSID = ssid;
  currentMode = "wifi_password";
  appendLine(`[*] Selected SSID: <span style="color:#38bdf8">${ssid}</span>`, "log-info");
  document.getElementById("promptLabel").innerText = `Enter WPA2 Key for '${ssid}': `;
}

function connectWifiWithKey(ssid, key) {
  currentMode = "normal";
  document.getElementById("promptLabel").innerText = "redteam@laptop2:~$ ";

  appendLine("[*] Generating WPA2 4-Way Handshake...", "log-info");
  setTimeout(() => {
    appendLine(`[+] Associated with BSSID 8C:AA:B5:12:34:56 on Channel 36.`, "log-success");
    appendLine(`[+] DHCP Discover -> DHCP ACK from 10.218.22.1`, "log-info");
    appendLine(`[+] Assigned IP Address: <span style="color:#10b981; font-weight:700;">10.218.22.163</span> (Netmask: 255.255.255.0)`, "log-success");
    appendLine(`[+] Gateway: 10.218.22.1 | DNS: 10.218.22.1, 8.8.8.8`, "log-info");
    appendLine(`[✓] SUCCESS: PC 2 is now switched and connected to <span style="color:#10b981; font-weight:700;">${ssid}</span>!`, "log-success");
    isWifiConnected = true;
    appendLine(`[*] Next step: Run <span class="cmd-highlight" onclick="copyCmd('nmap 10.218.22.0/24')">nmap 10.218.22.0/24</span> to discover camera nodes.`, "log-warn");
  }, 600);
}

async function runNmapScan(target) {
  appendLine(`[*] Starting Nmap 7.94 ( https://nmap.org ) at ${new Date().toLocaleTimeString()}...`, "log-info");
  appendLine(`[*] Scanning subnet ${target} across 1000 common surveillance ports...`, "log-info");

  try {
    const res = await fetch("/api/network/scan");
    const data = await res.json();

    setTimeout(() => {
      appendLine(`
Nmap scan report for <span style="color:#10b981; font-weight:700;">pi1-camera-node (10.218.22.14)</span>
Host is up (0.0018s latency).
PORT     STATE SERVICE REASON
22/tcp   open  ssh     OpenSSH 8.9p1 (Raspbian)
8080/tcp open  http    Motion Control Web Interface
8081/tcp open  rtsp/mjpeg Motion Live Surveillance Stream

Nmap scan report for <span style="color:#38bdf8; font-weight:700;">trustfusion-soc-defender (10.218.22.163)</span>
Host is up (0.0002s latency).
PORT     STATE SERVICE REASON
8502/tcp open  http    TrustFusion AI Master SOC Hub

Nmap done: 4 IP addresses (4 hosts up) scanned in ${data.scan_time_ms} ms.`, "log-success");

      appendLine(`[*] Discovered Raspberry Pi at <span style="color:#10b981">10.218.22.14</span>.`, "log-warn");
      appendLine(`[*] Next step: Type <span class="cmd-highlight" onclick="copyCmd('ssh pi1@10.218.22.14')">ssh pi1@10.218.22.14</span> to test credentials.`, "log-info");
    }, 500);

  } catch (err) {
    appendLine(`[-] Scan error: ${err}`, "log-danger");
  }
}

function runPing(host) {
  appendLine(`PING ${host} (${host}) 56(84) bytes of data.`, "log-info");
  let seq = 1;
  const timer = setInterval(() => {
    appendLine(`64 bytes from ${host}: icmp_seq=${seq} ttl=64 time=1.84 ms`);
    seq++;
    if (seq > 4) {
      clearInterval(timer);
      appendLine(`--- ${host} ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3004ms
rtt min/avg/max/mdev = 1.62/1.81/1.94/0.11 ms`, "log-success");
    }
  }, 300);
}

function startSshSession(target) {
  appendLine(`Connecting to ${target}...`, "log-info");
  currentMode = "ssh_password";
  document.getElementById("promptLabel").innerText = `${target}'s password: `;
}

function verifySshPassword(pass) {
  if (pass === "123" || pass === "raspberry") {
    currentMode = "ssh_session";
    document.getElementById("promptLabel").innerText = "pi1@raspberrypi:~ $ ";
    appendLine(`Linux raspberrypi 6.1.21-v8+ #1642 SMP PREEMPT Debian aarch64
The programs included with the Debian GNU/Linux system are free software.
Last login: Mon Nov 16 01:10:04 2026 from 10.218.22.163

[✓] SSH Session Established. You are logged into the physical Raspberry Pi!
Type <span class="cmd-highlight" onclick="copyCmd('ls')">ls</span>, <span class="cmd-highlight" onclick="copyCmd('ps aux | grep motion')">ps aux | grep motion</span>, or <span class="cmd-highlight" onclick="copyCmd('exit')">exit</span>.`, "log-success");
  } else {
    appendLine("Permission denied, please try again.", "log-danger");
    document.getElementById("promptLabel").innerText = "pi1@10.218.22.14's password: ";
  }
}

function handlePiSshCommand(cmd) {
  const parts = cmd.trim().split(/\s+/);
  const root = parts[0];

  if (root === "exit") {
    currentMode = "normal";
    document.getElementById("promptLabel").innerText = "redteam@laptop2:~$ ";
    appendLine("Connection to 10.218.22.14 closed.", "log-info");
    appendLine(`[*] Back on PC 2. Next: Execute the attack with <span class="cmd-highlight" onclick="copyCmd('inject --mismatch-port 8503')">inject --mismatch-port 8503</span>.`, "log-warn");
    return;
  }

  if (root === "ls") {
    appendLine("camera_sentinel  Desktop  Documents  motion.conf  videos", "log-info");
  } else if (root === "ifconfig" || root === "ip") {
    appendLine(`eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.218.22.14  netmask 255.255.255.0  broadcast 10.218.22.255`, "log-info");
  } else if (cmd.includes("motion")) {
    appendLine(`root      1142  4.2  3.8  98210 38412 ?  Ssl  01:00   0:15 /usr/bin/motion -c /etc/motion/motion.conf
pi1       1892  0.0  0.1   6124   892 pts/0    S+   01:15   0:00 grep motion`, "log-success");
  } else if (root === "pwd") {
    appendLine("/home/pi1", "log-info");
  } else {
    appendLine(`pi1: command '${escapeHtml(root)}' executed.`, "log-info");
  }
}

async function executeStreamInjection(parts) {
  appendLine("[*] Initializing MITM Stream Hijack & Port Mismatch Attack...", "log-info");
  appendLine("[*] Stage 1: Starting rogue looped MJPEG generator on Laptop 2 (Port: 8503)...", "log-info");
  appendLine("[*] Stage 2: Spoofing camera network ARP tables between Pi (10.218.22.14) & Defender (10.218.22.163)...", "log-info");
  appendLine("[!] Stage 3: Injecting rogue stream with PORT MISMATCH (Sending on port 8503, expected port 8081)...", "log-warn");
  appendLine("[!] Stage 4: Cryptographic HMAC telemetry stripped from injected frames...", "log-warn");

  try {
    const res = await fetch("/api/attack/launch/MITM", { method: "POST" });
    const data = await res.json();

    setTimeout(async () => {
      // Query defender live status
      const sRes = await fetch("/api/target/status");
      const sData = await sRes.json();
      const fusion = sData.fusion || {};

      appendLine(`
========================== ATTACK LAUNCH SUCCESS ==========================
[+] Stream redirected to: <span style="color:#f43f5e">http://10.218.22.163:8503/rogue_feed</span>
[+] Port Mismatch Triggered: <span style="color:#f59e0b">Port 8503 != 8081</span>
[+] Latency to Target: ${data.latency_ms} ms

🚨 LIVE DEFENDER RESPONSE ON PC 1:
   • Status Posture: <span class="log-danger">${fusion.status || 'CRITICAL_ATTACK'}</span>
   • Trust Score: <span class="log-danger">${fusion.trust_score || '25.0'}%</span> (Collapsed from 99%!)
   • Active Alerts: <span style="color:#f43f5e; font-weight:700;">${(fusion.active_alerts || ['PORT_MISMATCH', 'AUTH_FAILURE', 'VIDEO_REPLAY_LOOP']).join(', ')}</span>
   • AI Classification: <span style="color:#f59e0b">${fusion.ai_classification || 'FEED_SPOOFING_REPLAY_ATTACK'}</span>
   • Scene Verdict: <span style="color:#f43f5e">${fusion.cross_layer_decision ? fusion.cross_layer_decision.verdict : 'REPLAY_ATTACK'}</span>
===========================================================================`, "log-danger");

      appendLine(`[*] PC 1 Defender has successfully detected your attack and locked down surveillance!`, "log-success");
      appendLine(`[*] To restore the real Pi camera, type: <span class="cmd-highlight" onclick="copyCmd('reset')">reset</span>.`, "log-info");
    }, 700);

  } catch (err) {
    appendLine(`[-] Attack error: ${err}`, "log-danger");
  }
}

async function checkDefenderStatus() {
  appendLine("[*] Querying Defender Hub at http://10.218.22.163:8502/api/status...", "log-info");
  try {
    const res = await fetch("/api/target/status");
    const data = await res.json();
    const fusion = data.fusion || {};
    const trust = fusion.trust_score !== undefined ? fusion.trust_score : "N/A";
    const status = fusion.status || "UNKNOWN";
    const alerts = fusion.active_alerts || [];
    const src = data.camera_source || "Unknown";

    const color = trust < 40 ? "#ef4444" : (trust < 75 ? "#f59e0b" : "#10b981");

    appendLine(`
Target Hub: http://10.218.22.163:8502
Active Stream Source: ${src}
Trust Score: <span style="color:${color}; font-size:1.1rem; font-weight:800;">${trust}%</span> (${status})
Active Critical Alarms: ${alerts.length ? alerts.join(", ") : "None (All Secure)"}
Layer 1 Feed Health: ${fusion.layer1_feed_health}%
Layer 2 Network Health: ${fusion.layer2_net_health}%
YOLOv8 Occupancy: ${fusion.occupancy_state} (${fusion.num_persons} persons)
Cross-Layer Verdict: ${fusion.cross_layer_decision ? fusion.cross_layer_decision.badge : 'N/A'}`, "log-info");
  } catch (err) {
    appendLine(`[-] Cannot query defender: ${err}`, "log-danger");
  }
}

async function resetSystem() {
  appendLine("[*] Resetting all attack vectors & restoring genuine Pi camera feed...", "log-info");
  try {
    const res = await fetch("/api/attack/launch/RESET", { method: "POST" });
    const data = await res.json();

    setTimeout(async () => {
      const sRes = await fetch("/api/target/status");
      const sData = await sRes.json();
      const fusion = sData.fusion || {};

      appendLine(`
[✓] SYSTEM RESET COMPLETE:
   • Stream restored to: <span style="color:#10b981">${sData.camera_source}</span>
   • Defender Status: <span style="color:#10b981; font-weight:700;">${fusion.status}</span>
   • Trust Score: <span style="color:#10b981; font-weight:800;">${fusion.trust_score}%</span>
   • Active Alerts: [] (All Clear)`, "log-success");
    }, 600);
  } catch (err) {
    appendLine(`[-] Reset error: ${err}`, "log-danger");
  }
}

function escapeHtml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
