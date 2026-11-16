===================================================================================
  🔴 COLLEGE PRESENTATION ATTACK EXECUTION CHEAT SHEET (PC 2 RED TEAM)
  Target Camera: Raspberry Pi (10.218.22.14:8081)
  Target Defender: TrustFusion AI SOC on PC 1 (10.218.22.163:8502)
  Attacker Laptop: PC 2 Console (http://10.218.22.163:8503)
===================================================================================

Open the PC 2 terminal in your browser on Laptop 2:
👉 http://10.218.22.163:8503

Follow these exact steps during your demonstration:

-----------------------------------------------------------------------------------
STEP 1: SCAN FOR SURVEILLANCE WI-FI NETWORKS
-----------------------------------------------------------------------------------
Command:
scan-wifi

Explanation for Evaluator:
"Here we scan the 2.4GHz and 5GHz wireless spectrum to discover the target banking surveillance network SSID ('ATM_SURVEILLANCE_5G')."

-----------------------------------------------------------------------------------
STEP 2: CONNECT PC 2 TO THE ATM SURVEILLANCE WI-FI
-----------------------------------------------------------------------------------
Command:
connect-wifi ATM_SURVEILLANCE_5G

Password Prompt:
ATM_SECURE_2026   (or press Enter)

Explanation for Evaluator:
"Laptop 2 associates with the ATM surveillance Wi-Fi network and obtains a local IP (10.218.22.163) on the same subnet as the camera."

-----------------------------------------------------------------------------------
STEP 3: NETWORK SWEEP & DEVICE RECONNAISSANCE
-----------------------------------------------------------------------------------
Command:
nmap 10.218.22.0/24

Explanation for Evaluator:
"We perform port scanning to locate the physical camera node at 10.218.22.14 running OpenSSH on port 22 and the surveillance video stream on port 8081."

-----------------------------------------------------------------------------------
STEP 4: VERIFY CREDENTIALS & LOGIN VIA SSH TO RASPBERRY PI
-----------------------------------------------------------------------------------
Command:
ssh pi1@10.218.22.14

Password:
123

What to run inside the Pi shell (pi1@raspberrypi:~ $):
ls
ps aux | grep motion
exit

Explanation for Evaluator:
"We verify SSH access to the camera hardware and inspect the running Motion surveillance service before executing the interception."

-----------------------------------------------------------------------------------
STEP 5: EXECUTE STREAM HIJACK WITH PORT MISMATCH & ROGUE VIDEO INJECTION
-----------------------------------------------------------------------------------
Command:
inject --mismatch-port 8503

Explanation for Evaluator:
"Laptop 2 ARP-poisons the connection, intercepts the genuine Raspberry Pi video feed, and forces PC 1 Defender to receive our looped empty-room recording. Crucially, the stream arrives from a mismatched port (8503 instead of the authorized camera port 8081) with NO hardware HMAC cryptographic token."

Expected Result on PC 1 Defender:
- Trust Score instantly drops from 99% to 25.0% (CRITICAL_ATTACK)
- Active Alarms fired: ['PORT_MISMATCH', 'AUTH_FAILURE', 'VIDEO_REPLAY_LOOP']
- AI Classification: FEED_SPOOFING_REPLAY_ATTACK
- Video HUD on PC 1 flashes red alarm banner!

-----------------------------------------------------------------------------------
STEP 6: CHECK DEFENDER STATUS LIVE FROM TERMINAL
-----------------------------------------------------------------------------------
Command:
check-defender

Explanation for Evaluator:
"We query PC 1's REST API from our terminal to confirm that the TrustFusion cross-layer engine detected our port mismatch, invalid HMAC, and cyclical loop."

-----------------------------------------------------------------------------------
STEP 7: RESET & RESTORE GENUINE FEED
-----------------------------------------------------------------------------------
Command:
reset

Explanation for Evaluator:
"We stop the attack, restoring the authentic Raspberry Pi camera feed. TrustFusion AI automatically validates the fresh HMAC token and normalizes the Trust Score back to 99% SECURE."
===================================================================================
