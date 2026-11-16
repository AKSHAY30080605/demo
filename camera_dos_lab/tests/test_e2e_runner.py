import asyncio
import websockets
import json
import time

async def run_full_e2e():
    print("[1] Connecting to ws://localhost:8000/ws/dashboard...")
    async with websockets.connect('ws://localhost:8000/ws/dashboard') as ws_dash:
        raw = await ws_dash.recv()
        st = json.loads(raw)
        lbl = st['verdict']['label']
        print(f"    Initial Dashboard Verdict: {lbl} (Confidence: {st['verdict']['confidence']})")
        assert lbl == 'BENIGN', f"Expected BENIGN, got {lbl}"

        print("[2] Connecting to ws://localhost:8000/ws/control...")
        async with websockets.connect('ws://localhost:8000/ws/control') as ws_ctrl:
            await ws_ctrl.recv() # Initial state

            # Test A: SYN Flood Preset
            print("[3] Sending preset: syn_flood from PC2...")
            await ws_ctrl.send(json.dumps({'type': 'preset', 'name': 'syn_flood'}))
            
            for _ in range(5):
                raw = await ws_dash.recv()
                st = json.loads(raw)
                if st['verdict']['label'] == 'SYN Flood':
                    break
            print(f"    Dashboard received: {st['verdict']['label']} (Confidence: {st['verdict']['confidence']})")
            assert st['verdict']['label'] == 'SYN Flood'
            print(f"    Attribution top feature: {st['explain'][0]['feature']} ({st['explain'][0]['contribution']}%)")

            # Test B: Reset
            print("[4] Sending reset from PC2...")
            await ws_ctrl.send(json.dumps({'type': 'reset'}))
            for _ in range(5):
                raw = await ws_dash.recv()
                st = json.loads(raw)
                if st['verdict']['label'] == 'BENIGN':
                    break
            print(f"    Dashboard restored: {st['verdict']['label']}")
            assert st['verdict']['label'] == 'BENIGN'

            # Test C: UDP Flood Preset
            print("[5] Sending preset: udp_flood from PC2...")
            await ws_ctrl.send(json.dumps({'type': 'preset', 'name': 'udp_flood'}))
            for _ in range(5):
                raw = await ws_dash.recv()
                st = json.loads(raw)
                if st['verdict']['label'] == 'UDP Flood':
                    break
            print(f"    Dashboard received: {st['verdict']['label']} (Confidence: {st['verdict']['confidence']})")
            assert st['verdict']['label'] == 'UDP Flood'

            # Test D: Reset again
            print("[6] Sending reset from PC2...")
            await ws_ctrl.send(json.dumps({'type': 'reset'}))
            for _ in range(5):
                raw = await ws_dash.recv()
                st = json.loads(raw)
                if st['verdict']['label'] == 'BENIGN':
                    break
            print(f"    Dashboard restored: {st['verdict']['label']}")
            assert st['verdict']['label'] == 'BENIGN'

    print("\n======================================================")
    print(">>> ALL WEBSOCKET & ML INFERENCE TESTS PASSED 100% <<<")
    print("======================================================")

if __name__ == '__main__':
    asyncio.run(run_full_e2e())
