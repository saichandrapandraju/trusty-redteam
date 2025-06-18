import asyncio
import httpx
import websockets
import json
import sys
import argparse
from typing import Optional

async def test_streaming_scan(
    base_url: str = "http://localhost:8001",
    model_name: str = "qwen2", 
    endpoint: str = "http://localhost:8080/v1",
    scan_profile: str = "quick",
    plugin: str = "garak"
):
    """Test the WebSocket streaming functionality of the scan API"""
    
    print(f"🚀 Testing scan with WebSocket streaming")
    print(f"   Model: {model_name}")
    print(f"   Profile: {scan_profile}")
    print(f"   Plugin: {plugin}")
    print(f"   Endpoint: {endpoint}")
    print("-" * 50)
    
    scan_id: Optional[str] = None
    
    try:
        # 1. Start a scan
        async with httpx.AsyncClient(timeout=30.0) as client:
            print("📤 Starting scan...")
            response = await client.post(
                f"{base_url}/scan/start",
                json={
                    "plugin": plugin,
                    "model": {
                        "model_name": model_name,
                        "endpoint": endpoint
                    },
                    "scan_profile": scan_profile
                }
            )
            
            if response.status_code != 200:
                print(f"❌ Failed to start scan: {response.status_code}")
                print(f"   Response: {response.text}")
                return
                
            data = response.json()
            scan_id = data["scan_id"]
            stream_url = data["stream_url"]
            
            print(f"✅ Started scan: {scan_id}")
            print(f"🔗 Stream URL: {stream_url}")
            print()
        
        # 2. Monitor via WebSocket with better error handling
        ws_url = f"ws://localhost:8001/scan/{scan_id}/stream"
        print(f"🔌 Connecting to WebSocket: {ws_url}")
        
        results_count = 0
        vulnerabilities_count = 0
        
        try:
            async with websockets.connect(ws_url, ping_interval=30) as websocket:
                print("✅ WebSocket connected - listening for results...")
                print()
                
                while True:
                    try:
                        message = await asyncio.wait_for(websocket.recv(), timeout=60.0)
                        data = json.loads(message)
                        
                        if "error" in data:
                            print(f"❌ WebSocket error: {data['error']}")
                            break
                        
                        if data["type"] == "result":
                            result = data["data"]
                            progress = data.get("progress", {})
                            
                            results_count += 1
                            if result.get("vulnerable", False):
                                vulnerabilities_count += 1
                                status = "🔴 VULNERABLE"
                            else:
                                status = "🟢 SECURE"
                            
                            probe_name = result.get('probe', 'Unknown')
                            severity = result.get('severity', 'N/A')
                            
                            print(f"[{results_count:3d}] {probe_name} - {status}")
                            if result.get("vulnerable") and severity != 'N/A':
                                print(f"      └── Severity: {severity}")
                                
                            # Show progress
                            total_probes = progress.get("total_probes", results_count)
                            total_vulns = progress.get("vulnerabilities", vulnerabilities_count)
                            print(f"      📊 Progress: {total_probes} probes, {total_vulns} vulnerabilities")
                            print()
                            
                        elif data["type"] == "complete":
                            print("🎉 Scan completed!")
                            print(f"   Total results received via stream: {data.get('total_results', results_count)}")
                            print(f"   Final status: {data.get('status', 'Unknown')}")
                            break
                            
                        else:
                            print(f"📨 Unknown message type: {data.get('type', 'N/A')}")
                            
                    except asyncio.TimeoutError:
                        print("⏰ No message received in 60s, checking if scan is still running...")
                        # Check scan status
                        async with httpx.AsyncClient() as client:
                            status_response = await client.get(f"{base_url}/scan/{scan_id}/status")
                            if status_response.status_code == 200:
                                status_data = status_response.json()
                                if status_data["status"] != "running":
                                    print(f"📝 Scan status: {status_data['status']}")
                                    break
                            else:
                                print("❌ Failed to check scan status")
                                break
                        
        except websockets.exceptions.ConnectionClosed:
            print("🔌 WebSocket connection closed")
        except Exception as e:
            print(f"❌ WebSocket error: {e}")
            
        # 3. Get final results via HTTP API
        print()
        print("📋 Fetching final results via HTTP API...")
        
        async with httpx.AsyncClient() as client:
            # Wait a moment for scan to fully complete
            await asyncio.sleep(2)
            
            try:
                response = await client.get(f"{base_url}/scan/{scan_id}/results")
                if response.status_code == 200:
                    results = response.json()
                    
                    print("📊 Final Summary:")
                    print(f"   • Total probes: {results['total_probes']}")
                    print(f"   • Vulnerabilities found: {results['vulnerabilities_found']}")
                    
                    if 'duration_seconds' in results:
                        duration = results['duration_seconds']
                        if hasattr(duration, 'total_seconds'):
                            duration = duration.total_seconds()
                        print(f"   • Duration: {duration:.1f}s")
                    
                    if 'severity_breakdown' in results:
                        breakdown = results['severity_breakdown']
                        if breakdown:
                            print("   • Severity breakdown:")
                            for severity, count in breakdown.items():
                                print(f"     - {severity}: {count}")
                    
                    print(f"   • Started: {results.get('started_at', 'N/A')}")
                    print(f"   • Completed: {results.get('completed_at', 'N/A')}")
                    
                elif response.status_code == 400:
                    print("⏳ Scan not yet completed, checking status...")
                    status_response = await client.get(f"{base_url}/scan/{scan_id}/status")
                    if status_response.status_code == 200:
                        status_data = status_response.json()
                        print(f"   Current status: {status_data['status']}")
                        print(f"   Progress: {status_data.get('progress', {})}")
                else:
                    print(f"❌ Failed to get results: {response.status_code}")
                    print(f"   Response: {response.text}")
                    
            except Exception as e:
                print(f"❌ Error fetching results: {e}")
                
    except KeyboardInterrupt:
        print("\n🛑 Interrupted by user")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()

async def test_basic_endpoints(base_url: str = "http://localhost:8001"):
    """Test basic API endpoints"""
    print("🔍 Testing basic API endpoints...")
    
    async with httpx.AsyncClient() as client:
        try:
            # Test root endpoint
            response = await client.get(base_url)
            if response.status_code == 200:
                print("✅ Root endpoint working")
            else:
                print(f"❌ Root endpoint failed: {response.status_code}")
                
            # Test plugins endpoint
            response = await client.get(f"{base_url}/plugins")
            if response.status_code == 200:
                plugins = response.json()
                print(f"✅ Plugins endpoint working - {len(plugins.get('plugins', []))} plugins available")
                for plugin in plugins.get('plugins', []):
                    print(f"   • {plugin.get('name', 'Unknown')}: {plugin.get('description', 'No description')}")
            else:
                print(f"❌ Plugins endpoint failed: {response.status_code}")
                
        except Exception as e:
            print(f"❌ Error testing endpoints: {e}")

def main():
    parser = argparse.ArgumentParser(description="Test the scan API with WebSocket streaming")
    parser.add_argument("--url", default="http://localhost:8001", help="Base URL of the API")
    parser.add_argument("--model", default="qwen2", help="Model name to use")
    parser.add_argument("--endpoint", default="http://localhost:8080/v1", help="Model endpoint")
    parser.add_argument("--profile", default="quick", choices=["quick", "full"], help="Scan profile")
    parser.add_argument("--plugin", default="garak", help="Plugin to use")
    parser.add_argument("--test-endpoints", action="store_true", help="Test basic endpoints first")
    
    args = parser.parse_args()
    
    async def run_tests():
        if args.test_endpoints:
            await test_basic_endpoints(args.url)
            print()
        
        await test_streaming_scan(
            base_url=args.url,
            model_name=args.model,
            endpoint=args.endpoint,
            scan_profile=args.profile,
            plugin=args.plugin
        )
    
    try:
        asyncio.run(run_tests())
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
        sys.exit(0)

if __name__ == "__main__":
    main()