# Universal API for LLM Red Teaming

A streamlined API for LLM vulnerability testing.

## Features

- ✅ **Garak Integration** - Full vulnerability scanning
- ✅ **Scan Profiles** - Quick, Standard, Comprehensive
- ✅ **Real-time Streaming** - WebSocket support
- ✅ **vLLM Support** - OpenAI-compatible endpoints

## Quick Start

1. **Install**
   ```bash
   pip install -e .
   ```

2. **Run Server**
   ```bash
   redteam-server --port <default-8001> --host <default-0.0.0.0>
   ```
3. **API Docs**
   Check the swagger at http://localhost:8001/docs

3. **Example Usage**
   ```python
   # Start scan
   response = requests.post("http://localhost:8001/scan/start", json={
      "model": {
         "model_name": "vllm-model-name",
         "endpoint": "http://vllm-server:port/v1"
      },
      "scan_profile": "quick"
   })

   scan_id = response.json()["scan_id"]

   # Get status
   status = requests.get(f"http://localhost:8001/scan/{scan_id}/status")
   print(status.json())

   # Get results
   results = requests.get(f"http://localhost:8001/scan/{scan_id}/results")
   print(results.json())
   ```

## API Endpoints

- `GET /` - API info

- `GET /plugins` - List plugins

- `POST /scan/start` - Start scan

- `GET /scan/{id}/status` - Check status

- `GET /scan/{id}/results` - Get results

- `WS /scan/{id}/stream` - Live stream

## Scan Profiles

- **Quick** - Essential tests (~5 min)

- **Standard** - Must test scenarios (~30 min)

- **Comprehensive** - All tests (>2 hrs)
