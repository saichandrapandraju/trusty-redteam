# Universal API for LLM Red Teaming

A streamlined API for LLM vulnerability testing that supports both raw LLMs (via OpenAI compatible endpoint) and complete guardrailed systems (via [FMS Orchestrator Gateway](https://github.com/trustyai-explainability/vllm-orchestrator-gateway)).

## Features

- ✅ **Garak Integration** - Full vulnerability scanning
- ✅ **Scan Profiles** - Quick, Standard, Comprehensive
- ✅ **Real-time Streaming** - WebSocket support
- ✅ **Dual Testing Modes** - Test raw LLMs or complete guardrailed systems
- ✅ **Multiple Providers** - OpenAI-compatible (vLLM server) and Guardrails Gateway (FMS Orchestrator)support

## Testing Modes

### Raw LLM Testing (OpenAI Compatible)
Test LLMs directly via OpenAI-compatible APIs (vLLM)
- **Use case**: Evaluate base model vulnerabilities
- **Provider**: `openai.OpenAICompatible`

### Guardrailed System Testing (Guardrails Gateway)
Test complete guardrailed systems that include safety filters and policies
- **Use case**: Evaluate end-to-end system security including guardrails effectiveness
- **Provider**: `guardrails_gateway`

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

## Example Usage

### Testing Raw LLM (vLLM/OpenAI Compatible)
```python
response = requests.post("http://localhost:8001/scan/start", json={
   "model": {
      "model_name": "your-model-name",
      "endpoint": "http://vllm-server:port/v1",
      "provider": "openai.OpenAICompatible"
   },
   "scan_profile": "quick"
})
```

### Testing Guardrailed System
```python
response = requests.post("http://localhost:8001/scan/start", json={
   "model": {
      "model_name": "your-model-name", 
      "endpoint": "http://guardrails-gateway-server:port/all/v1",
      "provider": "guardrails_gateway"
   },
   "scan_profile": "quick"
})
```

### Get Results
```python
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
- `GET /plugins` - List avilable plugins
- `POST /scan/start` - Start vulnerability scan
- `GET /scan/{id}/status` - Check scan status
- `GET /scan/{id}/results` - Get scan results
- `WS /scan/{id}/stream` - Real-time results stream

## Scan Profiles

- **Quick** - Essential tests (~5 min)
- **Standard** - Must test scenarios (~1 hr)
- **Comprehensive** - All tests (>2 hrs)

## Providers

| Provider | Description | Use Case |
|----------|-------------|----------|
| `openai.OpenAICompatible` | Direct LLM testing via OpenAI API | Raw model vulnerability assessment |
| `guardrails_gateway` | Guardrailed system testing | End-to-end system security evaluation |
