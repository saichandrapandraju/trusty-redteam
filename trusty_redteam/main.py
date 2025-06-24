from fastapi import FastAPI, HTTPException, WebSocket, BackgroundTasks
from contextlib import asynccontextmanager
from typing import Dict
import asyncio
from datetime import datetime
import uuid
import argparse

from trusty_redteam.config import settings
from trusty_redteam.plugin_manager import plugin_manager
from trusty_redteam.plugins.base import BasePlugin
from trusty_redteam.schemas import (
    ScanRequest, ScanStatus, 
    ScanResult, RequestStatus, TestResult
)
import logging

logger = logging.getLogger(__name__)

# FIXME: Improve this
active_scans: Dict[str, dict] = {}

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan"""
    await plugin_manager.initialize()
    yield
    await plugin_manager.cleanup()

app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    lifespan=lifespan
)

@app.get("/")
async def root():
    return {
        "name": settings.app_name,
        "version": settings.version,
        "endpoints": [
            "/plugins",
            "/scan/start",
            "/scan/{scan_id}/status",
            "/scan/{scan_id}/results",
            "/scan/{scan_id}/stream"
        ]
    }

# Plugin endpoints
@app.get("/plugins")
async def list_plugins():
    """List available plugins"""
    return {
        "plugins": [p.model_dump() for p in plugin_manager.list_plugins()]
    }

# Scan endpoints
@app.post("/scan/start")
async def start_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks
):
    """Start a vulnerability scan"""

    plugin = plugin_manager.get_plugin(request.plugin)
    if not plugin:
        raise HTTPException(404, f"{request.plugin} plugin not available")
        
    scan_id = str(uuid.uuid4())
    
    # Initialize scan tracking
    active_scans[scan_id] = {
        "status": RequestStatus.RUNNING,
        "started_at": datetime.utcnow(),
        "model": request.model,
        "scan_profile": request.scan_profile,
        "results": [],
        "progress": {
            "total_probes": 0,
            "vulnerabilities": 0
        }
    }
    
    # Start scan in background
    background_tasks.add_task(
        run_scan_task,
        scan_id,
        plugin,
        request
    )
    
    return {
        "scan_id": scan_id,
        "status": RequestStatus.RUNNING,
        "message": f"Started {request.scan_profile} scan",
        "stream_url": f"/scan/{scan_id}/stream"
    }


async def run_scan_task(scan_id: str, plugin: BasePlugin, request: ScanRequest):
    """Background task to run scan"""
    scan_data = active_scans[scan_id]
    
    try:
        # Run scan and collect results (async)
        async for result in plugin.run_scan(
            request.model,
            request.scan_profile.value,
            request.custom_probes,
            request.extra_params
        ):
            assert isinstance(result, TestResult), f"Expected TestResult, got {type(result)}"
            scan_data["results"].append(result)
            
            # Update progress counters
            scan_data["progress"]["total_probes"] += 1
            if result.vulnerable:
                scan_data["progress"]["vulnerabilities"] += 1
        
        # Calculate severity & attack_type breakdown
        severity_breakdown = {}
        attack_type_breakdown = {}

        for result in scan_data["results"]:
            result: TestResult = result
            attack_type_breakdown[result.attack_type.value] = attack_type_breakdown.get(result.attack_type.value, {})
            attack_type_breakdown[result.attack_type.value][result.probe] = attack_type_breakdown[result.attack_type.value].get(result.probe, {})
            attack_type_breakdown[result.attack_type.value][result.probe]['total_probes'] = attack_type_breakdown[result.attack_type.value][result.probe].get('total_probes', 0) + 1
            if 'vulnerabilities' not in attack_type_breakdown[result.attack_type.value][result.probe]:
                attack_type_breakdown[result.attack_type.value][result.probe]['vulnerabilities'] = 0
            if result.vulnerable:
                attack_type_breakdown[result.attack_type.value][result.probe]['vulnerabilities'] += 1 
            if result.severity:
                severity_name = result.severity.value
                severity_breakdown[severity_name] = \
                    severity_breakdown.get(severity_name, 0) + 1
        
        if "summary" not in scan_data:
            scan_data["summary"] = {}
        scan_data["summary"]["severity_breakdown"] = severity_breakdown
        scan_data["summary"]["attack_type_breakdown"] = attack_type_breakdown
                
        # Mark complete
        scan_data["status"] = RequestStatus.COMPLETED
        scan_data["completed_at"] = datetime.utcnow()
        
    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}")
        scan_data["status"] = RequestStatus.FAILED
        scan_data["error"] = str(e)

@app.get("/scan/{scan_id}/status")
async def get_scan_status(scan_id: str):
    """Get scan status"""
    if scan_id not in active_scans:
        raise HTTPException(404, "Scan not found")
        
    scan_data = active_scans[scan_id]
    
    return ScanStatus(
        scan_id=scan_id,
        status=scan_data["status"],
        started_at=scan_data["started_at"],
        completed_at=scan_data.get("completed_at"),
        progress=scan_data["progress"],
        summary=scan_data.get("summary", {})
    )

@app.get("/scan/{scan_id}/results")
async def get_scan_results(scan_id: str):
    """Get scan results with efficient summary"""
    if scan_id not in active_scans:
        raise HTTPException(404, "Scan not found")
        
    scan_data = active_scans[scan_id]

    if scan_data["status"] != RequestStatus.COMPLETED:
        raise HTTPException(400, "Scan not completed")
    
    severity_breakdown = scan_data["summary"].get("severity_breakdown", {})
    attack_type_breakdown = scan_data["summary"].get("attack_type_breakdown", {})
    total_probes = scan_data["progress"]["total_probes"]
    vulnerabilities_found = scan_data["progress"]["vulnerabilities"]
                
    duration = 0
    if scan_data.get("completed_at"):
        duration = (scan_data["completed_at"] - scan_data["started_at"]).total_seconds()
        
    return ScanResult(
        scan_id=scan_id,
        model=scan_data["model"],
        scan_profile=scan_data["scan_profile"],
        started_at=scan_data["started_at"],
        completed_at=scan_data.get("completed_at", datetime.utcnow()),
        duration_seconds=duration,
        total_probes=total_probes,
        vulnerabilities_found=vulnerabilities_found,
        severity_breakdown=severity_breakdown,
        attack_type_breakdown=attack_type_breakdown,
        results=scan_data["results"]
    )

@app.websocket("/scan/{scan_id}/stream")
async def scan_stream(websocket: WebSocket, scan_id: str):
    """Stream scan results via WebSocket"""
    await websocket.accept()
    
    if scan_id not in active_scans:
        await websocket.send_json({"error": "Scan not found"})
        await websocket.close()
        return
        
    scan_data = active_scans[scan_id]
    last_sent = 0
    
    try:
        while scan_data["status"] == RequestStatus.RUNNING:
            # Send new results
            results = scan_data["results"]
            if len(results) > last_sent:
                for i in range(last_sent, len(results)):
                    await websocket.send_json({
                        "type": "result",
                        "data": results[i].model_dump(mode='json'),
                        "progress": scan_data["progress"]
                    })
                last_sent = len(results)
                
            await asyncio.sleep(1)
            
        # Send completion
        await websocket.send_json({
            "type": "complete",
            "status": scan_data["status"],
            "total_results": len(scan_data["results"])
        })
        
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        await websocket.close()

def run_server():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=settings.port)
    parser.add_argument("--host", type=str, default=settings.host)
    args = parser.parse_args()
    
    import uvicorn
    uvicorn.run(
        "trusty_redteam.main:app",
        host=args.host,
        port=args.port,
        reload=settings.debug
    )

if __name__ == "__main__":
    run_server()