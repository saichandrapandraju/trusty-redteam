from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from enum import Enum
from datetime import datetime
import uuid

# Enums
class AttackType(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    TOXICITY = "toxicity"
    BIAS = "bias"
    CUSTOM = "custom"

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class ScanProfile(str, Enum):
    QUICK = "quick"
    STANDARD = "standard"
    COMPREHENSIVE = "comprehensive"
    CUSTOM = "custom"

class RequestStatus(str, Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class Provider(str, Enum):
    """Provider of the model"""
    OPENAI_COMPATIBLE = "openai.OpenAICompatible"
    GUARDRAILS_GATEWAY = "guardrails_gateway"

class ProcessState(str, Enum):
    STARTING = "starting"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"

# Models
class ModelInfo(BaseModel):
    """Target model information"""
    model_name: str
    endpoint: str
    provider: Provider = Provider.OPENAI_COMPATIBLE  # vLLM is OpenAI-compatible

    
class TestResult(BaseModel):
    """Individual test result"""
    result_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    probe: str
    attack_type: AttackType
    prompt: str
    responses: List[Optional[str]] = []
    vulnerable: bool
    severity: Optional[Severity] = None
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    evidence: List[str] = []
    execution_time: Optional[float] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = {}

class ScanRequest(BaseModel):
    """Scan request"""
    model: ModelInfo
    scan_profile: ScanProfile = ScanProfile.QUICK
    custom_probes: Optional[List[str]] = None
    plugin: str = "garak"   # TODO: Enum?
    extra_params: Optional[Dict[str, Any]] = None

class ScanStatus(BaseModel):
    """Scan status response"""
    scan_id: str
    status: RequestStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    progress: Dict[str, Any] = {}
    summary: Dict[str, Any] = {}
    error: Optional[str] = None
    error_type: Optional[str] = None
    user_action: Optional[str] = None

class ScanResult(BaseModel):
    """Complete scan result"""
    scan_id: str
    model: ModelInfo
    scan_profile: str
    started_at: datetime
    completed_at: datetime
    duration_seconds: float
    total_probes: int
    vulnerabilities_found: int
    severity_breakdown: Dict[str, int]
    attack_type_breakdown: Dict[str, Any]
    results: List[TestResult]

class PluginInfo(BaseModel):
    """Plugin information"""
    name: str
    version: str
    description: str
    supported_attacks: List[AttackType]
    features: List[str]