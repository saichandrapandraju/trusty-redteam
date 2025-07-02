from abc import ABC, abstractmethod
from typing import List, Dict, Any, AsyncIterator
from trusty_redteam.schemas import ModelInfo, TestResult, PluginInfo

class BasePlugin(ABC):
    """Base plugin interface"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.name = self.__class__.__name__
        
    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the plugin"""
        pass
        
    @abstractmethod
    async def run_scan(
        self,
        scan_id: str,
        model: ModelInfo,
        scan_profile: str = "quick",
        custom_probes: List[str] = None,
        extra_params: Dict[str, Any] = None
    ) -> AsyncIterator[TestResult]:
        """Run vulnerability scan"""
        pass
        
    @abstractmethod
    def get_info(self) -> PluginInfo:
        """Get plugin information"""
        pass
        
    async def cleanup(self) -> None:
        """Cleanup resources"""
        pass