from pydantic_settings import BaseSettings
from typing import List, Dict, Any, Optional
from pathlib import Path
import os

class Settings(BaseSettings):
    # App
    app_name: str = "Universal LLM Red Team API"
    version: str = "0.0.1"
    log_level: str = "debug"
    development: bool = True
    
    # API
    host: str = "0.0.0.0"
    port: int = 8001

    # Directories
    base_dir: Path = Path(__file__).parent.parent
    tmp_dir: Path = base_dir / "tmp"
    
    # Plugins
    enabled_plugins: List[str] = ["garak"]
    plugin_configs: Dict[str, Dict[str, Any]] = {
        "garak": {
            "garak_path": "garak",
            "scan_report_dir": tmp_dir / "garak",
            "parallel_probes": 8,
            "timeout": 60*60*3,
            "cleanup_scan_dir_on_exit": False,
        }
    }

settings = Settings()

# create tmp dir for garak scan reports
settings.plugin_configs["garak"]["scan_report_dir"].mkdir(exist_ok=True)

# TODO: Remove this by using .getenv() when creating the generator options for garak
os.environ["OPENAICOMPATIBLE_API_KEY"] = "DUMMY"