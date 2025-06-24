from pydantic_settings import BaseSettings
from typing import List, Dict, Any, Optional
from pathlib import Path
import os

class Settings(BaseSettings):
    # App
    app_name: str = "Universal LLM Red Team API"
    version: str = "0.0.1"
    debug: bool = True
    
    # API
    host: str = "0.0.0.0"
    port: int = 8001

    # Directories
    base_dir: Path = Path(__file__).parent.parent
    logs_dir: Path = base_dir / "logs"
    tmp_dir: Path = base_dir / "tmp"
    
    # Plugins
    enabled_plugins: List[str] = ["garak"]
    plugin_configs: Dict[str, Dict[str, Any]] = {
        "garak": {
            "working_dir": tmp_dir / "garak",
            "parallel_probes": 8,
            "timeout": 60*60*3
        }
    }
    
    # Garak specific
    garak_path: str = "garak"
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()

# Create directories
settings.logs_dir.mkdir(exist_ok=True)
settings.tmp_dir.mkdir(exist_ok=True)
settings.plugin_configs["garak"]["working_dir"].mkdir(exist_ok=True)
os.environ["OPENAICOMPATIBLE_API_KEY"] = "DUMMY"