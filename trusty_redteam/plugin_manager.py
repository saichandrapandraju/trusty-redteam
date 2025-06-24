from typing import Dict, Optional, List
import importlib
from trusty_redteam.schemas import PluginInfo
from trusty_redteam.plugins.base import BasePlugin
from trusty_redteam.config import settings
import logging
logger = logging.getLogger(__name__)

class PluginManager:
    """Plugin manager with core features"""
    
    def __init__(self):
        self.plugins: Dict[str, BasePlugin] = {}
        self._initialized = False
        
    async def initialize(self):
        """Initialize enabled plugins"""
        if self._initialized:
            return
            
        for plugin_name in settings.enabled_plugins:
            try:
                await self.load_plugin(plugin_name)

            except Exception as e:
                logger.error(f"Failed to load plugin {plugin_name}: {e}")
                
        self._initialized = True
        logger.info(f"Initialized {len(self.plugins)} plugins")
        
    async def load_plugin(self, name: str):
        """Load a specific plugin"""
        try:
            # FIXME: This is a hack to find the plugin class
            # Import plugin module
            module = importlib.import_module(f"trusty_redteam.plugins.{name}.{name}")
            # Find plugin class ( FIXME: assumes it ends with 'Plugin')
            plugin_class = None
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (isinstance(attr, type) and 
                    attr_name.lower().endswith('plugin') and
                    attr_name.lower() != 'baseplugin'):
                    plugin_class = attr
                    break
                    
            if not plugin_class:
                raise ValueError(f"No plugin class found in {name}")
                
            # Create instance with config
            config = settings.plugin_configs.get(name, {})
            plugin: BasePlugin = plugin_class(config)
            await plugin.initialize()
            
            self.plugins[name] = plugin
            logger.info(f"Loaded plugin: {name}")
            
        except Exception as e:
            logger.error(f"Error loading plugin {name}: {e}")
            raise
            
    def get_plugin(self, name: str) -> Optional[BasePlugin]:
        """Get a loaded plugin"""
        return self.plugins.get(name)
        
    def list_plugins(self) -> List[PluginInfo]:
        """List all loaded plugins"""
        return [
            plugin.get_info() 
            for plugin in self.plugins.values()
        ]
        
    async def cleanup(self):
        """Cleanup all plugins"""
        for name, plugin in self.plugins.items():
            try:
                await plugin.cleanup()
            except Exception as e:
                logger.error(f"Error cleaning up plugin {name}: {e}")
                
        self.plugins.clear()
        self._initialized = False

# Global instance
plugin_manager = PluginManager()