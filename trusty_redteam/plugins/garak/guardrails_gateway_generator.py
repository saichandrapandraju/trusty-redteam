import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import time
import threading
import sys
import traceback
from typing import List, Union
from trusty_redteam.config import settings
import logging

logger = logging.getLogger(__name__)

CHAT_COMPLETIONS = "chat/completions"
DETECTION_DUMMY_MESSAGE = "I am sorry, I cannot help with that." # TODO: How to handle this in an interactive mode?
session = None

def get_session() -> requests.Session:
    global session
    if session is None:
        session = requests.Session()

        retry_strategy = Retry(
            total=5,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        parallel_probes = settings.plugin_configs.get("garak", {}).get("parallel_probes", 5)
        total_concurrent = parallel_probes + 10     # extra buffer

        logger.debug(f"Configuring connection pool for {total_concurrent} concurrent connections")

        adapter = HTTPAdapter(
            pool_connections=total_concurrent,
            pool_maxsize=total_concurrent,
            max_retries=retry_strategy
            )
        
        session.mount("http://", adapter)
        session.mount("https://", adapter)

    return session

def guardrails_gateway(prompt: str, **kwargs) -> List[Union[str, None]]:
    """Single Response Garak custom generator."""
    
    debug_file = "/tmp/garak_debug.log"
    
    def debug_log(message):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        thread_id = threading.get_ident()
        with open(debug_file, "a") as f:
            f.write(f"[{timestamp}] Thread-{thread_id}: {message}\n")
            f.flush()
    
    try:
        debug_log(f"=== FUNCTION CALLED ===")
        debug_log(f"Prompt: {prompt[:100]}...")
        debug_log(f"Kwargs: {kwargs}")
        debug_log(f"Module name: {__name__}")
        debug_log(f"Python path: {sys.path}")

        if "uri" not in kwargs:
            raise ValueError("'uri' is required for Guardrails Gateway models")
        gateway_route: str = kwargs["uri"].rstrip("/")

        if "model" not in kwargs:
            raise ValueError("'model' is required for Guardrails Gateway models")
        model_name: str = kwargs["model"]

        if not gateway_route.endswith(CHAT_COMPLETIONS):
            gateway_route = f"{gateway_route}/{CHAT_COMPLETIONS}"

        payload = {
            "model": model_name,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": kwargs.get("temperature", 0.6),
            "max_tokens": kwargs.get("max_tokens", 60),
            "top_p": kwargs.get("top_p", 1.0),
        }
        
        debug_log(f"Payload prepared: {payload}")
        
        session = get_session()
        # Light monitoring - track request timing
        start_time = time.time()
        debug_log("Session obtained")
        
        debug_log("Making HTTP request...")
        response = session.post(
            gateway_route, 
            headers={"Content-Type": "application/json"}, 
            json=payload,
            timeout=(10, 30)
        )
        response_time = time.time() - start_time
        
        # Log slow requests (could indicate overload)
        if response_time > 5.0:
            debug_log(f"Slow request: {response_time:.2f}s for prompt: {prompt[:30]}...")
        
        
        debug_log(f"HTTP response: {response.status_code}")
        
        if response.status_code != 200:
            error_msg = f"HTTP Error {response.status_code}: {response.text}"
            debug_log(f"HTTP Error: {error_msg}")
            raise GuardrailsGatewayError(error_msg)
        
        response_json = response.json()
        debug_log(f"Response JSON keys: {list(response_json.keys())}")
        
        if "detections" in response_json and response_json["detections"]:
            debug_log("Detection triggered, returning dummy message")
            return [DETECTION_DUMMY_MESSAGE]
        
        if response_json.get("choices"):
            result = [c["message"]["content"] for c in response_json["choices"]]
            debug_log(f"Returning choices: {result}")
            return result
        
        debug_log("No choices in response, returning dummy message")
        raise GuardrailsGatewayError("Invalid response from Guardrails Gateway. No choices/detections in response.")
    
    except Exception as e:
        debug_log(f"EXCEPTION: {str(e)}")
        debug_log(f"TRACEBACK: {traceback.format_exc()}")
        # Return a valid response even on error
        raise GuardrailsGatewayError(f"Function error: {str(e)}")

# Custom exception class for Guardrails Gateway errors
class GuardrailsGatewayError(Exception):
    pass