import asyncio
import logging
import os
import time
import signal
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from trusty_redteam.schemas import ProcessState
from trusty_redteam.errors import ScanProcessError, ScanValidationError, ScanTimeoutError
from asyncio import StreamReader
logger = logging.getLogger(__name__)

class ProcessManager:
    """Manages subprocess lifecycle"""
    
    def __init__(self, scan_id: str, working_dir: Path):
        self.scan_id = scan_id
        self.working_dir = working_dir
        self.process: Optional[asyncio.subprocess.Process] = None
        self.state = ProcessState.STARTING
        self.start_time = None
        self.end_time = None
        self.stdout_buffer = []
        self.stderr_buffer = []
        self._cleanup_tasks = []
        
    async def __aenter__(self):
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.cleanup()
        
    async def start_process(self, cmd: List[str]) -> None:
        try:
            logger.info(f"[{self.scan_id}] Starting process: {' '.join(cmd)}")
            self.start_time = time.time()
            
            # Validate command
            if not cmd or not cmd[0]:
                raise ScanValidationError("Empty command provided")
                
            # Create process
            self.process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(self.working_dir),
                # Ensure process gets its own process group for better cleanup
                preexec_fn=os.setpgrp if os.name != 'nt' else None
            )
            
            self.state = ProcessState.RUNNING
            logger.info(f"[{self.scan_id}] Process started with PID: {self.process.pid}")
            
            # Start monitoring tasks
            self._start_monitoring_tasks()
            
        except FileNotFoundError as e:
            self.state = ProcessState.FAILED
            raise ScanProcessError(f"Command not found: {cmd[0]}. Please ensure Garak is installed and in PATH.") from e
        except PermissionError as e:
            self.state = ProcessState.FAILED
            raise ScanProcessError(f"Permission denied executing: {cmd[0]}. Check file permissions.") from e
        except Exception as e:
            self.state = ProcessState.FAILED
            raise ScanProcessError(f"Failed to start process: {str(e)}") from e
            
    def _start_monitoring_tasks(self):
        """Start background tasks for monitoring process output"""
        if self.process:
            self._cleanup_tasks.append(
                asyncio.create_task(self._monitor_stream(self.process.stdout, self.stdout_buffer, "stdout"))
            )
            self._cleanup_tasks.append(
                asyncio.create_task(self._monitor_stream(self.process.stderr, self.stderr_buffer, "stderr"))
            )

    async def _monitor_stream(self, stream:StreamReader, buffer:list, stream_name:str):
        """Generic stream monitoring method"""
        if not stream:
            return
            
        try:
            while True:
                line = await stream.readline()
                if not line:
                    break
                    
                decoded_line = line.decode().strip()
                buffer.append(decoded_line)
                
                # Keep buffer size manageable
                if len(buffer) > 1000:
                    buffer[:] = buffer[-500:]
                    
                # Special handling for stderr
                if stream_name == "stderr" and any(keyword in decoded_line.lower() 
                                                for keyword in ['error', 'warning', 'exception', 'failed']):
                    logger.warning(f"[{self.scan_id}] {stream_name.upper()}: {decoded_line}")
                else:
                    logger.debug(f"[{self.scan_id}] {stream_name.upper()}: {decoded_line}")
                    
        except Exception as e:
            logger.warning(f"[{self.scan_id}] Error monitoring {stream_name}: {e}")

    def check_process_completion(self):
        """Check if process has completed and update state accordingly"""
        if not self.process:
            return
        
        # Check if process has terminated
        if self.process.returncode is not None:
            if self.state == ProcessState.RUNNING:  # Only update if currently running
                self.end_time = time.time()
                
                if self.process.returncode == 0:
                    self.state = ProcessState.COMPLETED
                    logger.info(f"[{self.scan_id}] Process completed successfully with return code {self.process.returncode}")
                else:
                    self.state = ProcessState.FAILED
                    error_output = '\n'.join(self.stderr_buffer[-5:]) if self.stderr_buffer else "No error output"
                    logger.error(f"[{self.scan_id}] Process failed with return code {self.process.returncode}. Recent errors: {error_output}")

    def is_completed(self) -> bool:
        """Check if process is completed (success or failure)"""
        return self.state in [ProcessState.COMPLETED, ProcessState.FAILED, ProcessState.TIMEOUT, ProcessState.CANCELLED]
    
    def is_running(self) -> bool:
        """Check if process is still running"""
        return self.state == ProcessState.RUNNING and (not self.process or self.process.returncode is None)


    async def wait_for_completion(self, timeout: int = None) -> Tuple[int, str]:
        """Wait for process completion with timeout"""
        if not self.process:
            raise ScanProcessError("Process not started")
            
        try:
            if timeout:
                return_code = await asyncio.wait_for(
                    self.process.wait(), 
                    timeout=timeout
                )
            else:
                return_code = await self.process.wait()
                
            self.end_time = time.time()
            
            if return_code == 0:
                self.state = ProcessState.COMPLETED
                message = f"Process completed successfully in {self.end_time - self.start_time:.1f}s"
            else:
                self.state = ProcessState.FAILED
                error_output = '\n'.join(self.stderr_buffer[-10:]) if self.stderr_buffer else "No error output"
                message = f"Process failed with return code {return_code}. Last errors: {error_output}"
                
            logger.info(f"[{self.scan_id}] {message}")
            return return_code, message
            
        except asyncio.TimeoutError:
            self.state = ProcessState.TIMEOUT
            await self.terminate()
            raise ScanTimeoutError(f"Process timed out after {timeout}s")
            
    async def terminate(self):
        """Gracefully terminate the process"""
        if not self.process:
            return
            
        logger.info(f"[{self.scan_id}] Terminating process (PID: {self.process.pid})")
        
        try:
            # Try graceful termination first
            if self.process.returncode is None:
                if os.name != 'nt':
                    # On Unix, terminate the process group
                    try:
                        os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
                    except (ProcessLookupError, PermissionError):
                        self.process.terminate()
                else:
                    # On Windows
                    self.process.terminate()
                    
                # Wait for graceful termination
                try:
                    await asyncio.wait_for(self.process.wait(), timeout=10)
                    logger.info(f"[{self.scan_id}] Process terminated gracefully")
                except asyncio.TimeoutError:
                    # Force kill if graceful termination fails
                    logger.warning(f"[{self.scan_id}] Graceful termination failed, force killing")
                    if os.name != 'nt':
                        try:
                            os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                        except (ProcessLookupError, PermissionError):
                            self.process.kill()
                    else:
                        self.process.kill()
                    await self.process.wait()
                    
        except Exception as e:
            logger.error(f"[{self.scan_id}] Error terminating process: {e}")
            
        self.state = ProcessState.CANCELLED
        
    async def cleanup(self):
        """Cleanup resources"""
        # Cancel monitoring tasks
        for task in self._cleanup_tasks:
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                    
        # Terminate process if still running
        if self.process and self.process.returncode is None:
            await self.terminate()
            
        self._cleanup_tasks.clear()
        
    def get_diagnostics(self) -> Dict[str, Any]:
        """Get diagnostic information for debugging"""
        return {
            "scan_id": self.scan_id,
            "state": self.state.value,
            "pid": self.process.pid if self.process else None,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": self.end_time - self.start_time if self.end_time and self.start_time else None,
            "stdout_lines": len(self.stdout_buffer),
            "stderr_lines": len(self.stderr_buffer),
            "recent_stdout": self.stdout_buffer[-5:] if self.stdout_buffer else [],
            "recent_stderr": self.stderr_buffer[-5:] if self.stderr_buffer else [],
        }