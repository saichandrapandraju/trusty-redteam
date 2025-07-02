class ScanError(Exception):
    """Base exception for scan errors"""
    pass

class ProcessError(ScanError):
    """Process execution related errors"""
    pass

class ValidationError(ScanError):
    """Input validation errors"""
    pass

class TimeoutError(ScanError):
    """Timeout related errors"""
    pass

class ResourceError(ScanError):
    """Resource management errors"""
    pass