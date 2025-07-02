class ScanError(Exception):
    """Base exception for scan errors"""
    pass

class ScanProcessError(ScanError):
    """Process execution related errors"""
    pass

class ScanValidationError(ScanError):
    """Input validation errors"""
    pass

class ScanTimeoutError(ScanError):
    """Timeout related errors"""
    pass

class ScanResourceError(ScanError):
    """Resource management errors"""
    pass