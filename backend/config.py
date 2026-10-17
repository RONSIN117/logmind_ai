"""
LogMind Configuration & LinuxONE System Metadata
"""
import os
import platform

class Config:
    PROJECT_NAME = "LogMind"
    VERSION = "2.1.0"
    TRACK = "AI Secured: Innovation Without Exposure"
    SECONDARY_TRACK = "Real-Time AI for Critical Decisions"
    
    # LinuxONE / IBM Z Architecture Metadata
    TARGET_ARCH = "s390x"
    PLATFORM_NAME = "IBM LinuxONE III / Emperor 4 (s390x Enterprise Enclave)"
    ENCLAVE_MODE = "IBM Secure Execution (Confidential Computing)"
    CRYPTO_ACCELERATOR = "CPACF / Crypto Express8S active"
    IS_S390X = platform.machine().lower() in ["s390x", "s390"]
    
    # Upload Data Guard Settings
    MAX_UPLOAD_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB
    ALLOWED_EXTENSIONS = {".log", ".txt", ".csv", ".json"}
    
    # Severity & Security Constraints
    SEVERITY_LEVELS = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    DEFAULT_SEVERITY_FLOOR = "HIGH"
    
    # LLM Settings
    MAX_TOKENS = 512
    TEMPERATURE = 0.1
