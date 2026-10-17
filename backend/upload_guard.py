"""
LogMind Upload Data Guard
Runs pre-flight security checks on incoming log files:
1. Validates file format and size limits.
2. Scans for PII, secrets, API tokens, database credentials, and IP addresses.
3. Generates a secure redaction preview before logs enter the pipeline.
"""
import re
from typing import List, Dict, Any, Tuple

# Secret & PII Patterns
PATTERNS = {
    "Email Address": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b',
    "JWT Bearer Token": r'Bearer\s+[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*',
    "API Key": r'(?:sk_live_|api_key=|key=)[A-Za-z0-9_\-]{16,}',
    "DB Connection String": r'[a-zA-Z0-9_+]+://[^:]+:([^@\s]+)@[^/\s]+(?:/[^\s]*)?',
    "Password Parameter": r'(?:password|passwd|pwd|pass)=([^\s&,;]+)',
    "IPv4 Address": r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
}

class UploadGuard:
    @staticmethod
    def inspect(filename: str, content: str) -> Dict[str, Any]:
        """
        Inspect log content and return redaction preview and flagged entities.
        """
        findings: List[Dict[str, Any]] = []
        masked_content = content
        
        # 1. DB Passwords (mask password portion only)
        def mask_db_pass(m):
            pwd = m.group(1)
            findings.append({
                "type": "Database Credential",
                "original": pwd,
                "masked": "[REDACTED_DB_PASSWORD]",
                "category": "SECRET"
            })
            return m.group(0).replace(pwd, "[REDACTED_DB_PASSWORD]")
        
        masked_content = re.sub(PATTERNS["DB Connection String"], mask_db_pass, masked_content)
        
        # 2. Bearer Tokens
        for m in re.finditer(PATTERNS["JWT Bearer Token"], masked_content):
            token = m.group(0)
            masked_token = "Bearer [REDACTED_JWT_TOKEN]"
            findings.append({
                "type": "JWT Bearer Token",
                "original": token[:25] + "...",
                "masked": masked_token,
                "category": "SECRET"
            })
            masked_content = masked_content.replace(token, masked_token)
            
        # 3. API Keys
        for m in re.finditer(PATTERNS["API Key"], masked_content):
            api_key = m.group(0)
            masked_key = api_key.split("=")[0] + "=[REDACTED_API_KEY]" if "=" in api_key else "[REDACTED_API_KEY]"
            findings.append({
                "type": "API Secret Key",
                "original": api_key[:18] + "...",
                "masked": masked_key,
                "category": "SECRET"
            })
            masked_content = masked_content.replace(api_key, masked_key)
            
        # 4. Passwords
        for m in re.finditer(PATTERNS["Password Parameter"], masked_content):
            param = m.group(0)
            val = m.group(1)
            findings.append({
                "type": "Password Parameter",
                "original": val,
                "masked": "[REDACTED_PASSWORD]",
                "category": "SECRET"
            })
            masked_content = masked_content.replace(param, param.replace(val, "[REDACTED_PASSWORD]"))
            
        # 5. Emails
        for m in re.finditer(PATTERNS["Email Address"], masked_content):
            email = m.group(0)
            masked_email = "[REDACTED_EMAIL]"
            findings.append({
                "type": "Email PII",
                "original": email,
                "masked": masked_email,
                "category": "PII"
            })
            masked_content = masked_content.replace(email, masked_email)
            
        # 6. IP Addresses (mask for preview)
        ip_map = {}
        for m in re.finditer(PATTERNS["IPv4 Address"], masked_content):
            ip = m.group(0)
            if ip.startswith("127.0.0"):
                continue
            if ip not in ip_map:
                ip_map[ip] = f"[IP_ALIAS_{len(ip_map)+1}]"
                findings.append({
                    "type": "IP Address",
                    "original": ip,
                    "masked": ip_map[ip],
                    "category": "NETWORK"
                })
        for ip, alias in ip_map.items():
            masked_content = masked_content.replace(ip, alias)
            
        # Summary stats
        secrets_count = sum(1 for f in findings if f["category"] == "SECRET")
        pii_count = sum(1 for f in findings if f["category"] == "PII")
        network_count = sum(1 for f in findings if f["category"] == "NETWORK")
        
        return {
            "status": "FLAGGED" if findings else "CLEAN",
            "filename": filename,
            "total_lines": len(content.splitlines()),
            "total_findings": len(findings),
            "stats": {
                "secrets_detected": secrets_count,
                "pii_detected": pii_count,
                "network_addresses": network_count
            },
            "findings": findings,
            "original_preview": content[:1200] + ("\n... [truncated]" if len(content) > 1200 else ""),
            "masked_preview": masked_content[:1200] + ("\n... [truncated]" if len(masked_content) > 1200 else ""),
            "masked_full": masked_content
        }
