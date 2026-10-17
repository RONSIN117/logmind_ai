"""
LogMind Field Quarantine & Identifier Pseudonymizer
Quarantines attacker-controllable fields (User-Agents, query strings, referers)
into opaque tokens ([UA#1]) and replaces identifiers with consistent aliases.
The raw data is stored in the LinuxONE enclave boundary, accessible only to analysts.
"""
from typing import List, Dict, Any, Tuple
import hashlib
from backend.parser import LogEvent

class QuarantineManager:
    def __init__(self):
        self.quarantine_vault: Dict[str, Dict[str, Any]] = {}
        self.alias_map: Dict[str, str] = {}
        self.token_counter = 0

    def get_alias(self, original_val: str, prefix: str) -> str:
        """Generates a stable pseudonym for an identifier."""
        if not original_val:
            return original_val
        if original_val not in self.alias_map:
            # Deterministic short hash
            h = hashlib.sha256(original_val.encode('utf-8')).hexdigest()[:4].upper()
            self.alias_map[original_val] = f"{prefix}_{h}"
        return self.alias_map[original_val]

    def quarantine_field(self, event_id: int, field_name: str, raw_value: str) -> str:
        """
        Replaces raw attacker-controlled text with an opaque token.
        Stores the raw string inside the LinuxONE quarantine vault.
        """
        if not raw_value:
            return raw_value
        self.token_counter += 1
        prefix_tag = {
            "user_agent": "UA",
            "referer": "REF",
            "uri_query": "QUERY",
            "user_input": "INPUT"
        }.get(field_name, "FIELD")

        token = f"[{prefix_tag}#{self.token_counter}]"
        
        # Check if the raw value contains obvious prompt injection or suspicious phrasing
        has_suspicious_payload = any(
            kw in raw_value.lower()
            for kw in [
                "ignore", "system instruction", "override", "benign", 
                "authorized", "do not trigger", "disregard", "ciso"
            ]
        )

        self.quarantine_vault[token] = {
            "token": token,
            "event_id": event_id,
            "field_name": field_name,
            "raw_value": raw_value,
            "quarantined_by": "LinuxONE Isolation Enclave",
            "has_suspicious_payload": has_suspicious_payload
        }
        return token

    def sanitize_events(self, events: List[LogEvent]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Transforms raw LogEvents into sanitized, model-safe dictionaries.
        """
        sanitized_list = []
        for ev in events:
            # Pseudonymize account and IP
            safe_account = self.get_alias(ev.account, "User") if ev.account else None
            safe_ip = self.get_alias(ev.source_ip, "IP") if ev.source_ip else None
            
            safe_details = dict(ev.details)
            
            # Quarantine attacker-controllable web fields
            if "user_agent" in safe_details:
                raw_ua = safe_details["user_agent"]
                token = self.quarantine_field(ev.event_id, "user_agent", raw_ua)
                safe_details["user_agent"] = token

            if "referer" in safe_details and safe_details["referer"] != "-":
                raw_ref = safe_details["referer"]
                token = self.quarantine_field(ev.event_id, "referer", raw_ref)
                safe_details["referer"] = token

            sanitized_list.append({
                "event_id": ev.event_id,
                "timestamp": ev.timestamp,
                "service": ev.service,
                "action": ev.action,
                "account": safe_account,
                "source_ip": safe_ip,
                "status": ev.status,
                "safe_details": safe_details
            })

        summary_metrics = {
            "total_quarantined_fields": len(self.quarantine_vault),
            "total_pseudonymized_entities": len(self.alias_map),
            "suspicious_payloads_neutralized": sum(1 for v in self.quarantine_vault.values() if v["has_suspicious_payload"])
        }

        return sanitized_list, summary_metrics
