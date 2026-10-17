"""
LogMind Deterministic Rule Engine
Principle: "Rules decide; AI explains."
Deterministic correlation rules determine the incident verdict and enforce
a strict Severity Floor that downstream AI cannot lower.
"""
from typing import List, Dict, Any, Optional
from backend.parser import LogEvent

class AlertVerdict:
    def __init__(
        self,
        alert_fired: bool,
        verdict: str,
        rule_name: str,
        severity: str,
        severity_floor: str,
        supporting_event_ids: List[int],
        rule_summary: str,
        iocs: Dict[str, Any]
    ):
        self.alert_fired = alert_fired
        self.verdict = verdict
        self.rule_name = rule_name
        self.severity = severity
        self.severity_floor = severity_floor
        self.supporting_event_ids = supporting_event_ids
        self.rule_summary = rule_summary
        self.iocs = iocs

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_fired": self.alert_fired,
            "verdict": self.verdict,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "severity_floor": self.severity_floor,
            "supporting_event_ids": self.supporting_event_ids,
            "rule_summary": self.rule_summary,
            "iocs": self.iocs
        }

class RulesEngine:
    @classmethod
    def evaluate(cls, events: List[LogEvent]) -> AlertVerdict:
        """
        Runs deterministic stateful correlation over the event stream.
        Looks for: repeated failed logins -> successful login -> privileged action.
        """
        failed_logins: List[LogEvent] = []
        successful_login: Optional[LogEvent] = None
        privilege_events: List[LogEvent] = []
        suspicious_web_events: List[LogEvent] = []
        
        compromised_account = None
        attacker_ip = None

        for ev in events:
            # 1. Track failed auth
            if ev.action == "auth_failed":
                failed_logins.append(ev)
                if ev.source_ip:
                    attacker_ip = ev.source_ip

            # 2. Check for successful auth
            elif ev.action == "auth_success":
                # Check if preceded by multiple failures
                if len(failed_logins) >= 2:
                    successful_login = ev
                    compromised_account = ev.account
                    if ev.source_ip:
                        attacker_ip = ev.source_ip

            # 3. Check for privilege escalation
            elif ev.action == "privilege_escalation":
                if successful_login and (ev.account == compromised_account or not ev.account):
                    privilege_events.append(ev)

            # 4. Check for high-privilege web actions
            elif ev.service == "web_server":
                uri = ev.details.get("uri", "")
                if any(k in uri.lower() for k in ["admin", "config", "permissions", "export"]):
                    suspicious_web_events.append(ev)

        # Correlation logic:
        # Fired if: >= 3 failed logins AND successful login AND (privilege escalation OR admin web action)
        if len(failed_logins) >= 3 and successful_login and (privilege_events or suspicious_web_events):
            supporting_ids = [e.event_id for e in failed_logins] + [successful_login.event_id]
            supporting_ids.extend([e.event_id for e in privilege_events])
            supporting_ids.extend([e.event_id for e in suspicious_web_events])
            supporting_ids = sorted(list(set(supporting_ids)))

            rule_summary = (
                f"Deterministic Correlation Alert: Account compromise sequence identified. "
                f"Originating IP '{attacker_ip}' initiated {len(failed_logins)} failed authentication attempts, "
                f"successfully breached account '{compromised_account}', and subsequently executed privileged root commands "
                f"and administrative web operations. Verified by events {supporting_ids}."
            )

            return AlertVerdict(
                alert_fired=True,
                verdict="ACCOUNT_COMPROMISE_DETECTED",
                rule_name="Rule-104: Credential Brute-Force & Privilege Escalation",
                severity="HIGH",
                severity_floor="HIGH",
                supporting_event_ids=supporting_ids,
                rule_summary=rule_summary,
                iocs={
                    "attacker_ip": attacker_ip,
                    "compromised_account": compromised_account,
                    "failed_count": len(failed_logins),
                    "privilege_command": privilege_events[0].details.get("command") if privilege_events else None,
                    "target_endpoints": [e.details.get("uri") for e in suspicious_web_events]
                }
            )

        # Non-compromise or benign verdict
        return AlertVerdict(
            alert_fired=False,
            verdict="BENIGN_ACTIVITY",
            rule_name="Rule-001: Routine System Operations",
            severity="LOW",
            severity_floor="LOW",
            supporting_event_ids=[e.event_id for e in events[:5]],
            rule_summary="Routine system activity. No multi-stage compromise pattern matched.",
            iocs={}
        )
