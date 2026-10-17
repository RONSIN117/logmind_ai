"""
LogMind Event Parser & Normalizer
Normalizes authentication and web access logs into structured LogEvent objects
with monotonic event IDs.
"""
import re
from typing import List, Dict, Any, Optional, Tuple

class LogEvent:
    def __init__(
        self,
        event_id: int,
        timestamp: str,
        service: str,
        action: str,
        account: Optional[str] = None,
        source_ip: Optional[str] = None,
        status: str = "INFO",
        details: Optional[Dict[str, Any]] = None,
        raw: str = ""
    ):
        self.event_id = event_id
        self.timestamp = timestamp
        self.service = service
        self.action = action
        self.account = account
        self.source_ip = source_ip
        self.status = status
        self.details = details or {}
        self.raw = raw

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "service": self.service,
            "action": self.action,
            "account": self.account,
            "source_ip": self.source_ip,
            "status": self.status,
            "details": self.details,
            "raw": self.raw
        }

class LogParser:
    # Syslog SSH failed (supports raw IP or masked alias)
    REGEX_SSH_FAILED = re.compile(
        r'^(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)\s+(?P<host>[\w-]+)\s+sshd\[\d+\]:\s+Failed password for (?:invalid user\s+|user\s+)?(?P<user>[\w\.-]+)\s+from\s+(?P<ip>[0-9\.]+|\[[A-Z0-9_]+\]|[\w\.\-]+)'
    )
    # Syslog SSH accepted
    REGEX_SSH_ACCEPTED = re.compile(
        r'^(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)\s+(?P<host>[\w-]+)\s+sshd\[\d+\]:\s+Accepted password for\s+(?P<user>[\w\.-]+)\s+from\s+(?P<ip>[0-9\.]+|\[[A-Z0-9_]+\]|[\w\.\-]+)'
    )
    # Syslog sudo
    REGEX_SUDO = re.compile(
        r'^(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)\s+(?P<host>[\w-]+)\s+sudo\[\d+\]:\s+(?P<user>[\w\.-]+)\s*:\s*TTY=(?P<tty>[^\s;]+)\s*;\s*PWD=(?P<pwd>[^\s;]+)\s*;\s*USER=(?P<target_user>[^\s;]+)\s*;\s*COMMAND=(?P<cmd>.+)$'
    )
    # Combined Apache/Nginx web log
    REGEX_WEB = re.compile(
        r'^(?P<ip>[0-9\.]+|\[[A-Z0-9_]+\]|[\w\.\-]+)\s+-\s+(?P<user>[^\s]+)\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<uri>[^\s]+)\s+[A-Z0-9\./]+"\s+(?P<status>\d+)\s+(?P<bytes>\d+)\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)"'
    )

    @classmethod
    def parse_text(cls, log_text: str) -> Tuple[List[LogEvent], int, int]:
        """
        Parses multi-line text (syslog, web logs, or CSV) into a list of LogEvents.
        Returns: (events, success_count, malformed_count)
        """
        lines = [line.strip() for line in log_text.splitlines() if line.strip()]
        if not lines:
            return [], 0, 0

        events: List[LogEvent] = []
        malformed_count = 0

        # Check if input is CSV format (e.g., datasetIBM_2M.csv)
        if "event_id" in lines[0].lower() and "," in lines[0]:
            import csv
            import io
            reader = csv.DictReader(io.StringIO(log_text))
            for idx, row in enumerate(reader, 1):
                try:
                    action = row.get("action", "").lower()
                    status = row.get("status", "").upper()
                    if action == "login" and status == "FAIL":
                        normalized_action = "auth_failed"
                    elif action == "login" and status == "SUCCESS":
                        normalized_action = "auth_success"
                    elif "sudo" in action or "escalat" in action or "root" in action:
                        normalized_action = "privilege_escalation"
                    else:
                        normalized_action = action or "event"

                    ev = LogEvent(
                        event_id=idx,
                        timestamp=row.get("timestamp", ""),
                        service=row.get("source", "system"),
                        action=normalized_action,
                        account=row.get("user") or None,
                        source_ip=row.get("ip") or None,
                        status=status or "INFO",
                        details={"user_agent": row.get("user_agent", ""), "source": row.get("source", "")},
                        raw=str(row)
                    )
                    events.append(ev)
                except Exception:
                    malformed_count += 1
            return events, len(events), malformed_count

        event_id = 1
        for line in lines:
            parsed = cls._parse_line(line, event_id)
            if parsed:
                events.append(parsed)
                event_id += 1
            else:
                malformed_count += 1

        return events, len(events), malformed_count

    @classmethod
    def _parse_line(cls, line: str, event_id: int) -> Optional[LogEvent]:
        # 1. SSH Failed
        m = cls.REGEX_SSH_FAILED.search(line)
        if m:
            return LogEvent(
                event_id=event_id,
                timestamp=m.group("ts"),
                service="sshd",
                action="auth_failed",
                account=m.group("user"),
                source_ip=m.group("ip"),
                status="FAILED",
                details={"reason": "bad_password", "host": m.group("host")},
                raw=line
            )

        # 2. SSH Accepted
        m = cls.REGEX_SSH_ACCEPTED.search(line)
        if m:
            return LogEvent(
                event_id=event_id,
                timestamp=m.group("ts"),
                service="sshd",
                action="auth_success",
                account=m.group("user"),
                source_ip=m.group("ip"),
                status="SUCCESS",
                details={"host": m.group("host")},
                raw=line
            )

        # 3. Sudo Privilege Escalation
        m = cls.REGEX_SUDO.search(line)
        if m:
            return LogEvent(
                event_id=event_id,
                timestamp=m.group("ts"),
                service="sudo",
                action="privilege_escalation",
                account=m.group("user"),
                status="SUCCESS",
                details={
                    "target_user": m.group("target_user"),
                    "command": m.group("cmd"),
                    "pwd": m.group("pwd")
                },
                raw=line
            )

        # 4. Web access log
        m = cls.REGEX_WEB.search(line)
        if m:
            account = m.group("user") if m.group("user") != "-" else None
            return LogEvent(
                event_id=event_id,
                timestamp=m.group("ts"),
                service="web_server",
                action="http_request",
                account=account,
                source_ip=m.group("ip"),
                status=m.group("status"),
                details={
                    "method": m.group("method"),
                    "uri": m.group("uri"),
                    "referer": m.group("ref"),
                    "user_agent": m.group("ua"),
                    "bytes": int(m.group("bytes"))
                },
                raw=line
            )

        # Generic fallback if line contains timestamp and keyword
        return None
