"""
LogMind Plain-Code Output Validator
Runs inside the LinuxONE enclave to verify model responses:
1. Schema verification
2. Fact-checking against valid event IDs
3. Severity Floor enforcement (blocks unsupported downgrades)
"""
from typing import Dict, Any, List, Tuple
from backend.rules_engine import AlertVerdict

class OutputValidator:
    @staticmethod
    def validate(
        model_output: Dict[str, Any],
        verdict: AlertVerdict,
        valid_event_ids: List[int]
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Validates model output against deterministic constraints.
        Returns: (validated_output, validation_report)
        """
        report = {
            "is_valid": True,
            "severity_floor_enforced": False,
            "hallucinated_citations_detected": [],
            "schema_compliant": True,
            "status": "PASSED"
        }

        # 1. Schema check
        required_keys = ["summary", "verdict", "severity", "cited_event_ids"]
        for key in required_keys:
            if key not in model_output:
                report["is_valid"] = False
                report["schema_compliant"] = False
                report["status"] = "FALLBACK_TRIGGERED"
                return {
                    "summary": verdict.rule_summary,
                    "verdict": verdict.verdict,
                    "severity": verdict.severity,
                    "cited_event_ids": verdict.supporting_event_ids,
                    "is_fallback": True
                }, report

        output = dict(model_output)
        
        # 2. Citation verification
        cited_ids = output.get("cited_event_ids", [])
        invalid_ids = [eid for eid in cited_ids if eid not in valid_event_ids]
        if invalid_ids:
            report["hallucinated_citations_detected"] = invalid_ids
            # Filter out invalid citations
            output["cited_event_ids"] = [eid for eid in cited_ids if eid in valid_event_ids]

        # 3. Severity Floor enforcement
        rule_severity = verdict.severity
        model_severity = output.get("severity", "LOW").upper()
        
        severity_rank = {
            "INFORMATIONAL": 0,
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4
        }
        
        rule_rank = severity_rank.get(rule_severity, 3)
        model_rank = severity_rank.get(model_severity, 1)

        if model_rank < rule_rank:
            # Model attempted to downgrade!
            report["severity_floor_enforced"] = True
            output["severity"] = rule_severity
            output["verdict"] = verdict.verdict
            output["downgrade_blocked"] = True
            output["downgrade_attempted"] = model_severity
            report["status"] = "SEVERITY_OVERRIDDEN"

        output["is_fallback"] = False
        return output, report
