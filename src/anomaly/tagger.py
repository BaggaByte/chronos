"""
Module 4 (part): ATT&CK Technique Tagger – data-driven rules.

Rules live in config/attack_mappings.yaml so the logic is extensible
and reviewable without touching Python.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from src.schema import ChronosEvent

# ---------------------------------------------------------------------------
# Built-in fallback rules (used when YAML is unavailable or missing)
# ---------------------------------------------------------------------------
_FALLBACK_RULES: List[Dict[str, Any]] = [
    {
        "id": "initial_access_web_login",
        "techniques": ["T1566", "T1190"],
        "match": {
            "source_type": ["apache", "nginx"],
            "path_in": ["/login", "/wp-login.php", "/admin"],
            "status_in": [200, 302],
        },
    },
    {
        "id": "initial_access_login_action",
        "techniques": ["T1190"],
        "match": {"action_contains": "login"},
    },
    {
        "id": "credential_dump_mimikatz",
        "techniques": ["T1003"],
        "match": {"source_type": ["evtx"], "process_contains": "mimi"},
    },
    {
        "id": "credential_dump_special_privs",
        "techniques": ["T1003"],
        "match": {"source_type": ["evtx"], "event_id": 4672},
    },
    {
        "id": "lateral_ssh",
        "techniques": ["T1021", "T1078"],
        "match": {"action_contains_any": ["ssh_accepted", "session_opened"]},
    },
    {
        "id": "lateral_rdp_logon",
        "techniques": ["T1021"],
        "match": {
            "source_type": ["evtx"],
            "event_id": 4624,
            "logon_type_in": [3, 10],
        },
    },
    {
        "id": "staging_tar",
        "techniques": ["T1560"],
        "match": {"action": "sudo", "command_contains": "tar"},
    },
    {
        "id": "exfil_s3",
        "techniques": ["T1041"],
        "match": {
            "source_type": ["aws_cloudtrail"],
            "action_in": ["PutObject", "CopyObject", "UploadPart"],
        },
    },
]


def _load_rules(config_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    if config_path is None:
        config_path = (
            Path(__file__).resolve().parent.parent.parent / "config" / "attack_mappings.yaml"
        )
    if not config_path.exists():
        return _FALLBACK_RULES
    try:
        import yaml  # type: ignore
        with open(config_path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data.get("rules") or _FALLBACK_RULES
    except Exception:
        return _FALLBACK_RULES


def _match_rule(event: ChronosEvent, match: Dict[str, Any]) -> bool:
    """Evaluate a single rule's match block against an event."""
    src = event.source_type.value if hasattr(event.source_type, "value") else str(event.source_type)
    action = (event.action or "").lower()
    process = (event.process or "").lower()
    extra = event.extra or {}

    if "source_type" in match:
        allowed = [s.lower() for s in match["source_type"]]
        if src.lower() not in allowed:
            return False

    if "action" in match and action != match["action"].lower():
        return False

    if "action_contains" in match:
        if match["action_contains"].lower() not in action:
            return False

    if "action_contains_any" in match:
        if not any(tok.lower() in action for tok in match["action_contains_any"]):
            return False

    if "action_in" in match:
        if event.action not in match["action_in"]:
            return False

    if "process_contains" in match:
        needle = match["process_contains"].lower()
        cmd = str(extra.get("CommandLine") or extra.get("command") or "").lower()
        if needle not in process and needle not in cmd:
            return False

    if "command_contains" in match:
        cmd = str(extra.get("command") or extra.get("CommandLine") or "").lower()
        if match["command_contains"].lower() not in cmd:
            return False

    if "path_in" in match:
        path = extra.get("path")
        if path not in match["path_in"]:
            return False

    if "status_in" in match:
        if extra.get("status") not in match["status_in"]:
            return False

    if "event_id" in match:
        eid = extra.get("EventID", extra.get("event_id"))
        if eid != match["event_id"]:
            return False

    if "logon_type_in" in match:
        lt = extra.get("LogonType")
        if lt not in match["logon_type_in"]:
            return False

    return True


class AttackTagger:
    def __init__(self, config_path: Optional[Path] = None):
        self.rules = _load_rules(config_path)

    def tag(self, events: List[ChronosEvent]) -> List[ChronosEvent]:
        for e in events:
            techs = set(e.attack_techniques)
            for rule in self.rules:
                try:
                    if _match_rule(e, rule.get("match") or {}):
                        for t in rule.get("techniques") or []:
                            techs.add(t if isinstance(t, str) else getattr(t, "value", str(t)))
                except Exception:
                    continue
            e.attack_techniques = sorted(techs)
            if e.attack_techniques:
                high = {"T1003", "T1041", "T1560"}
                med = {"T1021", "T1190", "T1566", "T1078"}
                if any(t in high for t in e.attack_techniques):
                    e.severity = "high"
                elif any(t in med for t in e.attack_techniques):
                    e.severity = "medium"
        return events
