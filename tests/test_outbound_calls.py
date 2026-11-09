"""Static guards for outbound HTTP calls and hashing."""

import ast
import hashlib
from pathlib import Path

import cloudguard_anomaly
from cloudguard_anomaly.enterprise.threat_intel import ThreatIntelligence

PACKAGE = Path(cloudguard_anomaly.__file__).parent
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head"}


def _requests_calls():
    for path in PACKAGE.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in HTTP_METHODS
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "requests"
            ):
                yield path.relative_to(PACKAGE), node


def test_every_outbound_request_has_a_timeout():
    """Without one a hung endpoint blocks a worker forever."""
    missing = [
        f"{path}:{node.lineno}"
        for path, node in _requests_calls()
        if not any(keyword.arg == "timeout" for keyword in node.keywords)
    ]
    assert missing == []


def test_indicator_ids_do_not_use_md5():
    assert ThreatIntelligence()._generate_id("value") == hashlib.sha256(b"value").hexdigest()[:16]
