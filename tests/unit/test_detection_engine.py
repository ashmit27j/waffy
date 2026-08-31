"""Unit and security tests for Phase 3 Detection and Rule Engine."""

import json
from pathlib import Path
from urllib.parse import parse_qs

import pytest

from waffy.core.enums import HttpMethod, ParanoiaLevel, SignatureCategory
from waffy.core.exceptions import RuleLoadError
from waffy.core.models.domain import HttpRequestRecord
from waffy.detection.positive import (
    ParameterConstraint,
    PositiveSecurityEngine,
    RouteSecurityConfig,
    UnknownParamPolicy,
)
from waffy.detection.signatures import (
    SignatureDefinition,
    SignatureEngine,
    load_all_rules_from_dir,
    load_rules_from_file,
)


@pytest.fixture
def seed_signatures() -> list[SignatureDefinition]:
    return load_all_rules_from_dir("config/rules")


def test_rule_loader_valid_and_duplicate(tmp_path: Path) -> None:
    # Valid rule file
    rules = load_rules_from_file("config/rules/seed_rules.toml")
    assert len(rules) >= 10

    # Malformed file
    bad_rule_file = tmp_path / "bad_rule.toml"
    bad_rule_file.write_text("invalid = [rule unclosed", encoding="utf-8")
    with pytest.raises(RuleLoadError, match="Malformed TOML"):
        load_rules_from_file(bad_rule_file)

    # Duplicate rule id detection
    dup_dir = tmp_path / "rules"
    dup_dir.mkdir()
    f1 = dup_dir / "r1.toml"
    f2 = dup_dir / "r2.toml"
    content = """
    [[rules]]
    id = "DUP-001"
    category = "sqli"
    pattern = "select"
    """
    f1.write_text(content, encoding="utf-8")
    f2.write_text(content, encoding="utf-8")
    with pytest.raises(RuleLoadError, match="Duplicate rule ID 'DUP-001'"):
        load_all_rules_from_dir(dup_dir)


def test_signature_true_and_false_positives(seed_signatures: list[SignatureDefinition]) -> None:
    engine = SignatureEngine(seed_signatures, paranoia_level=ParanoiaLevel.PL2)

    # 1. SQL Injection
    attack_sqli = HttpRequestRecord(
        method=HttpMethod.GET,
        path="/products",
        query_string="id=1+UNION+SELECT+null,username,password+FROM+users",
        query_params={"id": ["1 UNION SELECT null,username,password FROM users"]},
        client_ip="1.2.3.4",
    )
    benign_sqli = HttpRequestRecord(
        method=HttpMethod.GET,
        path="/selection/options",
        query_string="text=Please+select+an+option+from+the+menu",
        query_params={"text": ["Please select an option from the menu"]},
        client_ip="1.2.3.4",
    )
    matches_attack = engine.match(attack_sqli)
    assert any(m.category == SignatureCategory.SQLI for m in matches_attack)
    matches_benign = engine.match(benign_sqli)
    assert not any(m.category == SignatureCategory.SQLI for m in matches_benign)

    # 2. XSS
    attack_xss = HttpRequestRecord(
        method=HttpMethod.POST,
        path="/comment",
        client_ip="1.2.3.4",
        parsed_body_summary={"comment": "<script>alert(document.cookie)</script>"},
    )
    benign_xss = HttpRequestRecord(
        method=HttpMethod.POST,
        path="/comment",
        client_ip="1.2.3.4",
        parsed_body_summary={"comment": "I love writing script for movies!"},
    )
    assert any(
        m.category == SignatureCategory.XSS
        for m in engine.match(attack_xss, b"<script>alert(document.cookie)</script>")
    )
    assert not any(
        m.category == SignatureCategory.XSS
        for m in engine.match(benign_xss, b"I love writing script for movies!")
    )

    # 3. Command Injection
    attack_cmdi = HttpRequestRecord(
        method=HttpMethod.GET,
        path="/ping",
        query_string="ip=127.0.0.1;cat+/etc/passwd",
        query_params={"ip": ["127.0.0.1;cat /etc/passwd"]},
        client_ip="1.2.3.4",
    )
    benign_cmdi = HttpRequestRecord(
        method=HttpMethod.GET,
        path="/ping",
        query_string="ip=127.0.0.1&count=4",
        query_params={"ip": ["127.0.0.1"], "count": ["4"]},
        client_ip="1.2.3.4",
    )
    assert any(
        m.category == SignatureCategory.COMMAND_INJECTION
        for m in engine.match(attack_cmdi)
    )
    assert not any(
        m.category == SignatureCategory.COMMAND_INJECTION
        for m in engine.match(benign_cmdi)
    )

    # 4. Path Traversal
    attack_trav = HttpRequestRecord(
        method=HttpMethod.GET,
        path="/download",
        query_string="file=../../../../etc/passwd",
        query_params={"file": ["../../../../etc/passwd"]},
        client_ip="1.2.3.4",
    )
    benign_trav = HttpRequestRecord(
        method=HttpMethod.GET,
        path="/download",
        query_string="file=annual_report_2026.pdf",
        query_params={"file": ["annual_report_2026.pdf"]},
        client_ip="1.2.3.4",
    )
    assert any(m.category == SignatureCategory.PATH_TRAVERSAL for m in engine.match(attack_trav))
    assert not any(
        m.category == SignatureCategory.PATH_TRAVERSAL for m in engine.match(benign_trav)
    )

    # 5. SSTI
    attack_ssti = HttpRequestRecord(
        method=HttpMethod.POST,
        path="/render",
        client_ip="1.2.3.4",
        parsed_body_summary={"name": "{{7*7}}"},
    )
    benign_ssti = HttpRequestRecord(
        method=HttpMethod.POST,
        path="/render",
        client_ip="1.2.3.4",
        parsed_body_summary={"name": "Alice and Bob"},
    )
    assert any(m.category == SignatureCategory.SSTI for m in engine.match(attack_ssti, b"{{7*7}}"))
    assert not any(
        m.category == SignatureCategory.SSTI
        for m in engine.match(benign_ssti, b"Alice and Bob")
    )


def test_paranoia_level_gating(seed_signatures: list[SignatureDefinition]) -> None:
    # PL1 engine should NOT trigger PL2 signature (open redirect)
    engine_pl1 = SignatureEngine(seed_signatures, paranoia_level=ParanoiaLevel.PL1)
    req = HttpRequestRecord(
        method=HttpMethod.GET,
        path="/redirect",
        query_string="url=https://evil.com/phish",
        query_params={"url": ["https://evil.com/phish"]},
        client_ip="1.2.3.4",
    )
    assert not any(m.category == SignatureCategory.OPEN_REDIRECT for m in engine_pl1.match(req))

    # PL2 engine SHOULD trigger PL2 signature
    engine_pl2 = SignatureEngine(seed_signatures, paranoia_level=ParanoiaLevel.PL2)
    assert any(m.category == SignatureCategory.OPEN_REDIRECT for m in engine_pl2.match(req))


def test_positive_security_engine() -> None:
    routes = [
        RouteSecurityConfig(
            route_id="api_users",
            path_pattern="^/api/users",
            allowed_methods=[HttpMethod.GET, HttpMethod.POST],
            unknown_param_policy=UnknownParamPolicy.REJECT,
            parameters=[
                ParameterConstraint(
                    name="user_id", param_type="int", required=True, max_length=5
                ),
                ParameterConstraint(
                    name="email", param_type="string", regex_pattern="^[^@]+@[^@]+$"
                ),
            ],
        )
    ]
    pos_engine = PositiveSecurityEngine(routes)

    # 1. Valid request
    valid_req = HttpRequestRecord(
        method=HttpMethod.GET,
        path="/api/users/profile",
        query_params={"user_id": ["1234"], "email": ["test@example.com"]},
        client_ip="127.0.0.1",
    )
    assert len(pos_engine.validate(valid_req)) == 0

    # 2. Invalid method
    bad_method_req = HttpRequestRecord(
        method=HttpMethod.DELETE,
        path="/api/users/profile",
        query_params={"user_id": ["1234"]},
        client_ip="127.0.0.1",
    )
    violations = pos_engine.validate(bad_method_req)
    assert any(v.constraint_name == "allowed_methods" for v in violations)

    # 3. Missing required parameter & unknown parameter
    bad_params_req = HttpRequestRecord(
        method=HttpMethod.GET,
        path="/api/users/profile",
        query_params={"unknown_field": ["hacked"]},
        client_ip="127.0.0.1",
    )
    violations2 = pos_engine.validate(bad_params_req)
    assert any(
        v.constraint_name == "required_parameter" and v.parameter_name == "user_id"
        for v in violations2
    )
    assert any(
        v.constraint_name == "unknown_parameter" and v.parameter_name == "unknown_field"
        for v in violations2
    )

    # 4. Route with no config falls back cleanly (empty violations)
    unconfigured_req = HttpRequestRecord(
        method=HttpMethod.GET,
        path="/unconfigured/endpoint",
        client_ip="127.0.0.1",
    )
    assert pos_engine.validate(unconfigured_req) == []


def test_rule_complexity_time_budget(seed_signatures: list[SignatureDefinition]) -> None:
    # Set an extremely tight budget (0.0001 ms) to ensure budget exceeded trigger
    tight_engine = SignatureEngine(
        seed_signatures, paranoia_level=ParanoiaLevel.PL1, time_budget_ms=0.00001
    )

    req = HttpRequestRecord(
        method=HttpMethod.GET,
        path="/products",
        query_string="q=" + "a" * 1000,
        query_params={"q": ["a" * 1000]},
        client_ip="1.2.3.4",
    )

    # Match execution should abort gracefully without throwing or hanging
    matches = tight_engine.match(req)
    assert isinstance(matches, list)


def test_benign_traffic_corpus_false_positive_rate(
    seed_signatures: list[SignatureDefinition],
) -> None:
    corpus_path = Path("tests/security/fixtures/benign/benign_traffic.json")
    with open(corpus_path, encoding="utf-8") as f:
        corpus_items = json.load(f)

    engine_pl1 = SignatureEngine(seed_signatures, paranoia_level=ParanoiaLevel.PL1)
    false_positives = 0
    total_requests = len(corpus_items)

    for item in corpus_items:
        req = HttpRequestRecord(
            method=HttpMethod(item["method"]),
            path=item["path"],
            query_string=item.get("query", ""),
            query_params=parse_qs(item.get("query", ""), keep_blank_values=True),
            headers=item.get("headers", []),
            client_ip="192.168.1.100",
        )
        body_bytes = item.get("body", "").encode("utf-8")
        matches = engine_pl1.match(req, body_bytes)
        if len(matches) > 0:
            false_positives += 1

    fp_rate = (false_positives / total_requests) * 100.0
    print(
        f"\nMeasured Benign Corpus False-Positive Rate: {fp_rate:.2f}% "
        f"({false_positives}/{total_requests})"
    )
    assert false_positives == 0, f"Expected 0% FP rate on benign corpus at PL1, got {fp_rate}%"
