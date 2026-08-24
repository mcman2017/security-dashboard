from sec_dashboard.scans.parsers.lynis import HARDENING_INDEX_ID, parse_lynis
from sec_dashboard.severity import Severity

SAMPLE_DAT = """\
# Lynis Report
lynis_version=3.1.6
os_fullname=Ubuntu 24.04
os_kernel_version=6.17.0
hardening_index=66
warning[]=AUTH-9286|No password set for single user mode|-|-
warning[]=FIRE-4512|iptables module loaded but no rules active|-|-
suggestion[]=BOOT-5184|Set a password on GRUB bootloader|-|-
suggestion[]=PKGS-7420|Consider using a tool to automatically apply upgrades|details here|extra here
suggestion[]=SHRT-1|too few pipes
malformed line without equals
unknown[]=SOME-1|Not a warning or suggestion|-|-
"""


def test_parse_counts_and_kinds():
    findings = parse_lynis(SAMPLE_DAT, target_node="worker-1")
    # 2 warnings + 3 suggestions + 1 hardening-index INFO; unknown[] skipped
    assert len(findings) == 6
    kinds = [f["severity_original"] for f in findings]
    assert kinds.count("warning") == 2
    assert kinds.count("suggestion") == 3


def test_severity_mapping():
    findings = parse_lynis(SAMPLE_DAT, target_node="worker-1")
    by_id = {f["scanner_id"]: f for f in findings}
    assert by_id["AUTH-9286"]["severity_normalized"] == int(Severity.MEDIUM)
    assert by_id["BOOT-5184"]["severity_normalized"] == int(Severity.LOW)


def test_node_attribution_and_shape():
    findings = parse_lynis(SAMPLE_DAT, target_node="cp-1")
    for f in findings:
        assert f["resource_kind"] == "Host"
        assert f["resource_name"] == "cp-1"
        assert f["resource_ns"] is None
        assert f["image"] is None
        assert f["ecosystem_bucket"] is False
    auth = next(f for f in findings if f["scanner_id"] == "AUTH-9286")
    assert auth["title"] == "No password set for single user mode"
    assert auth["control_id"] == "AUTH-9286"
    assert auth["evidence"]["hardening_index"] == "66"


def test_detail_and_extra_fields():
    findings = parse_lynis(SAMPLE_DAT, target_node="n")
    pkgs = next(f for f in findings if f["scanner_id"] == "PKGS-7420")
    assert pkgs["description"] == "details here"
    assert pkgs["evidence"]["extra"] == "extra here"
    # "-" placeholders normalize to None
    boot = next(f for f in findings if f["scanner_id"] == "BOOT-5184")
    assert boot["description"] is None


def test_short_pipe_row_tolerated():
    findings = parse_lynis(SAMPLE_DAT, target_node="n")
    short = next(f for f in findings if f["scanner_id"] == "SHRT-1")
    assert short["title"] == "too few pipes"
    assert short["description"] is None


def test_hardening_index_finding():
    findings = parse_lynis(SAMPLE_DAT, target_node="worker-1")
    hi = [f for f in findings if f["scanner_id"] == HARDENING_INDEX_ID]
    assert len(hi) == 1
    assert hi[0]["severity_normalized"] == int(Severity.INFO)
    assert hi[0]["title"] == "Lynis hardening index: 66"
    assert hi[0]["evidence"]["lynis_version"] == "3.1.6"
    assert hi[0]["evidence"]["os_fullname"] == "Ubuntu 24.04"


def test_no_hardening_index_no_extra_finding():
    findings = parse_lynis("warning[]=A-1|msg|-|-\n", target_node="n")
    assert len(findings) == 1
    assert findings[0]["scanner_id"] == "A-1"


def test_empty_input():
    assert parse_lynis("", target_node="n") == []
