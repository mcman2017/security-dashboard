from sec_dashboard.config import settings
from sec_dashboard.scans.lynis import build_job, result_rel_path

SCAN_ID = "abcd1234-5678-90ab-cdef-1234567890ab"


def _job():
    settings.lynis_image = "example/lynis:test"
    return build_job(SCAN_ID, "worker-1", False)


def test_result_rel_path():
    assert result_rel_path(SCAN_ID, "worker-1") == f"{SCAN_ID}/worker-1.dat"


def test_job_name_and_labels():
    job = _job()
    assert job["metadata"]["name"] == f"lynis-worker-1-{SCAN_ID[:8]}"
    labels = job["metadata"]["labels"]
    assert labels["security-dashboard/scan-id"] == SCAN_ID
    assert labels["security-dashboard/scanner"] == "lynis"
    assert labels["security-dashboard/job-target"] == "worker-1"
    assert labels["security-dashboard/job-role"] == "node"
    # pod template carries the same labels (poller matches on them)
    assert job["spec"]["template"]["metadata"]["labels"] == labels


def test_control_plane_role_label():
    settings.lynis_image = "example/lynis:test"
    job = build_job(SCAN_ID, "cp-1", True)
    assert job["metadata"]["labels"]["security-dashboard/job-role"] == "cp"


def test_node_pinning_and_host_access():
    pod = _job()["spec"]["template"]["spec"]
    assert pod["nodeName"] == "worker-1"
    assert pod["hostPID"] is True
    assert pod["hostNetwork"] is True
    # blanket toleration — control-plane taints must not block the audit
    assert pod["tolerations"] == [{"operator": "Exists"}]
    assert pod["automountServiceAccountToken"] is False


def test_privileged_scanner_and_mounts():
    pod = _job()["spec"]["template"]["spec"]
    container = pod["containers"][0]
    assert container["securityContext"] == {"privileged": True}
    mounts = {m["name"]: m for m in container["volumeMounts"]}
    assert mounts["rootfs"]["mountPath"] == "/rootfs"
    assert mounts["rootfs"]["readOnly"] is True
    assert mounts["scan-results"]["mountPath"] == "/scan-results"
    volumes = {v["name"]: v for v in pod["volumes"]}
    assert volumes["rootfs"]["hostPath"] == {"path": "/", "type": "Directory"}
    assert volumes["scan-results"]["persistentVolumeClaim"]["claimName"] == settings.scan_results_pvc


def test_command_audits_host_and_publishes_atomically():
    cmd = _job()["spec"]["template"]["spec"]["containers"][0]["command"]
    assert cmd[:2] == ["sh", "-c"]
    script = cmd[2]
    # host (not container) audit
    assert "--rootdir /rootfs/" in script
    assert "--forensics" in script
    # readable stdout stays in the job log
    assert "--quiet" not in script
    # lynis writes report.dat 0640 root:root; api reads as uid 1000
    assert "chmod 644" in script
    # atomic publish
    dest = f"/scan-results/{SCAN_ID}/worker-1.dat"
    assert f"cp /tmp/report.dat {dest}.tmp" in script
    assert f"mv {dest}.tmp {dest}" in script
    # missing report is a loud failure, not a silent success
    assert "exit 1" in script


def test_node_name_sanitized_for_job_name():
    settings.lynis_image = "example/lynis:test"
    job = build_job(SCAN_ID, "Node.Example_01", False)
    assert job["metadata"]["name"] == f"lynis-node-example-01-{SCAN_ID[:8]}"
    # the label keeps the real node name for result lookup
    assert job["metadata"]["labels"]["security-dashboard/job-target"] == "Node.Example_01"


def test_image_pull_secrets():
    settings.lynis_image = "example/lynis:test"
    settings.lynis_image_pull_secrets = ""
    pod = build_job(SCAN_ID, "n1", False)["spec"]["template"]["spec"]
    assert "imagePullSecrets" not in pod
    settings.lynis_image_pull_secrets = "regcred, other"
    pod = build_job(SCAN_ID, "n1", False)["spec"]["template"]["spec"]
    assert pod["imagePullSecrets"] == [{"name": "regcred"}, {"name": "other"}]
    settings.lynis_image_pull_secrets = ""


def test_job_spec_safety_caps():
    spec = _job()["spec"]
    assert spec["backoffLimit"] == 0
    assert spec["activeDeadlineSeconds"] == settings.lynis_job_deadline_s
    assert spec["ttlSecondsAfterFinished"] == 86_400
    assert spec["template"]["spec"]["restartPolicy"] == "Never"
