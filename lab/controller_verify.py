#!/usr/bin/env python3
"""HTTPS controller-v1 interoperability, with no active network discovery."""

import datetime
from email.parser import BytesParser
from email.policy import default
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import time


def future(days=0, seconds=0):
    return (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days, seconds=seconds)).isoformat()


def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def main(binary):
    with tempfile.TemporaryDirectory(prefix="otter-controller-lab-") as directory:
        root = Path(directory)
        certificate, key = root / "cert.pem", root / "key.pem"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-keyout", str(key), "-out", str(certificate), "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        interfaces = json.loads(subprocess.check_output([binary, "interfaces", "--json"]))
        interface = next(item for item in interfaces if item.get("macAddress")) if any(item.get("macAddress") for item in interfaces) else interfaces[0]
        data = {"credential": "a" * 43, "rotations": 0, "uploads": [], "finished": {}, "retried": 0, "importCompleted": False, "error": None}
        rejected_upload = threading.Event()

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def send_json(self, value, status=200):
                body = json.dumps(value).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                try:
                    self.post()
                except Exception as error:
                    data["error"] = type(error).__name__
                    self.send_json({"errors": [{"message": "lab assertion failed"}]}, 400)

            def post(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                if self.path == "/api/otter/v1/enroll":
                    report = json.loads(body)
                    assert report["token"] == "t" * 43
                    assert report["version"]
                    assert "controller-v1" in report["capabilities"]
                    assert report["computerName"]
                    adapter = next(item for item in report["networkAdapters"] if item["name"] == interface["name"])
                    assert adapter["friendlyName"] == interface["friendlyName"]
                    assert adapter["ipAddresses"] == [address for address in interface["addresses"] if is_ip(address)]
                    assert not self.headers.get("Authorization")
                    self.send_json({"credential": data["credential"], "credentialExpiresAt": future(days=10), "scanner": {"id": "scanner1", "name": "Lab", "site": "site1"}}, 201)
                    return
                assert self.headers.get("Authorization") == "Otter " + data["credential"]
                if self.path == "/api/otter/v1/credentials/rotate":
                    data["rotations"] += 1
                    data["credential"] = "b" * 43
                    self.send_json({"credential": data["credential"], "credentialExpiresAt": future(days=365)})
                elif self.path == "/api/otter/v1/poll":
                    report = json.loads(body)
                    assert "scan-v2" in report["capabilities"]
                    assert interface["name"] in report["interfaces"]
                    assert report["computerName"]
                    assert any(adapter["name"] == interface["name"] for adapter in report["networkAdapters"])
                    if len(data["finished"]) == 3:
                        self.send_json({"errors": [{"message": "revoked"}]}, 401) if data["importCompleted"] else self.send_json({"action": "idle", "retryAfterSeconds": 1})
                        return
                    run = next(name for name in ["run1", "run2", "run3"] if name not in data["finished"])
                    configuration = {
                        "name": "Lab", "targets": ["192.0.2.1"], "interface": interface["name"],
                        "sourceMac": "00:11:22:33:44:55", "serverUrl": url, "site": "site1",
                        "noProtocols": True, "noArp": True, "noProfinet": True, "noSnmp": True, "noLldp": True,
                    }
                    if run == "run3":
                        configuration["output"] = "/forbidden/server/path"
                    self.send_json({"action": "run", "run": {"id": run, "configuration": configuration, "credentials": {"snmp": [{"community": "lab-secret"}]}, "uploadPath": "/api/asset-imports", "leaseExpiresAt": future(seconds=120)}})
                elif self.path.endswith("/start"):
                    self.send_json({"status": "running"})
                elif self.path.endswith("/heartbeat"):
                    assert 0 <= json.loads(body)["progress"] <= 100
                    self.send_json({"cancelRequested": "run2" in self.path, "leaseExpiresAt": future(seconds=120)})
                elif self.path == "/api/asset-imports":
                    message = BytesParser(policy=default).parsebytes(b"Content-Type: " + self.headers["Content-Type"].encode() + b"\r\n\r\n" + body)
                    parts = {part.get_param("name", header="content-disposition"): part.get_payload(decode=True) for part in message.iter_parts()}
                    metadata = json.loads(parts["_payload"])
                    assert metadata["source"] == "otserver-otter" and metadata["otterRun"] == "run1"
                    assert metadata["executionMode"] == "queued" and "site" not in metadata
                    export = json.loads(parts["file"])
                    assert export["format"] == "otserver-scan" and export["schemaVersion"] == 2
                    assert "lab-secret" not in parts["file"].decode()
                    data["uploads"].append(parts["file"])
                    if len(data["uploads"]) == 1:
                        self.send_json({"error": "temporarily unavailable"}, 503)
                        rejected_upload.set()
                    else:
                        assert data["uploads"][0] == data["uploads"][1]
                        self.send_json({"doc": {"id": "import1", "status": "pending"}}, 201)
                elif self.path == "/api/asset-imports/import1/retry":
                    data["retried"] += 1
                    assert data["retried"] == 1
                    self.send_json({"doc": {"id": "import1", "status": "pending"}})
                elif self.path.endswith("/finish"):
                    run = self.path.split("/")[-2]
                    result = json.loads(body)
                    assert result["status"] == {"run1": "completed", "run2": "cancelled", "run3": "failed"}[run]
                    if run == "run1":
                        assert result["importID"] == "import1"
                    data["finished"][run] = result["status"]
                    self.send_json({"status": result["status"]})
                else:
                    raise AssertionError("unknown route")

            def do_GET(self):
                assert self.path == "/api/asset-imports/import1"
                assert self.headers.get("Authorization") == "Otter " + data["credential"]
                data["importCompleted"] = data["retried"] == 1
                self.send_json({"id": "import1", "status": "completed" if data["importCompleted"] else "failed"})

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        url = f"https://localhost:{server.server_port}"
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        state = root / "state"
        environment = {**os.environ, "SSL_CERT_FILE": str(certificate)}
        command = [binary, "controller", "--server-url", url, "--state-dir", str(state), "--poll-seconds", "1", "--file-credentials", "--queued-imports", "--ack-authorized"]
        process = None
        try:
            process = subprocess.Popen([*command, "--enroll"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
            process.stdin.write(("t" * 43 + "\n").encode())
            process.stdin.close()
            process.stdin = None
            assert rejected_upload.wait(30), "first managed upload was not attempted"
            process.kill()
            first_logs = process.communicate(timeout=10)
            saved = json.loads((state / "agent-state.json").read_text())
            assert saved["assignment"]["phase"] == "ready" and saved["fileCredential"]["credential"] == "b" * 43
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
            last_logs = process.communicate(timeout=45)
            assert process.returncode == 1, "revocation must stop the agent"
            assert data["error"] is None and data["rotations"] == 1 and len(data["uploads"]) == 2
            assert len(data["finished"]) == 3 and data["retried"] == 1 and data["importCompleted"]
            for log in first_logs + last_logs:
                assert not any(secret.encode() in log for secret in ["a" * 43, "b" * 43, "t" * 43, "lab-secret"])
            subprocess.run([binary, "validate", str(state / "run1.otserver.json")], check=True, stdout=subprocess.DEVNULL)
            assert not (state / "run3.otserver.json").exists()
            assert "schemaVersion" in (state / "run2.otserver.json").read_text()
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.communicate()
            server.shutdown()
            server.server_close()
        print("Otter HTTPS controller lab passed (rotation, recovery, cancellation, import retry, revocation).")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/usr/local/bin/otserver-otter")
