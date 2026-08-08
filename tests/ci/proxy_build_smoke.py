#!/usr/bin/env python3
"""Dependency-free build/startup smoke checks for the GitHub Actions matrix."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


PAYOUT_ADDRESS = (
    "48edfHu7V9Z84YzzMa6fUueoELZ9ZRXq9VetWzYGzKt52XU5xvqgzYnDK9URnRoJ"
    "Mk1j8nLwEVsaSWJ4fhdUyZijBGUicoD"
)
API_TOKEN = "ci-only-loopback-token"


def parse_on_off(value: str) -> bool:
    normalized = value.strip().upper()
    if normalized not in {"ON", "OFF"}:
        raise argparse.ArgumentTypeError("expected ON or OFF")
    return normalized == "ON"


def run(
    argv: list[str],
    *,
    expected: int = 0,
    timeout: float = 30,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        argv,
        check=False,
        cwd=Path(__file__).resolve().parents[2],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
    )
    if result.returncode != expected:
        raise AssertionError(
            f"expected exit {expected}, got {result.returncode}: {' '.join(argv)}\n"
            f"{result.stdout}"
        )
    return result


def unused_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def daemon_config(*, api_port: int, stratum_port: int) -> dict[str, object]:
    return {
        "access-log-file": None,
        "access-password": "ci-stratum-password",
        "algo-ext": False,
        "api": {"id": "ci-daemon-solo", "worker-id": "ci-daemon-solo"},
        "http": {
            "enabled": True,
            "host": "127.0.0.1",
            "port": api_port,
            "access-token": API_TOKEN,
            # The CI POST test must reach the proxy's hard reload guard instead
            # of being rejected by the generic restricted-mode guard first.
            "restricted": False,
        },
        "background": False,
        "bind": [{"host": "127.0.0.1", "port": stratum_port, "tls": False}],
        "colors": False,
        "custom-diff": 4_194_304,
        "custom-diff-stats": True,
        "donate-level": 0,
        "event-stream": {
            "enabled": False,
            "path": "/run/xmrig-proxy/events.sock",
        },
        "randomx-verifier": {
            "enabled": False,
            "path": "/run/xmrig-randomx-verifier/verifier.sock",
            "timeout-ms": 5_000,
            "max-queue": 256,
            "max-pending-per-miner": 8,
            "max-consecutive-rejections": 8,
            "candidate-max-per-minute": 12,
            "candidate-global-max-per-minute": 48,
            "candidate-emergency-max-per-minute": 4,
        },
        "log-file": None,
        "mode": "simple",
        "pools": [
            {
                "algo": "rx/0",
                "coin": "monero",
                "url": "daemon+http://127.0.0.1:18081",
                "user": PAYOUT_ADDRESS,
                "pass": "x",
                "rig-id": None,
                "keepalive": False,
                "enabled": True,
                "tls": False,
                "sni": False,
                "tls-fingerprint": None,
                "daemon": True,
                "daemon-poll-interval": 20_000,
                "daemon-job-timeout": 5_000,
                "daemon-zmq-port": 18_083,
                "socks5": None,
                "self-select": None,
                "submit-to-origin": False,
            }
        ],
        "retries": 2,
        "retry-pause": 1,
        "reuse-timeout": 0,
        "tls": {
            "enabled": False,
            "protocols": None,
            "cert": None,
            "cert_key": None,
            "ciphers": None,
            "ciphersuites": None,
            "dhparam": None,
        },
        "dns": {"ip_version": 0, "ttl": 30},
        "user-agent": None,
        "syslog": False,
        "verbose": False,
        "watch": False,
        "workers": True,
    }


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def assert_cli_contract(binary: Path, *, with_http: bool, with_tls: bool) -> None:
    version = run([str(binary), "--version"]).stdout
    assert "libuv/" in version, version
    assert ("OpenSSL/" in version) is with_tls, version

    help_text = run([str(binary), "--help"]).stdout
    for feature in ("--daemon", "--http-port"):
        assert (feature in help_text) is with_http, help_text
    assert ("--tls-bind" in help_text) is with_tls, help_text

    linkage = run(["ldd", str(binary)]).stdout
    assert "not found" not in linkage, linkage

    # The checked-in ordinary-pool configuration must parse in every build.
    run([str(binary), "--no-color", "--config=src/config.json", "--dry-run"])

    # An explicit missing configuration must never fall through to otherwise
    # valid CLI pool arguments or a fallback file.
    with tempfile.TemporaryDirectory(prefix="xmrig-config-guard-") as directory:
        missing = Path(directory, "missing.json")
        for option in (f"--config={missing}", f"-c{missing}"):
            run(
                [
                    str(binary),
                    "--no-color",
                    option,
                    "--url=pool.example.invalid:3333",
                    f"--user={PAYOUT_ADDRESS}",
                    "--dry-run",
                ],
                expected=2,
            )


def assert_daemon_config_contract(
    binary: Path,
    *,
    with_http: bool,
    test_invalid_address: bool,
) -> None:
    with tempfile.TemporaryDirectory(prefix="xmrig-daemon-config-") as directory:
        root = Path(directory)
        config = daemon_config(
            api_port=unused_loopback_port(),
            stratum_port=unused_loopback_port(),
        )
        path = root / "daemon.json"
        write_json(path, config)

        result = run(
            [str(binary), "--no-color", f"--config={path}", "--dry-run"],
            expected=0 if with_http else 2,
        )
        if with_http:
            assert "Solo Mining with Daemon to Address:" in result.stdout, result.stdout
            assert PAYOUT_ADDRESS in result.stdout, result.stdout
        else:
            assert "daemon solo mining requires a proxy build with HTTP support" in result.stdout

        if test_invalid_address:
            invalid = json.loads(json.dumps(config))
            invalid["pools"][0]["user"] = PAYOUT_ADDRESS[:-1] + "E"
            invalid_path = root / "invalid-wallet.json"
            write_json(invalid_path, invalid)
            result = run(
                [str(binary), "--no-color", f"--config={invalid_path}", "--dry-run"],
                expected=2,
            )
            assert "invalid payout address" in result.stdout, result.stdout

            watched = json.loads(json.dumps(config))
            watched["watch"] = True
            watched_path = root / "watched.json"
            write_json(watched_path, watched)
            result = run(
                [str(binary), "--no-color", f"--config={watched_path}", "--dry-run"],
                expected=2,
            )
            assert "configuration hot reload is disabled" in result.stdout, result.stdout


def authenticated_request(
    url: str,
    *,
    method: str = "GET",
    body: bytes | None = None,
) -> urllib.request.Request:
    headers = {"Authorization": f"Bearer {API_TOKEN}"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    return urllib.request.Request(url, data=body, headers=headers, method=method)


def assert_live_api(binary: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="xmrig-live-api-") as directory:
        root = Path(directory)
        api_port = unused_loopback_port()
        stratum_port = unused_loopback_port()
        config = daemon_config(
            api_port=api_port,
            stratum_port=stratum_port,
        )
        config_path = root / "live.json"
        log_path = root / "proxy.log"
        write_json(config_path, config)

        with log_path.open("w+", encoding="utf-8") as log:
            process = subprocess.Popen(
                [str(binary), "--no-color", f"--config={config_path}"],
                cwd=Path(__file__).resolve().parents[2],
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
            )
            try:
                summary: dict[str, object] | None = None
                deadline = time.monotonic() + 15
                summary_url = f"http://127.0.0.1:{api_port}/1/summary"
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        break
                    try:
                        with urllib.request.urlopen(
                            authenticated_request(summary_url), timeout=1
                        ) as response:
                            summary = json.load(response)
                        break
                    except (OSError, urllib.error.URLError, json.JSONDecodeError):
                        time.sleep(0.1)

                if summary is None:
                    log.flush()
                    log.seek(0)
                    raise AssertionError(
                        "proxy API did not become ready\n" + log.read()
                    )

                assert summary.get("kind") == "proxy", summary
                assert summary.get("mode") == "simple", summary
                daemon_solo = summary.get("daemon_solo")
                assert isinstance(daemon_solo, dict), summary
                assert daemon_solo.get("enabled") is True, daemon_solo
                payouts = daemon_solo.get("payouts")
                assert isinstance(payouts, list) and len(payouts) == 1, daemon_solo
                assert payouts[0] == {
                    "address": PAYOUT_ADDRESS,
                    "coin": "XMR",
                    "network": "mainnet",
                    "type": "primary",
                    "validated": True,
                }, payouts[0]

                # A healthy API alone must not hide a failed Stratum bind.
                with socket.create_connection(
                    ("127.0.0.1", stratum_port), timeout=2
                ):
                    pass

                config_url = f"http://127.0.0.1:{api_port}/1/config"
                try:
                    urllib.request.urlopen(
                        authenticated_request(
                            config_url,
                            method="POST",
                            body=b"{}",
                        ),
                        timeout=2,
                    )
                except urllib.error.HTTPError as error:
                    assert error.code == 403, error.code
                else:
                    raise AssertionError("runtime configuration POST was accepted")
            finally:
                if process.poll() is None:
                    process.send_signal(signal.SIGTERM)
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
                        raise AssertionError("proxy did not stop after SIGTERM")

            if process.returncode != 0:
                log.flush()
                log.seek(0)
                raise AssertionError(
                    f"proxy exited with {process.returncode}\n{log.read()}"
                )

            log.flush()
            log.seek(0)
            output = log.read()
            assert "listen error" not in output, output
            assert "HTTP API server failed to start" not in output, output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--with-http", required=True, type=parse_on_off)
    parser.add_argument("--with-tls", required=True, type=parse_on_off)
    parser.add_argument("--live-api", action="store_true")
    args = parser.parse_args()

    binary = args.binary.resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise SystemExit(f"not an executable file: {binary}")
    if args.live_api and not args.with_http:
        raise SystemExit("--live-api requires --with-http ON")

    assert_cli_contract(binary, with_http=args.with_http, with_tls=args.with_tls)
    assert_daemon_config_contract(
        binary,
        with_http=args.with_http,
        test_invalid_address=args.live_api,
    )
    if args.live_api:
        assert_live_api(binary)

    print(
        "PASS:",
        binary.name,
        f"HTTP={'ON' if args.with_http else 'OFF'}",
        f"TLS={'ON' if args.with_tls else 'OFF'}",
        "live-api" if args.live_api else "static-smoke",
    )


if __name__ == "__main__":
    main()
