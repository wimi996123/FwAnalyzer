"""End-to-end tests for the MCP wrapper (mcp_server.py).

The server is exercised as a real subprocess over stdio: a batch of JSON-RPC
lines goes in, the response lines come out. That keeps the tests synchronous and
bounded while covering the actual transport.

A small ELF fixture is compiled with Keil's armclang when it is available; the
transport/argument tests run everywhere.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[0]
ARMC_LANG_CANDIDATES = [
    os.environ.get("KEIL_ARMCLANG", ""),
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "Keil_v5", "ARM", "ARMCLANG", "Bin", "armclang.exe"),
    os.path.join(os.environ.get("ProgramFiles", ""), "Keil_v5", "ARM", "ARMCLANG", "Bin", "armclang.exe"),
]
ARMLINK_CANDIDATES = [
    os.environ.get("KEIL_ARMLINK", ""),
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "Keil_v5", "ARM", "ARMCLANG", "Bin", "armlink.exe"),
    os.path.join(os.environ.get("ProgramFiles", ""), "Keil_v5", "ARM", "ARMCLANG", "Bin", "armlink.exe"),
]


def _find_armclang() -> str | None:
    for candidate in ARMC_LANG_CANDIDATES:
        if candidate and Path(candidate).is_file():
            return candidate
    return shutil.which("armclang")


def _find_armlink() -> str | None:
    for candidate in ARMLINK_CANDIDATES:
        if candidate and Path(candidate).is_file():
            return candidate
    return shutil.which("armlink")


def _make_fixture(directory: Path) -> Path | None:
    """Build a tiny linked ELF with DWARF; falls back to the object file."""
    armclang = _find_armclang()
    if armclang is None:
        return None
    source = directory / "fixture.c"
    source.write_text(
        "#include <stdint.h>\n"
        "typedef struct { uint32_t a; uint16_t b; uint8_t c[13]; } demo_ctx;\n"
        "demo_ctx g_ctx;\n"
        "int helper(int x) { g_ctx.a += x; return g_ctx.a; }\n"
        "int level2(int x) { return helper(x + 2); }\n"
        "int level1(int x) { return level2(x + 1); }\n"
        "int main(void) { level1(3); for (;;) { } }\n",
        encoding="utf-8",
    )
    target = directory / "fixture.o"
    completed = subprocess.run(
        [armclang, "-c", "-g", "-O0", "--target=arm-arm-none-eabi", "-mcpu=cortex-m4", "-mthumb",
         str(source), "-o", str(target)],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120,
    )
    if completed.returncode != 0 or not target.is_file():
        return None
    armlink = _find_armlink()
    if armlink is not None:
        linked = directory / "fixture.elf"
        link = subprocess.run(
            [armlink, "--cpu=Cortex-M4", "--entry=main", "--ro-base=0x08000000",
             "--rw-base=0x20000000", f"--output={linked}", "--no_startup", str(target)],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120,
        )
        if link.returncode == 0 and linked.is_file():
            return linked
    return target


def _run_messages(messages: list[dict], timeout: int = 120) -> list[dict]:
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    payload = "".join(json.dumps(message) + "\n" for message in messages)
    completed = subprocess.run(
        [sys.executable, "mcp_server.py"],
        input=payload, capture_output=True, text=True, encoding="utf-8",
        cwd=str(REPO_ROOT), env=env, timeout=timeout,
    )
    return [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]


def _call(request_id: int, name: str, arguments: dict) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
            "params": {"name": name, "arguments": arguments}}


INITIALIZE = {"jsonrpc": "2.0", "id": 0, "method": "initialize",
              "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                         "clientInfo": {"name": "tests", "version": "0"}}}


def _payload(response: dict) -> dict:
    return json.loads(response["result"]["content"][0]["text"])


class TransportTests(unittest.TestCase):
    def test_initialize_and_tool_list(self) -> None:
        responses = _run_messages([INITIALIZE, {"jsonrpc": "2.0", "method": "notifications/initialized"},
                                   {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}])
        self.assertEqual(responses[0]["result"]["serverInfo"]["name"], "axf-analyzer")
        self.assertIn("tools", responses[0]["result"]["capabilities"])
        tools = {tool["name"] for tool in responses[1]["result"]["tools"]}
        self.assertEqual(len(tools), 14)
        self.assertIn("axf_addr2line", tools)
        self.assertIn("axf_stackdepth", tools)
        self.assertIn("axf_audit_tasks", tools)
        for tool in responses[1]["result"]["tools"]:
            self.assertEqual(tool["inputSchema"]["type"], "object")
            self.assertIn("axf", tool["inputSchema"]["properties"])

    def test_every_tool_declares_all_four_annotation_hints(self) -> None:
        """Tool directories reject tools whose hints are missing or non-boolean."""
        responses = _run_messages([INITIALIZE, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}])
        tools = responses[1]["result"]["tools"]
        self.assertEqual(len(tools), 14)
        for tool in tools:
            annotations = tool.get("annotations")
            self.assertIsInstance(annotations, dict, f"{tool['name']} declares no annotations")
            for hint in ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"):
                self.assertIsInstance(annotations.get(hint), bool,
                                      f"{tool['name']}.annotations.{hint} must be an explicit boolean")
            # The whole server is read-only, so the hints must say exactly that.
            self.assertTrue(annotations["readOnlyHint"], tool["name"])
            self.assertFalse(annotations["destructiveHint"], tool["name"])
            self.assertTrue(annotations["idempotentHint"], tool["name"])
            self.assertFalse(annotations["openWorldHint"], tool["name"])

    def test_protocol_errors_do_not_kill_the_server(self) -> None:
        responses = _run_messages([
            INITIALIZE,
            {"jsonrpc": "2.0", "id": 2, "method": "no/such/method"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "axf_nope", "arguments": {}}},
        ])
        self.assertEqual(responses[1]["error"]["code"], -32601)
        payload = _payload(responses[2])
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"]["code"], "UNKNOWN_TOOL")

    def test_missing_file_is_a_tool_error(self) -> None:
        responses = _run_messages([INITIALIZE, _call(1, "axf_file_info", {"axf": "does-not-exist.axf"})])
        payload = _payload(responses[1])
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"]["code"], "FILE_NOT_FOUND")

    def test_bad_address_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = _make_fixture(Path(tmp))
            if fixture is None:
                self.skipTest("armclang not available")
            responses = _run_messages([INITIALIZE, _call(1, "axf_addr2line",
                                                         {"axf": str(fixture), "address": "zzz"})])
            payload = _payload(responses[1])
            self.assertEqual(payload["error"]["code"], "BAD_ARGUMENT")


class AnalyzerToolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        fixture = _make_fixture(Path(cls.tmp.name))
        if fixture is None:
            cls.tmp.cleanup()
            raise unittest.SkipTest("armclang not available")
        cls.fixture = fixture

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def _fixture(self) -> Path:
        return Path(self.fixture)

    def test_file_info_build_info_and_segments(self) -> None:
        responses = _run_messages([
            INITIALIZE,
            _call(1, "axf_file_info", {"axf": str(self._fixture())}),
            _call(2, "axf_build_info", {"axf": str(self._fixture())}),
            _call(3, "axf_segments", {"axf": str(self._fixture())}),
        ])
        info = _payload(responses[1])["data"]
        self.assertEqual(len(info["sha256"]), 64)
        build = _payload(responses[2])["data"]
        self.assertIn("architecture", build)
        segments = _payload(responses[3])["data"]["segments"]
        self.assertIsInstance(segments, list)

    def test_symbols_struct_stackframe_and_stackdepth(self) -> None:
        responses = _run_messages([
            INITIALIZE,
            _call(1, "axf_symbols_top", {"axf": str(self._fixture()), "kind": "func", "limit": 5}),
            _call(2, "axf_struct", {"axf": str(self._fixture()), "name": "demo_ctx"}),
            _call(3, "axf_stackframe", {"axf": str(self._fixture()), "function": "helper"}),
            _call(4, "axf_stackdepth", {"axf": str(self._fixture()), "entry": "main"}),
            _call(5, "axf_checksum", {"axf": str(self._fixture())}),
        ])
        top = _payload(responses[1])["data"]
        self.assertTrue(top["symbols"], top)
        self.assertIn("helper", {symbol["name"] for symbol in top["symbols"]})

        struct = _payload(responses[2])["data"]
        self.assertGreater(struct["size"], 0)
        self.assertTrue(struct["members"])

        frame = _payload(responses[3])["data"]
        self.assertGreaterEqual(frame["stack_frame"], 0)
        self.assertIn("source", frame)

        depth = _payload(responses[4])["data"]
        self.assertEqual(depth["tree"]["function"], "main")
        self.assertGreater(depth["summary"]["required_bytes"], 0)

        checksum = _payload(responses[5])["data"]["sha256"]
        self.assertTrue(checksum)
        self.assertTrue(all(len(value) == 64 for value in checksum.values()))

    def test_addr2line_and_disasm(self) -> None:
        responses = _run_messages([INITIALIZE, _call(1, "axf_symbol_addr",
                                                     {"axf": str(self._fixture()), "name": "main"})])
        symbol = _payload(responses[1])["data"]
        address = symbol["address"]
        batch = _run_messages([
            INITIALIZE,
            _call(1, "axf_addr2line", {"axf": str(self._fixture()), "address": address}),
            _call(2, "axf_disasm", {"axf": str(self._fixture()), "function": "helper", "max_chars": 200}),
            _call(3, "axf_callgraph", {"axf": str(self._fixture()), "function": "main", "depth": 2,
                                       "max_chars": 400}),
        ])
        location = _payload(batch[1])
        # A relocatable object may or may not carry usable line info; either way the tool must not crash.
        if location["ok"]:
            self.assertGreaterEqual(len(location["data"]["frames"]), 1)
        else:
            self.assertEqual(location["error"]["code"], "NO_SOURCE_INFO")

        disasm = _payload(batch[2])["data"]
        self.assertIn("text", disasm)
        self.assertLessEqual(len(disasm["text"]), 200 + 120)

        callgraph = _payload(batch[3])["data"]
        self.assertIn("text", callgraph)
        self.assertLessEqual(len(callgraph["text"]), 400 + 120)


if __name__ == "__main__":
    unittest.main()
