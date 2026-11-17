"""TLS 接入层加固测试（进程内启动真实 HTTPS 服务器）。

覆盖值班场景的四类问题：
  T-1 慢握手/不发 ClientHello 的半开连接不再阻塞 accept，
      正常连接随时可握手；半开连接在握手超时后被关闭且额度回收；
  T-2 半开连接洪水打满待握手额度时，新连接被快速拒绝，
      已接入（握手完成）的慢请求仍能正常跑完；洪水退去后服务自愈；
  T-3 握手异常（明文 HTTP、畸形字节、对端 RST）只杀死该连接，
      监听不终止，后续正常握手不受影响；待握手额度不泄漏；
  T-4 换证后新握手呈现新证书；换证期间在途慢请求仍在旧证书连接上完成。
"""

from __future__ import annotations

import os
import socket
import ssl
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path

# 必须在导入 app.tls_service 前设置：模块在导入时读取这些环境变量
os.environ["CERT_POLL_INTERVAL"] = "0.1"
os.environ["TLS_HANDSHAKE_TIMEOUT"] = "2"
os.environ["TLS_MAX_PENDING_HANDSHAKES"] = "8"
os.environ["TLS_ACCEPT_BACKLOG"] = "32"

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
# 支持 `python -I`：隔离模式忽略 PYTHONPATH，显式加入外部依赖目录（若存在）
_deps = Path("/tmp/pydeps")
if _deps.is_dir():
    sys.path.insert(0, str(_deps))

from app.cert_store import (  # noqa: E402
    CertificateStore,
    fingerprint_sha256,
    generate_self_signed_cert,
)
from app.tls_service import (  # noqa: E402
    HANDSHAKE_TIMEOUT,
    MAX_PENDING_HANDSHAKES,
    DemoHandler,
    RotatingSSLContext,
    ThreadingHTTPServerTLS,
)
from tests.helpers import (  # noqa: E402
    slow_request_on_dedicated_connection,
    tls_handshake_fingerprint,
)


def https_get(port: int, path: str, timeout: float = 5) -> tuple[int, bytes]:
    ctx = ssl._create_unverified_context()
    with urllib.request.urlopen(
        f"https://127.0.0.1:{port}{path}", context=ctx, timeout=timeout
    ) as resp:
        return resp.status, resp.read()


def half_open_connection(port: int) -> socket.socket:
    """TCP 连上但绝不发送 ClientHello。"""
    return socket.create_connection(("127.0.0.1", port), timeout=5)


def wait_until(predicate, timeout: float, interval: float = 0.05) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


class IngressTestCase(unittest.TestCase):
    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="tls-ingress-")
        self.store = CertificateStore(self.data_dir)
        self.store.cleanup_temp()
        self.store.bootstrap()
        self.rotating = RotatingSSLContext(self.store)
        self.watcher = threading.Thread(
            target=self.rotating.watch_forever, name="cert-watcher", daemon=True
        )
        self.watcher.start()
        self.server = ThreadingHTTPServerTLS(
            ("127.0.0.1", 0), DemoHandler, self.rotating
        )
        self.port = self.server.server_address[1]
        self.server_thread = threading.Thread(
            target=self.server.serve_forever, name="serve", daemon=True
        )
        self.server_thread.start()
        # 等服务器可握手
        self.assertTrue(wait_until(lambda: self._handshake_ok(), 5))

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join(timeout=5)

    # ---------------- 工具 ---------------- #

    def _handshake_ok(self) -> bool:
        try:
            tls_handshake_fingerprint(self.port)
            return True
        except OSError:
            return False

    def _all_slots_free(self) -> bool:
        acquired = 0
        sema = self.server._handshake_slots
        for _ in range(MAX_PENDING_HANDSHAKES):
            if not sema.acquire(blocking=False):
                break
            acquired += 1
        for _ in range(acquired):
            sema.release()
        return acquired == MAX_PENDING_HANDSHAKES

    # ---------------- T-1 ---------------- #

    def test_01_half_open_connection_does_not_block_and_times_out(self):
        # 半开连接占用一个工作线程等待 ClientHello
        evil = half_open_connection(self.port)
        self.addCleanup(evil.close)
        self.assertTrue(
            wait_until(lambda: self.server.active_handshakes >= 1, 3),
            "半开连接应进入待握手状态",
        )

        # 关键断言：半开存在期间，正常连接立刻可握手（accept 未被卡住）
        t0 = time.time()
        fp = tls_handshake_fingerprint(self.port)
        self.assertLess(time.time() - t0, 2.0, "正常握手被半开连接阻塞")
        self.assertEqual(fp, self.store.read_state().fingerprint_sha256)

        # 超时后服务端主动关闭半开连接，待握手计数归零
        self.assertTrue(
            wait_until(lambda: self.server.active_handshakes == 0,
                       HANDSHAKE_TIMEOUT + 3),
            "握手超时后待握手计数未归零",
        )
        evil.settimeout(3)
        try:
            data = evil.recv(1)
        except OSError:
            data = b""  # RST 也算服务端已关闭
        self.assertEqual(data, b"", "超时半开连接未被服务端关闭")

        # 额度回收后新连接一切正常
        status, body = https_get(self.port, "/health")
        self.assertEqual(status, 200)
        self.assertIn(b"ok", body)

    # ---------------- T-2 ---------------- #

    def test_02_flood_is_rejected_when_full_but_admitted_request_completes(self):
        # 先接入一条合法慢请求连接（握手完成即释放待握手额度）
        result = {}

        def runner():
            try:
                result["value"] = slow_request_on_dedicated_connection(
                    self.port, 4
                )
            except Exception as exc:  # noqa: BLE001
                result["error"] = exc

        slow_thread = threading.Thread(target=runner)
        slow_thread.start()
        time.sleep(0.8)  # 确保慢请求已在服务端处理中

        # 半开洪水打满全部待握手额度
        flood = []
        for _ in range(MAX_PENDING_HANDSHAKES):
            flood.append(half_open_connection(self.port))
        try:
            self.assertTrue(
                wait_until(
                    lambda: self.server.active_handshakes
                    == MAX_PENDING_HANDSHAKES,
                    3,
                ),
                "待握手额度未被半开连接打满",
            )

            # 满额期间新连接必须被快速拒绝（而不是挂起或拖垮监听）
            rejected = 0
            for _ in range(5):
                try:
                    tls_handshake_fingerprint(self.port)
                except (OSError, ssl.SSLError):
                    rejected += 1
            self.assertGreaterEqual(rejected, 4, "满额时新连接未被拒绝")

            # 已接入的慢请求不受洪水影响，照常完成
            slow_thread.join(timeout=10)
            self.assertNotIn("error", result, "已接入慢请求异常结束")
            peer_fp, status_code, response = result["value"]
            self.assertEqual(status_code, 200)
            self.assertIn(b'"status": "ok"', response)
            self.assertEqual(peer_fp, self.store.read_state().fingerprint_sha256)
        finally:
            for sock in flood:
                sock.close()

        # 洪水退去（超时关闭 + 额度回收）后服务自愈
        self.assertTrue(
            wait_until(lambda: self.server.active_handshakes == 0,
                       HANDSHAKE_TIMEOUT + 3),
            "洪水退去后待握手计数未归零",
        )
        self.assertTrue(wait_until(self._handshake_ok, 5), "服务未能自愈")

    # ---------------- T-3 ---------------- #

    def test_03_bad_handshakes_are_isolated_and_slots_not_leaked(self):
        def garbage_round(payload: bytes):
            with socket.create_connection(("127.0.0.1", self.port), timeout=5) as raw:
                raw.sendall(payload)
                raw.settimeout(HANDSHAKE_TIMEOUT + 3)
                try:
                    first = raw.recv(1)
                    if first == b"\x15":
                        # 服务端先发 TLS alert 再关闭：读完直到 EOF
                        while raw.recv(4096):
                            pass
                    else:
                        self.assertEqual(first, b"", "握手失败后连接未被关闭")
                except OSError:
                    pass  # RST 同样意味着连接被服务端终结

        # 明文 HTTP 打到 TLS 端口（WRONG_VERSION_NUMBER）
        for _ in range(3):
            garbage_round(b"GET / HTTP/1.1\r\nHost: api.local\r\n\r\n")
        # 畸形 TLS 记录
        for _ in range(3):
            garbage_round(b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00\xff")
        # 连上立刻 RST（设置 linger 0 后关闭）
        for _ in range(3):
            raw = socket.create_connection(("127.0.0.1", self.port), timeout=5)
            raw.setsockopt(
                socket.SOL_SOCKET, socket.SO_LINGER,
                b"\x01\x00\x00\x00\x00\x00\x00\x00",
            )
            raw.close()

        # 等所有失败握手走完并释放额度
        self.assertTrue(
            wait_until(lambda: self.server.active_handshakes == 0,
                       HANDSHAKE_TIMEOUT + 3),
            "失败握手后待握手计数未归零",
        )
        # 监听仍存活：正常请求与握手均可完成
        status, _ = https_get(self.port, "/health")
        self.assertEqual(status, 200)
        self.assertTrue(tls_handshake_fingerprint(self.port))
        # 信号量额度全部回收，没有泄漏
        self.assertTrue(wait_until(self._all_slots_free, 3), "待握手额度泄漏")

    # ---------------- T-4 ---------------- #

    def test_04_rotation_serves_new_cert_to_new_handshakes(self):
        old_fp = self.store.read_state().fingerprint_sha256
        self.assertEqual(tls_handshake_fingerprint(self.port), old_fp)

        cert_pem, key_pem, cert = generate_self_signed_cert(["api.local"])
        new_fp = fingerprint_sha256(cert)
        info, changed = self.store.rotate(cert_pem, key_pem)
        self.assertTrue(changed)

        # watcher 轮询热切换后，新握手必须呈现新指纹
        self.assertTrue(
            wait_until(
                lambda: self.rotating.loaded_version == info.version, 5
            ),
            "TLS 服务未热切换到新版本",
        )
        self.assertTrue(
            wait_until(
                lambda: self._handshake_fp_is(new_fp), 5
            ),
            "新握手未使用新版证书",
        )

    def test_05_inflight_request_survives_rotation_on_old_cert(self):
        old_fp = self.store.read_state().fingerprint_sha256

        result = {}

        def runner():
            try:
                result["value"] = slow_request_on_dedicated_connection(
                    self.port, 4
                )
            except Exception as exc:  # noqa: BLE001
                result["error"] = exc

        t = threading.Thread(target=runner)
        t.start()
        time.sleep(0.8)  # 请求已在服务端处理中

        cert_pem, key_pem, cert = generate_self_signed_cert(["api.local"])
        new_fp = fingerprint_sha256(cert)
        self.store.rotate(cert_pem, key_pem)
        self.assertTrue(
            wait_until(lambda: self._handshake_fp_is(new_fp), 5),
            "换证后新握手未使用新证书",
        )

        t.join(timeout=10)
        self.assertNotIn("error", result, "在途慢请求被换证打断")
        peer_fp, status_code, _ = result["value"]
        self.assertEqual(status_code, 200)
        self.assertEqual(peer_fp, old_fp, "在途连接应始终使用握手时的旧证书")
        self.assertNotEqual(old_fp, new_fp)

    def _handshake_fp_is(self, expected_fp: str) -> bool:
        try:
            return tls_handshake_fingerprint(self.port) == expected_fp
        except OSError:
            return False


if __name__ == "__main__":
    unittest.main(verbosity=2)
