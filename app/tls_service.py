"""面向 api.local 的 HTTPS 演示服务。

关键能力：
* 使用标准库 ssl.SSLContext，从 CertificateStore 的现役版本文件加载证书；
* 后台线程轮询 current.json，发现新版本即构建新 SSLContext 并原子替换，
  已建立的 TLS 连接仍持有旧 context，会用旧证书把在途请求处理完，
  只有新握手使用新证书；
* /slow 端点模拟耗时请求，用于验证换证不中断在途请求；
* 重载失败时保留上一个可用 context，服务不中断。

连接接入保护（值班场景加固）：
* accept 线程只做 TCP accept，TLS 握手在每连接工作线程中执行，
  任何一个握手卡死或异常都不会终止监听、不会挡住后续连接；
* 待握手连接受信号量约束（TLS_MAX_PENDING_HANDSHAKES），
  半开连接洪水打满额度时直接拒绝并关闭新 TCP 连接，
  已接入（拿到额度）的连接仍会完成握手与请求处理；
* 握手带总超时（TLS_HANDSHAKE_TIMEOUT 秒），未完成 ClientHello 的
  半开连接到期即关闭，额度随之回收；
* 握手在工作线程内才读取“当前最新” SSLContext，因此换证后获准
  接入的新握手一律使用新版证书。
"""

from __future__ import annotations

import http.server
import json
import os
import socket
import ssl
import threading
import time

from .cert_store import CertificateStore

POLL_INTERVAL = float(os.environ.get("CERT_POLL_INTERVAL", "0.5"))
# 握手总超时：超时未完成 TLS 握手（含迟迟不发 ClientHello）的连接被关闭
HANDSHAKE_TIMEOUT = float(os.environ.get("TLS_HANDSHAKE_TIMEOUT", "10"))
# 待握手连接上限：同时持有“待握手额度”的连接数，满额时拒绝新连接
MAX_PENDING_HANDSHAKES = int(os.environ.get("TLS_MAX_PENDING_HANDSHAKES", "128"))
# listen backlog：TCP 全连接队列长度
ACCEPT_BACKLOG = int(os.environ.get("TLS_ACCEPT_BACKLOG", "128"))


class RotatingSSLContext:
    """持有当前 SSLContext，按 current.json 版本号热切换。"""

    def __init__(self, store: CertificateStore):
        self._store = store
        self._lock = threading.Lock()
        self._context: ssl.SSLContext | None = None
        self._loaded_version: int | None = None
        self.reload(initial=True)

    @property
    def loaded_version(self) -> int | None:
        return self._loaded_version

    def get(self) -> ssl.SSLContext:
        with self._lock:
            assert self._context is not None
            return self._context

    def reload(self, initial: bool = False) -> bool:
        """检查现役版本是否变化并重新加载。返回是否发生了切换。"""
        try:
            version = self._store._read_current_version()
            if version is None:
                return False
            if not initial and version == self._loaded_version:
                return False
            cert_path, key_path = self._store.current_paths()
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            # 显式给出最小版本，避免演示环境与系统默认值差异
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
            with self._lock:
                old = self._context
                self._context = ctx
                self._loaded_version = version
            # 旧 context 不主动关闭：正在处理的连接仍在使用它，
            # 等连接结束后由 GC/OpenSSL 自行释放。
            del old
            return True
        except (ssl.SSLError, OSError, FileNotFoundError, json.JSONDecodeError, KeyError) as exc:
            # 落盘已是原子操作，这里主要防御外部误删；保留旧 context 继续服务
            print(f"[tls] 证书重载失败，保留版本 {self._loaded_version}: {exc!r}", flush=True)
            return False

    def watch_forever(self) -> None:
        while True:
            time.sleep(POLL_INTERVAL)
            try:
                if self.reload():
                    print(f"[tls] 已热切换到证书版本 {self._loaded_version}", flush=True)
            except Exception as exc:  # 守护线程绝不能死
                print(f"[tls] 轮询异常（已忽略）: {exc!r}", flush=True)


class DemoHandler(http.server.BaseHTTPRequestHandler):
    server_version = "CertRotateDemo/1.0"

    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - stdlib 命名
        if self.path in ("/", "/health"):
            self._json(200, {"status": "ok", "service": "https-demo"})
        elif self.path.startswith("/slow"):
            # ?seconds=3，默认 3 秒，上限 30 秒
            from urllib.parse import parse_qs, urlparse

            qs = parse_qs(urlparse(self.path).query)
            try:
                seconds = min(max(float(qs.get("seconds", ["3"])[0]), 0), 30)
            except ValueError:
                seconds = 3
            time.sleep(seconds)
            self._json(200, {"status": "ok", "slept_seconds": seconds})
        else:
            self._json(404, {"detail": "not found"})

    def log_message(self, fmt: str, *args) -> None:  # 安静一点
        print(f"[tls] {self.address_string()} {fmt % args}", flush=True)


class ThreadingHTTPServerTLS(http.server.ThreadingHTTPServer):
    """带握手隔离、握手超时与待握手额度的 HTTPS 服务器。

    与基类的关键差异：
    * ``get_request`` 只 accept 原始 TCP 套接字，绝不在 accept 线程做
      TLS 握手（旧实现会在 accept 线程阻塞式 wrap_socket，一个不发
      ClientHello 的连接即可冻结全部新接入）；
    * ``verify_request`` 用非阻塞信号量限制待握手连接数，满额即拒绝；
    * 工作线程内完成带超时的握手，任何握手异常只结束该连接，
      监听循环与其他连接不受影响。
    """

    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = ACCEPT_BACKLOG

    def __init__(self, addr, handler, rotating_ctx: RotatingSSLContext):
        super().__init__(addr, handler)
        self._rotating_ctx = rotating_ctx
        # 待握手额度：握手完成（成功或失败）后立即释放，
        # 因此长连接/慢请求不占用待握手额度，已接入请求总能跑完。
        self._handshake_slots = threading.BoundedSemaphore(MAX_PENDING_HANDSHAKES)
        self._active_handshakes = 0
        self._active_lock = threading.Lock()

    # ---------------- 接入指标（测试/排障用） ---------------- #

    @property
    def active_handshakes(self) -> int:
        with self._active_lock:
            return self._active_handshakes

    # ---------------- 接入主流程 ---------------- #

    def get_request(self):
        # 只 accept 裸 TCP；TLS 握手下沉到工作线程，accept 线程永不阻塞于 SSL
        return self.socket.accept()

    def verify_request(self, request, client_address) -> bool:
        # 非阻塞申请待握手额度：满额（半开连接洪水）时拒绝新连接。
        # 返回 False 后 ThreadingMixIn.process_request 会自行关闭套接字，
        # 不派发工作线程，监听循环继续服务。
        if self._handshake_slots.acquire(blocking=False):
            with self._active_lock:
                self._active_handshakes += 1
            return True
        print(
            f"[tls] 待握手连接已达上限 {MAX_PENDING_HANDSHAKES}，"
            f"拒绝新连接 {client_address}",
            flush=True,
        )
        return False

    def handle_error(self, request, client_address):
        # 接入/握手阶段的异常只记录，不允许冒泡打断 serve_forever
        print(f"[tls] 连接 {client_address} 处理异常（已关闭该连接）", flush=True)

    def process_request_thread(self, request, client_address):
        # 覆盖 ThreadingMixIn 的同名方法：工作线程入口。
        # 进入本方法即代表已拿到待握手额度。
        self._handle_client(request, client_address)

    def _release_handshake_slot(self) -> None:
        with self._active_lock:
            self._active_handshakes -= 1
        self._handshake_slots.release()

    def _handshake(self, sock: socket.socket) -> ssl.SSLSocket:
        """在工作线程内完成带超时的 TLS 握手。"""
        sock.settimeout(HANDSHAKE_TIMEOUT)
        # 此刻才取当前最新 context：换证后获准接入的新握手一律用新证书。
        # 连接一旦包装完成，其证书配置即固化，后续换证不影响在途连接。
        ctx = self._rotating_ctx.get()
        return ctx.wrap_socket(sock, server_side=True)

    def _handle_client(self, sock: socket.socket, client_address) -> None:
        tls_sock = None
        try:
            try:
                tls_sock = self._handshake(sock)
            except (socket.timeout, TimeoutError):
                print(
                    f"[tls] 握手超时（{HANDSHAKE_TIMEOUT:g}s 未完成），"
                    f"关闭 {client_address}",
                    flush=True,
                )
                return
            except ssl.SSLError as exc:
                # 畸形 ClientHello / 协议错误等：只丢弃这一条连接
                print(f"[tls] 握手失败，关闭 {client_address}: {exc!r}", flush=True)
                return
            except OSError as exc:
                print(f"[tls] 连接异常，关闭 {client_address}: {exc!r}", flush=True)
                return
            # 握手完成：先恢复阻塞语义（无数据超时），再交还标准请求处理；
            # 慢请求 / 长连接在此之后不再受握手超时限制。
            tls_sock.settimeout(None)
            try:
                self.finish_request(tls_sock, client_address)
            except Exception:
                self.handle_error(tls_sock, client_address)
            finally:
                self.shutdown_request(tls_sock)
        except Exception as exc:  # 兜底：单连接任何异常都不得波及监听
            print(f"[tls] 连接 {client_address} 未预期异常（已隔离）: {exc!r}", flush=True)
        finally:
            if tls_sock is None:
                # 握手未成功，裸套接字由本方法负责关闭
                try:
                    sock.close()
                except OSError:
                    pass
            # 无论握手成败都释放额度，保证半开连接超时后槽位可回收
            self._release_handshake_slot()


def serve(data_dir: str, host: str = "0.0.0.0", port: int = 8443) -> None:
    store = CertificateStore(data_dir)
    store.cleanup_temp()
    store.bootstrap()
    rotating_ctx = RotatingSSLContext(store)

    watcher = threading.Thread(
        target=rotating_ctx.watch_forever, name="cert-watcher", daemon=True
    )
    watcher.start()

    server = ThreadingHTTPServerTLS((host, port), DemoHandler, rotating_ctx)
    print(
        f"[tls] HTTPS 演示服务监听 {host}:{port}，"
        f"现役证书版本 v{rotating_ctx.loaded_version}，"
        f"握手超时 {HANDSHAKE_TIMEOUT:g}s，待握手上限 {MAX_PENDING_HANDSHAKES}，"
        f"backlog {ACCEPT_BACKLOG}",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    serve(
        data_dir=os.environ.get("CERT_DATA_DIR", "/data/certs"),
        host=os.environ.get("TLS_HOST", "0.0.0.0"),
        port=int(os.environ.get("TLS_PORT", "8443")),
    )
