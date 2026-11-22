#!/usr/bin/env python3
"""
CF 反代节点精筛（直连探测版 v2，不依赖任何第三方 API）

原理:
  对每个 ip:port 直接建立 TLS 连接，SNI 使用你托管在 Cloudflare 上的域名，
  然后请求 https://<sni>/cdn-cgi/trace，并在 User-Agent 中放入随机 nonce。
  真正把流量转发到 Cloudflare 的节点会返回 trace 文本，其中包含:
      h=<你的域名>    uag=<原样回显的 UA(含 nonce)>    colo=<机房>    loc=<国家>
  校验项:
    1. TLS 证书对你的域名有效（默认开启）
    2. 响应带 server: cloudflare / cf-ray
    3. HTTP 200，且 trace 的 h 等于你的域名、uag 回显了本次随机 nonce
  蜜罐/伪造节点无法回显每次不同的 nonce，也拿不到你域名的有效证书，会被剔除。

用法:
  python3 verify.py --input cf_hits.txt --output verified.txt --sni your.domain.com
  python3 verify.py --self-test --sni your.domain.com      # 自检：验证域名/网络/校验链路是否正常
  (域名也可用环境变量 CF_VERIFY_SNI 指定)

输入格式: 每行一个 ip:port（IPv6 可写 [addr]:port 或 addr:port），无端口默认 443，# 开头为注释；
          行内第一个空白分隔的字段为目标，其后内容（如延迟）会被忽略。
输出格式: ip,port,TRUE,colo,country,region,latency_ms,,asn,proto   （region / asn 直连拿不到，留空）
"""

import argparse
import ipaddress
import os
import secrets
import socket
import ssl
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import NamedTuple, Optional

from lib.utils import write_progress, write_progress_done
from lib.scanner_utils import CSV_HEADER

MAX_RETRIES = 1           # 仅对"超时"这类可能是偶发的失败重试
MAX_RESPONSE = 16 * 1024  # trace 响应很小，限制读取量防止被灌数据
DEFAULT_PORT = 443

REASON_LABEL = {
    "ok": "通过",
    "connect": "连接失败",
    "tls": "TLS失败",
    "cert": "证书无效",
    "http": "HTTP异常",
    "not_cf": "非CF响应",
    "status": "状态码非200",
    "fake_host": "Host不符",
    "fake_nonce": "未回显nonce(疑似蜜罐)",
    "error": "其他异常",
}

REASON_HINT = {
    "connect": "到目标的网络不通，请检查网络出口",
    "tls": "TLS 握手失败",
    "cert": "证书校验失败：检查系统 CA 证书，或该域名的证书是否有效",
    "http": "HTTP 响应异常",
    "not_cf": "响应里没有 Cloudflare 头：域名可能没有开启橙云(代理)",
    "status": "状态码不是 200：/cdn-cgi/trace 可能被 WAF/规则拦截，可用 --path 换路径",
    "fake_host": "trace 里的 h 与域名不符",
    "fake_nonce": "trace 没有回显 nonce：可能被缓存/改写，或探测路径不是 /cdn-cgi/trace",
}

_write_lock = threading.Lock()
_stats_lock = threading.Lock()
_stats: Counter = Counter()


class Config(NamedTuple):
    sni: str
    path: str
    timeout: float
    ctx: ssl.SSLContext
    strict: bool  # True: 校验 trace 回显(反蜜罐)；False: 只要求 CF 响应头


class ProbeError(Exception):
    def __init__(self, reason: str, retry: bool = False):
        super().__init__(reason)
        self.reason = reason
        self.retry = retry


def _count(key: str) -> None:
    with _stats_lock:
        _stats[key] += 1


def _format_stats() -> str:
    return ", ".join(f"{REASON_LABEL.get(k, k)}={v}" for k, v in _stats.most_common())


def _make_ctx(verify_cert: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if not verify_cert:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _parse_target(token: str) -> Optional[tuple[str, int]]:
    token = token.strip()
    if not token:
        return None
    # 先按 host:port 解析（IPv6 不加方括号时，最后一个冒号后为端口）
    if token.startswith("["):
        host, _, rest = token[1:].partition("]")
        port_s = rest.lstrip(":")
    else:
        host, _, port_s = token.rpartition(":")
    try:
        ipaddress.ip_address(host)
        port = int(port_s)
        if 0 < port < 65536:
            return host, port
        return None
    except ValueError:
        pass
    # 解析失败时，整行如果本身就是一个 IP，则使用默认端口
    try:
        ipaddress.ip_address(token.strip("[]"))
        return token.strip("[]"), DEFAULT_PORT
    except ValueError:
        return None


def _probe(ip: str, port: int, cfg: Config) -> dict:
    nonce = secrets.token_hex(8)
    ua = f"Mozilla/5.0 (compatible; cfverify/{nonce})"
    sep = "&" if "?" in cfg.path else "?"
    req = (
        f"GET {cfg.path}{sep}_={nonce} HTTP/1.1\r\n"
        f"Host: {cfg.sni}\r\n"
        f"User-Agent: {ua}\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n\r\n"
    ).encode()

    # 1) TCP 连接
    t0 = time.perf_counter()
    try:
        sock = socket.create_connection((ip, port), timeout=cfg.timeout)
    except OSError:
        raise ProbeError("connect")

    # 2) TLS 握手（SNI = 你的域名）
    try:
        sock.settimeout(cfg.timeout)
        ssock = cfg.ctx.wrap_socket(sock, server_hostname=cfg.sni)
    except ssl.SSLCertVerificationError:
        sock.close()
        raise ProbeError("cert")
    except socket.timeout:
        sock.close()
        raise ProbeError("tls", retry=True)
    except (ssl.SSLError, OSError):
        sock.close()
        raise ProbeError("tls")

    # 3) 发请求并读取响应
    buf = bytearray()
    t_first: Optional[float] = None
    try:
        with ssock:
            ssock.sendall(req)
            deadline = time.monotonic() + cfg.timeout * 2
            while len(buf) < MAX_RESPONSE and time.monotonic() < deadline:
                chunk = ssock.recv(4096)
                if not chunk:
                    break
                if t_first is None:
                    t_first = time.perf_counter()
                buf += chunk
    except socket.timeout:
        if not buf:
            raise ProbeError("http", retry=True)
    except OSError:
        if not buf:
            raise ProbeError("http")

    latency = round(((t_first or time.perf_counter()) - t0) * 1000)

    # 4) 解析响应
    head, sep_b, body = bytes(buf).partition(b"\r\n\r\n")
    if not sep_b:
        raise ProbeError("http")
    head_lines = head.decode("latin-1").split("\r\n")
    status_parts = head_lines[0].split(" ", 2)
    if len(status_parts) < 2 or not status_parts[0].startswith("HTTP/"):
        raise ProbeError("http")
    try:
        status = int(status_parts[1])
    except ValueError:
        raise ProbeError("http")

    headers: dict[str, str] = {}
    for line in head_lines[1:]:
        k, _, v = line.partition(":")
        headers[k.strip().lower()] = v.strip()

    if "cloudflare" not in headers.get("server", "").lower() and "cf-ray" not in headers:
        raise ProbeError("not_cf")

    ray = headers.get("cf-ray", "")
    colo = ray.rsplit("-", 1)[-1] if "-" in ray else ""
    country = ""

    if cfg.strict:
        if status != 200:
            raise ProbeError("status")
        trace: dict[str, str] = {}
        for line in body.decode("utf-8", "ignore").splitlines():
            k, eq, v = line.partition("=")
            if eq:
                trace[k.strip()] = v.strip()
        if trace.get("h", "").lower() != cfg.sni.lower():
            raise ProbeError("fake_host")
        if nonce not in trace.get("uag", ""):
            raise ProbeError("fake_nonce")  # 没有回显随机 nonce → 伪造/蜜罐
        colo = trace.get("colo") or colo
        country = trace.get("loc", "")

    return {"colo": colo, "country": country, "latency": latency}


def _check_one(target: tuple[str, int], cfg: Config) -> Optional[str]:
    ip, port = target
    for attempt in range(MAX_RETRIES + 1):
        try:
            r = _probe(ip, port, cfg)
        except ProbeError as e:
            if e.retry and attempt < MAX_RETRIES:
                time.sleep(0.3 * (attempt + 1))
                continue
            _count(e.reason)
            return None
        except Exception:
            _count("error")
            return None
        _count("ok")
        # CSV: ip,port,TRUE,colo,country,region,latency,,asn,proto
        # 直连探测拿不到 region / ASN，留空
        region, asn = "", ""
        proto = "IPv6" if ":" in ip else "IPv4"
        return f"{ip},{port},TRUE,{r['colo']},{r['country']},{region},{r['latency']},,{asn},{proto}"
    return None


def _self_test(cfg: Config) -> int:
    """解析自有域名当前指向的 Cloudflare 边缘 IP，并用同一套校验去探测。
    通过 = 域名已开橙云、/cdn-cgi/trace 可访问、证书与校验链路正常。
    说明：不在输出里打印域名本身（Actions 日志里可能是公开的）。"""
    try:
        infos = socket.getaddrinfo(cfg.sni, DEFAULT_PORT, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as e:
        print(f"自检失败：SNI 域名无法解析（{e}）")
        return 1
    ips = list(dict.fromkeys(i[4][0] for i in infos))[:3]
    if not ips:
        print("自检失败：SNI 域名没有 IPv4 解析结果")
        return 1

    errors: list[str] = []
    first_reason = ""
    for ip in ips:
        try:
            r = _probe(ip, DEFAULT_PORT, cfg)
        except ProbeError as e:
            first_reason = first_reason or e.reason
            errors.append(f"{ip}:{REASON_LABEL.get(e.reason, e.reason)}")
            continue
        print(f"自检通过：{ip}:{DEFAULT_PORT} colo={r['colo'] or '?'} 延迟 {r['latency']}ms")
        return 0
    hint = REASON_HINT.get(first_reason, "")
    print("自检失败：" + "; ".join(errors) + (f"。{hint}" if hint else ""))
    return 1


def _read_input(path: str) -> list[str]:
    lines: list[str] = []
    if not os.path.isfile(path):
        print(f"  输入文件不存在: {path}")
        return lines
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            lines.append(parts[0] if parts else line)
    return lines


def _normalize_sni(s: str) -> str:
    s = s.strip()
    for prefix in ("https://", "http://"):
        if s.lower().startswith(prefix):
            s = s[len(prefix):]
    s = s.split("/", 1)[0].strip().lower()
    try:
        s = s.encode("idna").decode("ascii")  # 中文/Unicode 域名转 punycode
    except UnicodeError:
        pass
    return s


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CF 反代节点精筛（直连探测：自有域名 SNI + /cdn-cgi/trace）")
    parser.add_argument("--input", help="输入文件 (cf_hits.txt)")
    parser.add_argument("--output", help="输出文件 (verified.txt)")
    parser.add_argument("--sni", default=os.environ.get("CF_VERIFY_SNI", ""),
                        help="托管在 Cloudflare 上的你自己的域名（也可用环境变量 CF_VERIFY_SNI）")
    parser.add_argument("--path", default="/cdn-cgi/trace",
                        help="探测路径，默认 /cdn-cgi/trace")
    parser.add_argument("--timeout", type=float, default=5.0,
                        help="连接/握手/读取的单步超时秒数")
    parser.add_argument("--chunk", type=int, default=5000, help="分片大小")
    parser.add_argument("--concurrent", type=int, default=64, help="并发数")
    parser.add_argument("--append", action="store_true",
                        help="追加模式（不覆盖已有结果）")
    parser.add_argument("--follow", action="store_true",
                        help="流式模式（从 stdin 读取，EOF 为结束）")
    parser.add_argument("--honeypot-check", default=True, action=argparse.BooleanOptionalAction,
                        help="反蜜罐：校验 trace 回显的 host 与随机 nonce (默认开启；"
                             "关闭后只要求响应带 Cloudflare 头)")
    parser.add_argument("--verify-cert", default=True, action=argparse.BooleanOptionalAction,
                        help="校验 TLS 证书是否对你的域名有效 (默认开启)")
    parser.add_argument("--self-test", action="store_true",
                        help="自检：探测自有域名当前解析到的 CF 边缘 IP，通过返回 0，失败返回 1")
    parser.add_argument("--quiet", action="store_true",
                        help="不在 stderr 输出失败原因统计")
    parser.add_argument("--verbose", action="store_true", help=argparse.SUPPRESS)  # 兼容旧参数，已忽略
    parser.add_argument("--api", help=argparse.SUPPRESS)  # 兼容旧调用，已忽略
    args = parser.parse_args()

    sni = _normalize_sni(args.sni)
    if not sni:
        parser.error("必须通过 --sni 或环境变量 CF_VERIFY_SNI 指定你的 Cloudflare 域名")
    if not args.self_test and (not args.input or not args.output):
        parser.error("需要 --input 和 --output（或使用 --self-test）")

    cfg = Config(
        sni=sni,
        path=args.path if args.path.startswith("/") else "/" + args.path,
        timeout=args.timeout,
        ctx=_make_ctx(args.verify_cert),
        strict=args.honeypot_check,
    )

    if args.self_test:
        sys.exit(_self_test(cfg))

    if args.follow:
        raw = [l.strip() for l in sys.stdin if l.strip() and not l.startswith("#")]
        raw = [r.split()[0] for r in raw]
    else:
        raw = _read_input(args.input)

    parsed = (_parse_target(r) for r in raw)
    lines = list(dict.fromkeys(t for t in parsed if t))  # 去重并保持顺序
    total = len(lines)
    if total == 0:
        sys.exit(0)

    passed = 0
    last_extra = ""
    start = time.time()

    mode = "a" if args.append else "w"
    with open(args.output, mode) as out:
        if args.append:
            existing = Path(args.output).exists() and Path(args.output).stat().st_size > 0
            if not existing:
                out.write(CSV_HEADER + "\n")
        else:
            out.write(CSV_HEADER + "\n")
        with ThreadPoolExecutor(max_workers=args.concurrent) as ex:
            for i in range(0, total, args.chunk):
                chunk = lines[i:i + args.chunk]
                futures = [ex.submit(_check_one, t, cfg) for t in chunk]
                for f in as_completed(futures):
                    try:
                        r = f.result()
                    except Exception:
                        continue
                    if r:
                        with _write_lock:
                            out.write(r + "\n")
                        passed += 1
                        if passed % 100 == 0:
                            out.flush()
                out.flush()

                elapsed = time.time() - start
                done = i + len(chunk)
                rate = done / elapsed if elapsed > 0 else 0
                eta_min = (total - done) / rate / 60 if rate > 0 else 0
                eta_m, eta_s = divmod(int(eta_min * 60), 60)
                last_extra = f" | 通过 {passed}/{total} | ETA {eta_m}分{eta_s}秒 | 直连精筛"
                write_progress(done / total * 100, last_extra)

    elapsed = int(time.time() - start)
    ep = f"{elapsed // 60}分{elapsed % 60}秒"
    done_extra = f" | 通过 {passed}/{total} | {ep} | 直连精筛"
    if len(done_extra) < len(last_extra):
        done_extra = done_extra + " " * (len(last_extra) - len(done_extra))
    write_progress_done(done_extra)

    if not args.quiet and _stats:
        print("验证统计: " + _format_stats(), file=sys.stderr)


if __name__ == "__main__":
    main()
