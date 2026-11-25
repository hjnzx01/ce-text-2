#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloudflare 反代 IP 优选（GitHub Actions 友好版 · 按端口接力）

流程
  来源-1.txt 网段 → 全部拆成单 IP → 按批做 TCP 端口扫描（开放 + 延迟）
  → 开放且延迟在范围内的 IP:端口 立即送 verify.py（直连精筛：自有域名 SNI + /cdn-cgi/trace，含反蜜罐）
  → 通过者连同延迟写入 output/

端口队列（每次运行只扫一个端口）
  端口列表默认 DEFAULT_PORTS（443 在最前）。每次运行只扫「队列中第一个尚未完成的端口」：
  该端口的全部 IP 扫完 → 验完队列 → 标记为已完成 → 本次运行结束；
  下一次运行（workflow 在 10 分钟后自动触发）自动换成队列里的下一个端口。
  一次运行时间预算用完但端口没扫完，则下次继续扫同一个端口（断点续跑）。
  所有端口都扫完后：默认停止自动接力（CF_LOOP_FOREVER=true 则自动开始新一轮）。

断点续跑
  output/state/progress.json       当前端口、该端口的 IP 偏移（cursor）、已完成端口、轮次、来源指纹
  output/state/pending_verify.txt  已扫到但尚未验证完的 IP:端口（下次运行优先验证）

去重
  结果以 (IP, 端口) 为唯一键；同 IP:端口 重复验证通过时以最新一次为准，
  cf_verified.csv / best_ip_ports.txt 中不会出现重复的 IP:端口。

只依赖标准库；verify.py 需与本脚本同目录（可用 --verify-script 指定）。
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import io
import ipaddress
import itertools
import json
import os
import re
import resource
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

# 默认端口队列：按顺序逐个扫描，443 最先
DEFAULT_PORTS = [
    443, 80, 8443, 9443, 30005, 8880, 2083, 2053, 8080, 2096,
    24442, 2082, 1024, 2087, 2086, 2095, 1025, 10443, 2052, 4443,
    4433, 7443, 10000, 8085, 27017, 10002, 20000, 10001, 28017, 18080,
    11434, 20202, 20201, 8000, 10101, 50001, 44365, 8081, 444, 4444,
    8001, 49154, 6443, 14430, 65530, 10033, 3389, 11235, 20002, 18852,
]

RESULT_COLUMNS = [
    "IP", "Port", "IP_Port", "TCP_Latency_ms", "API_Latency_ms",
    "Colo", "Country", "Region", "ASN", "Protocol", "Verified_At",
]

STOP = False

# verify.py 依赖 lib.utils / lib.scanner_utils。仓库里没有时，用这两个最小兼容版顶上（仅临时目录，不提交）
SHIM_UTILS = '''import sys


def write_progress(percent, extra=""):
    sys.stdout.write("\\r  [%5.1f%%]%s" % (percent, extra))
    sys.stdout.flush()


def write_progress_done(extra=""):
    sys.stdout.write("\\r  [100.0%%]%s\\n" % extra)
    sys.stdout.flush()
'''
SHIM_SCANNER = 'CSV_HEADER = "IP,Port,CF,Colo,Country,Region,Latency_ms,Speed,ASN,Protocol"\n'

TOKEN_V4_PORT = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}(?:/\d+)?):\d+$")
TOKEN_V6_BRACKET = re.compile(r"^\[([0-9A-Fa-f:.]+(?:/\d+)?)\](?::\d+)?$")


class Abort(Exception):
    """不可继续的错误：保存状态后以非零码退出。
    fatal=True（配置类错误）：同时通知 workflow 不要再自动接力；
    fatal=False（运行期的临时故障）：保留状态，workflow 仍会 10 分钟后重试。"""

    def __init__(self, msg: str, fatal: bool = True):
        super().__init__(msg)
        self.fatal = fatal


# ───────────────────────── 通用小工具 ─────────────────────────

def log(msg: str) -> None:
    print(msg, flush=True)


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def env_str(name: str, default: str = "") -> str:
    v = os.environ.get(name, "")
    v = v.strip() if v else ""
    return v if v else default


def to_num(value, default, cast=float, lo=None, hi=None):
    try:
        n = cast(str(value).strip())
    except (TypeError, ValueError):
        return default
    if lo is not None and n < lo:
        return default
    if hi is not None and n > hi:
        return hi
    return n


def parse_ports(raw: str) -> list[int]:
    ports: list[int] = []
    for tok in re.split(r"[,\s]+", raw or ""):
        if not tok:
            continue
        if tok.isdigit() and 1 <= int(tok) <= 65535:
            if int(tok) not in ports:
                ports.append(int(tok))
        else:
            log(f"::warning::忽略无效端口 {tok}")
    return ports or list(DEFAULT_PORTS)


def norm_key(ip, port) -> tuple[str, str]:
    """(IP, 端口) 的规范化唯一键：IPv6 写法统一、端口去前导零，保证 IP:端口 不会因写法不同而重复"""
    ip = str(ip).strip().strip("[]")
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        pass
    port = str(port).strip()
    try:
        port = str(int(port))
    except ValueError:
        pass
    return ip, port


def atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def load_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def on_signal(signum, _frame) -> None:
    global STOP
    STOP = True
    log(f"收到信号 {signum}：完成当前步骤、保存进度后退出")


# ───────────────────────── 网段 → IP ─────────────────────────

def load_networks(path: Path, min_v6_prefix: int):
    v4, v6 = [], []
    bad = skipped_v6 = 0
    with open(path, "r", encoding="utf-8-sig", errors="ignore") as f:
        for raw in f:
            line = raw.split("#", 1)[0].strip()
            for tok in re.split(r"[,\s]+", line):
                if not tok:
                    continue
                m = TOKEN_V4_PORT.match(tok) or TOKEN_V6_BRACKET.match(tok)
                if m:  # 兼容误带端口的写法：1.2.3.0/24:443、[2001:db8::/64]:443
                    tok = m.group(1)
                try:
                    net = ipaddress.ip_network(tok, strict=False)
                except ValueError:
                    bad += 1
                    if bad <= 20:
                        log(f"::warning::跳过无效网段 -> {tok}")
                    continue
                if net.version == 4:
                    v4.append(net)
                elif net.prefixlen < min_v6_prefix:
                    skipped_v6 += 1
                    if skipped_v6 <= 20:
                        log(f"::warning::IPv6 网段 {net} 前缀小于 /{min_v6_prefix}，无法全部展开，已跳过")
                else:
                    v6.append(net)
    # collapse：去重并合并重叠/相邻网段，结果按地址排序（顺序固定，断点才可靠）
    nets = list(ipaddress.collapse_addresses(v4)) + list(ipaddress.collapse_addresses(v6))
    return nets, bad, skipped_v6


def iter_ips(nets, sizes, start: int):
    """从展开序列的第 start 个 IP 开始，惰性产出 IP 字符串"""
    skip = start
    for net, size in zip(nets, sizes):
        if skip >= size:
            skip -= size
            continue
        base = int(net.network_address)
        cls = ipaddress.IPv4Address if net.version == 4 else ipaddress.IPv6Address
        for off in range(skip, size):
            yield str(cls(base + off))
        skip = 0


# ───────────────────────── 扫描（TCP 开放 + 延迟）─────────────────────────

async def tcp_probe(ip: str, port: int, timeout: float):
    t0 = time.perf_counter()
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
    except Exception:
        return None
    ms = (time.perf_counter() - t0) * 1000
    try:
        writer.transport.abort()
    except Exception:
        pass
    return ms


async def scan_batch(ips, ports, timeout, concurrency, samples, measure_conc, lo, hi):
    """第一阶段：高并发找开放端口；第二阶段：低并发多次采样，得到可信延迟并按范围过滤"""
    sem = asyncio.Semaphore(concurrency)
    opened: list[tuple[str, int]] = []

    async def first(ip, port):
        async with sem:
            if await tcp_probe(ip, port, timeout) is not None:
                opened.append((ip, port))

    await asyncio.gather(*(first(ip, p) for ip in ips for p in ports))
    if not opened:
        return 0, []

    need = (samples + 1) // 2  # 采样成功次数不足一半视为不稳定
    msem = asyncio.Semaphore(measure_conc)
    good: list[tuple[str, int, float]] = []

    async def measure(ip, port):
        async with msem:
            vals = []
            for _ in range(samples):
                v = await tcp_probe(ip, port, timeout)
                if v is not None:
                    vals.append(v)
        if len(vals) >= need:
            avg = statistics.fmean(vals)
            if lo <= avg <= hi:
                good.append((ip, port, round(avg, 1)))

    await asyncio.gather(*(measure(ip, p) for ip, p in opened))
    return len(opened), good


# ───────────────────────── verify.py 对接 ─────────────────────────

def prepare_verify_script(script: Path) -> Path:
    script = script.resolve()
    if not script.is_file():
        raise Abort(f"未找到 verify.py：{script}")
    chk = subprocess.run(
        [sys.executable, "-c", "import lib.utils, lib.scanner_utils"],
        cwd=script.parent, capture_output=True, text=True,
    )
    if chk.returncode == 0:
        return script
    shim = Path(tempfile.mkdtemp(prefix="cf_verify_"))
    (shim / "lib").mkdir()
    (shim / "lib" / "__init__.py").write_text("", encoding="utf-8")
    (shim / "lib" / "utils.py").write_text(SHIM_UTILS, encoding="utf-8")
    (shim / "lib" / "scanner_utils.py").write_text(SHIM_SCANNER, encoding="utf-8")
    shutil.copy(script, shim / script.name)
    log("::notice::仓库中缺少 lib.utils / lib.scanner_utils，已在临时目录使用最小兼容版（不影响仓库文件）")
    return shim / script.name


def verify_selftest(script: Path, timeout: float = 60.0) -> tuple[bool, str]:
    """调用 verify.py --self-test：探测自有域名当前解析到的 CF 边缘 IP。
    通过说明 域名已开橙云 / trace 可访问 / 证书与校验链路正常；返回 (是否通过, 最后一行输出)"""
    try:
        p = subprocess.run([sys.executable, str(script), "--self-test"],
                           capture_output=True, text=True, timeout=timeout, cwd=script.parent)
    except subprocess.TimeoutExpired:
        return False, "自检超时"
    lines = (p.stdout + "\n" + p.stderr).strip().splitlines()
    return p.returncode == 0, (lines[-1] if lines else "无输出")


def parse_verify_output(path: Path, lat_map: dict) -> list[dict]:
    """verify.py 输出：ip,port,TRUE,colo,country,region,api_latency,,ASxxx,proto"""
    rows = []
    stamp = now_iso()
    seen: set[tuple[str, str]] = set()
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        p = line.strip().split(",")
        if len(p) < 10:
            continue
        try:
            ipaddress.ip_address(p[0])
        except ValueError:
            continue  # 表头等非数据行
        key = norm_key(p[0], p[1])
        if key in seen:
            continue  # 同一批里重复的 IP:端口 只取一条
        tcp = lat_map.get(key)
        if tcp is None:
            continue
        seen.add(key)
        ip, port = key
        rows.append({
            "IP": ip, "Port": port, "IP_Port": f"{ip}:{port}",
            "TCP_Latency_ms": tcp, "API_Latency_ms": p[-4],
            "Colo": p[3], "Country": p[4], "Region": ",".join(p[5:-4]),
            "ASN": p[-2], "Protocol": p[-1], "Verified_At": stamp,
        })
    return rows


# ───────────────────────── git 增量提交 ─────────────────────────

def git(*args):
    return subprocess.run(["git", *args], capture_output=True, text=True)


def git_checkpoint(out_dir: str, reason: str) -> None:
    if not shutil.which("git") or git("rev-parse", "--is-inside-work-tree").returncode != 0:
        return
    git("add", "--", out_dir)
    if git("diff", "--staged", "--quiet").returncode == 0:
        return
    c = git("commit", "-m", f"chore: checkpoint ({reason}) {now_iso()} UTC")
    if c.returncode != 0:
        log(f"::warning::git commit 失败：{c.stderr.strip()[-200:]}")
        return
    for _ in range(3):
        if git("push").returncode == 0:
            log("断点已推送到仓库")
            return
        git("pull", "--rebase", "--autostash")
    log("::warning::git push 多次失败，进度仅保存在本次运行的工作区，稍后由收尾步骤再试")


# ───────────────────────── 主流程 ─────────────────────────

class Runner:
    def __init__(self, a):
        self.a = a
        self.t0 = time.monotonic()
        self.soft_deadline = self.t0 + max(0.0, min(a.budget_min, a.job_limit_min - 10)) * 60
        self.hard_deadline = self.t0 + max(1.0, a.job_limit_min - 4) * 60
        self.out_dir = Path(a.out_dir)
        self.state_dir = self.out_dir / "state"
        self.progress_path = self.state_dir / "progress.json"
        self.pending_path = self.state_dir / "pending_verify.txt"
        self.csv_path = self.out_dir / "cf_verified.csv"
        self.best_ip_ports_path = self.out_dir / "best_ip_ports.txt"
        self.best_ips_path = self.out_dir / "best_ips.txt"
        self.prog: dict = {}
        self.pending: dict[tuple[str, str], str] = {}
        self.results: dict[tuple[str, str], dict] = {}
        self.verify_script: Path | None = None
        self.fail_streak = 0
        self.last_log = 0.0
        self.last_commit = time.monotonic()
        # 本次运行统计
        self.run_scanned = self.run_open = self.run_inrange = self.run_verified = 0
        self.total = 0
        # 端口接力
        self.port: int | None = None        # 本次运行扫描的端口
        self.port_finished = False           # 本次运行是否把该端口扫完了
        self.all_done = False                # 端口队列是否全部扫完
        self.stop_chain = False              # 通知 workflow：不要再自动接力

    # ---- 状态读写 ----
    def load_results(self) -> None:
        if not self.csv_path.exists():
            return
        with open(self.csv_path, "r", encoding="utf-8", newline="") as f:
            for row in csv.DictReader(f):
                try:
                    float(row["TCP_Latency_ms"])
                    key = norm_key(row["IP"], row["Port"])
                except (KeyError, TypeError, ValueError):
                    continue
                old = self.results.get(key)
                # 历史文件里若已有重复的 IP:端口，保留验证时间最新的一条
                if old is not None and (old.get("Verified_At") or "") > (row.get("Verified_At") or ""):
                    continue
                row["IP"], row["Port"] = key
                row["IP_Port"] = f"{key[0]}:{key[1]}"
                self.results[key] = row

    def load_pending(self) -> None:
        if not self.pending_path.exists():
            return
        for line in self.pending_path.read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) >= 2 and ":" in parts[0]:
                ip, port = parts[0].rsplit(":", 1)
                self.pending[norm_key(ip, port)] = parts[1]

    def save_pending(self) -> None:
        text = "".join(f"{ip}:{port}\t{lat}\n" for (ip, port), lat in self.pending.items())
        atomic_write(self.pending_path, text)

    def save_progress(self) -> None:
        self.prog["updated"] = now_iso()
        atomic_write(self.progress_path, json.dumps(self.prog, ensure_ascii=False, indent=2) + "\n")

    def write_outputs(self) -> None:
        rows = sorted(self.results.values(), key=lambda r: (float(r["TCP_Latency_ms"]), r["IP"], str(r["Port"])))
        # 最后一道保险：按 (IP, 端口) 去重，保证输出里没有重复的 IP:端口
        seen: set[tuple[str, str]] = set()
        uniq = []
        for r in rows:
            k = norm_key(r["IP"], r["Port"])
            if k in seen:
                continue
            seen.add(k)
            uniq.append(r)
        rows = uniq

        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=RESULT_COLUMNS, extrasaction="ignore", lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
        atomic_write(self.csv_path, buf.getvalue())

        ip_ports, best_ip = [], {}
        for r in rows:
            ip, port, lat = r["IP"], r["Port"], float(r["TCP_Latency_ms"])
            host = f"[{ip}]" if ":" in ip else ip
            ip_ports.append(f"{host}:{port}#{lat:.1f}ms")
            best_ip.setdefault(ip, lat)  # 已按延迟升序，第一次出现即该 IP 的最低延迟
        atomic_write(self.best_ip_ports_path, "".join(x + "\n" for x in ip_ports))
        atomic_write(self.best_ips_path, "".join(f"{ip}#{lat:.1f}ms\n" for ip, lat in best_ip.items()))

    # ---- 验证 ----
    def run_verify(self, items, timeout: float):
        lat_map = {k: v for k, v in items}
        rows: list[dict] = []
        ok = True
        with tempfile.TemporaryDirectory(prefix="cf_chunk_") as td:
            inp, out = Path(td) / "in.txt", Path(td) / "out.csv"
            inp.write_text("".join(f"{ip}:{port}\t{l}\n" for (ip, port), l in items), encoding="utf-8")
            cmd = [
                sys.executable, str(self.verify_script),
                "--input", str(inp), "--output", str(out),
                "--concurrent", str(self.a.verify_concurrent),
                "--chunk", str(max(len(items), 1)),
            ]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                                      cwd=self.verify_script.parent)
                if proc.returncode != 0:
                    ok = False
                    log(f"::warning::verify.py 退出码 {proc.returncode}：{(proc.stderr or proc.stdout).strip()[-300:]}")
                elif proc.stderr.strip():
                    log("    " + proc.stderr.strip().splitlines()[-1])
            except subprocess.TimeoutExpired:
                ok = False
                log(f"::warning::verify.py 运行超过 {int(timeout)}s 被终止，本组保留在待验证队列")
            if out.exists():
                rows = parse_verify_output(out, lat_map)
        return rows, ok

    def drain_pending(self) -> None:
        a = self.a
        while self.pending and not STOP:
            remaining = self.hard_deadline - time.monotonic()
            if remaining < 45:
                log(f"验证时间窗口用尽，待验证队列剩余 {len(self.pending)} 条，留待下次运行")
                return
            keys = list(self.pending)[: a.verify_chunk]
            items = [(k, self.pending[k]) for k in keys]
            t = time.monotonic()
            rows, ok = self.run_verify(items, min(a.verify_timeout, remaining - 15))
            for r in rows:
                self.results[norm_key(r["IP"], r["Port"])] = r  # 同 IP:端口 以最新为准，天然去重
            if rows:
                self.write_outputs()
            if ok:
                self.fail_streak = 0
                for k in keys:
                    self.pending.pop(k, None)
                self.save_pending()
                self.run_verified += len(rows)
                stats = self.prog.setdefault("stats", {})
                stats["verified"] = stats.get("verified", 0) + len(rows)
                self.save_progress()
                log(f"  [验证] {len(items)} 个 IP:端口 → 通过 {len(rows)} | 用时 {time.monotonic() - t:.0f}s | "
                    f"队列剩余 {len(self.pending)} | 累计优选 {len(self.results)}")
                if not rows and len(items) >= 30 and not verify_selftest(self.verify_script)[0]:
                    # 整组 0 通过且自检失败：别把这组当成"不合格"丢掉
                    self.pending.update({k: v for k, v in items})
                    self.save_pending()
                    raise Abort("验证链路自检失败（整组 0 通过），已保留待验证队列；请检查 CF_VERIFY_SNI 域名是否仍是橙云且 /cdn-cgi/trace 可访问",
                                fatal=False)
            else:
                self.fail_streak += 1
                self.save_progress()
                if self.fail_streak >= 3:
                    raise Abort("verify.py 连续 3 次失败，已保存进度并停止", fatal=False)
                return

    # ---- 端口队列 ----
    def pick_port(self) -> tuple[int, list[int]]:
        """决定本次运行扫哪个端口：队列中第一个尚未完成的端口；必要时开始新一轮"""
        prog, ports = self.prog, self.a.ports
        prog["done_ports"] = [p for p in prog.get("done_ports", []) if p in ports]
        todo = [p for p in ports if p not in prog["done_ports"]]

        # 上次该端口已扫完但没来得及标记（例如收尾验证中途出错）：补记并换下一个
        if todo and prog.get("port") == todo[0] and prog.get("cursor", 0) >= self.total:
            prog["done_ports"].append(todo[0])
            todo = todo[1:]

        if not todo:
            prog.update(round=prog.get("round", 1) + 1, cursor=0, stats={}, done_ports=[],
                        port=None, round_started=now_iso())
            log(f"端口队列已全部扫完，开始第 {prog['round']} 轮")
            todo = list(ports)

        cur = todo[0]
        if "port" not in prog:        # 兼容旧版断点（没有端口字段）：沿用其 cursor，视为当前端口
            prog["port"] = cur
        if prog["port"] != cur:       # 换端口：该端口从第一个 IP 重新开始
            prog.update(port=cur, cursor=0, stats={})
        return cur, todo

    # ---- 日志 ----
    def maybe_log(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self.last_log < 20:
            return
        self.last_log = now
        cur = self.prog["cursor"]
        log(f"[进度] 端口 {self.port} {cur:,}/{self.total:,} ({cur / self.total * 100:.2f}%) 第{self.prog['round']}轮 | "
            f"本次已扫 {self.run_scanned:,} 开放 {self.run_open:,} 延迟达标 {self.run_inrange:,} "
            f"验证通过 {self.run_verified:,} | 队列 {len(self.pending)} | 用时 {(now - self.t0) / 60:.1f}min")

    def maybe_commit(self, reason: str, force: bool = False) -> None:
        if self.a.commit_every_min <= 0:
            return
        if force or time.monotonic() - self.last_commit >= self.a.commit_every_min * 60:
            git_checkpoint(self.a.out_dir, reason)
            self.last_commit = time.monotonic()

    # ---- 主循环 ----
    def run(self) -> None:
        a = self.a
        self.state_dir.mkdir(parents=True, exist_ok=True)
        if a.reset_state:
            log("reset_state=true：清空断点与待验证队列")
            for p in (self.progress_path, self.pending_path):
                p.unlink(missing_ok=True)
        if a.clear_results:
            log("clear_results=true：清空历史优选结果")
            for p in (self.csv_path, self.best_ip_ports_path, self.best_ips_path):
                p.unlink(missing_ok=True)

        src = Path(a.source)
        if not src.is_file():
            raise Abort(f"仓库根目录未找到 {a.source}")
        nets, bad, skipped_v6 = load_networks(src, a.min_v6_prefix)
        if not nets:
            raise Abort(f"{a.source} 中没有有效网段")
        sizes = [n.num_addresses for n in nets]
        self.total = sum(sizes)
        fp = hashlib.sha1("\n".join(str(n) for n in nets).encode()).hexdigest()

        # 断点
        prog = load_json(self.progress_path, {})
        if prog and prog.get("fingerprint") != fp:
            log(f"::warning::{a.source} 的网段内容与上次不同，旧断点作废，从头开始新一轮（历史结果保留）")
            prog = {"round": prog.get("round", 1) + 1}
        if "cursor" not in prog or prog.get("fingerprint") != fp:
            prog = {"round": prog.get("round", 1), "cursor": 0, "done_ports": [], "stats": {}}
        prog.update(fingerprint=fp, total=self.total)
        prog.setdefault("round_started", now_iso())
        self.prog = prog

        port, _todo = self.pick_port()
        self.port = port

        self.load_results()
        self.load_pending()

        # 提高文件描述符上限，并据此限制并发
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        want = 65536 if hard == resource.RLIM_INFINITY else min(hard, 65536)
        if soft < want:
            try:
                resource.setrlimit(resource.RLIMIT_NOFILE, (want, hard))
                soft = want
            except (ValueError, OSError):
                pass
        conc = max(50, min(a.concurrency, soft - 200))

        if not env_str("CF_VERIFY_SNI"):
            raise Abort("未设置 CF_VERIFY_SNI（托管在 Cloudflare 上的自有域名），无法进行直连验证")
        self.verify_script = prepare_verify_script(Path(a.verify_script))
        ok, info = verify_selftest(self.verify_script)
        if not ok:
            raise Abort(f"verify.py {info}")
        log(f"verify.py {info}")

        log(f"网段 {len(nets)} 个（去重合并后），共 {self.total:,} 个 IP；无效 {bad}、跳过超大 IPv6 {skipped_v6}")
        log(f"第 {prog['round']} 轮 | 当前端口 {port}（队列第 {a.ports.index(port) + 1}/{len(a.ports)} 个，"
            f"本轮已完成 {len(prog['done_ports'])} 个）| 断点 cursor={prog['cursor']:,} | "
            f"延迟 {a.min_latency}~{a.max_latency}ms | 批 {a.batch_size} | 并发 {conc} | 超时 {a.timeout_ms}ms")
        log(f"已有优选 {len(self.results)} 条 | 待验证队列 {len(self.pending)} 条 | "
            f"扫描预算 {(self.soft_deadline - self.t0) / 60:.1f}min")

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        timeout = max(a.timeout_ms, a.max_latency + 200) / 1000.0
        gen = iter_ips(nets, sizes, prog["cursor"])

        try:
            self.drain_pending()  # 上次遗留的先验证
            while not STOP and time.monotonic() < self.soft_deadline and prog["cursor"] < self.total:
                batch = list(itertools.islice(gen, a.batch_size))
                if not batch:
                    break
                n_open, good = loop.run_until_complete(scan_batch(
                    batch, [port], timeout, conc, a.samples, 100, a.min_latency, a.max_latency))
                for ip, p, lat in good:
                    self.pending[norm_key(ip, p)] = f"{lat}"
                prog["cursor"] += len(batch)
                st = prog.setdefault("stats", {})
                st["open"] = st.get("open", 0) + n_open
                st["in_range"] = st.get("in_range", 0) + len(good)
                self.run_scanned += len(batch)
                self.run_open += n_open
                self.run_inrange += len(good)
                self.save_pending()   # 先存队列，再存 cursor；中途崩溃只会重复扫描，不会丢
                self.save_progress()
                if good:
                    self.drain_pending()  # 扫到即验
                self.maybe_log()
                self.maybe_commit(f"port {port} cursor {prog['cursor']}/{self.total}")
            self.drain_pending()  # 收尾：把队列里剩下的在宽限期内验完

            # 该端口的全部 IP 都扫完了：标记完成，本次运行到此结束；下次运行自动换下一个端口
            if prog["cursor"] >= self.total and not STOP:
                self.port_finished = True
                if port not in prog["done_ports"]:
                    prog["done_ports"].append(port)
                self.all_done = all(p in prog["done_ports"] for p in a.ports)
                self.stop_chain = self.all_done and not a.loop_forever
        finally:
            loop.close()
            self.save_pending()
            self.save_progress()
            self.write_outputs()

        self.maybe_log(force=True)
        if self.port_finished:
            nxt = next((p for p in a.ports if p not in prog["done_ports"]), None)
            if self.all_done:
                log(f"端口 {port} 已扫描完成，端口队列全部扫完" +
                    ("，不再自动接力" if self.stop_chain else "，下次运行开始新一轮"))
            else:
                log(f"端口 {port} 已扫描完成，下次运行将扫描端口 {nxt}")
        else:
            log(f"已到时间预算，端口 {port} 尚未扫完，下次运行将从断点继续")

    # ---- 摘要 / 输出 ----
    def write_summary(self) -> None:
        path = os.environ.get("GITHUB_STEP_SUMMARY")
        if not path or not self.prog:
            return
        cur, tot = self.prog.get("cursor", 0), max(self.total, 1)
        done_ports = self.prog.get("done_ports", [])
        top = sorted(self.results.values(), key=lambda r: float(r["TCP_Latency_ms"]))[:10]
        lines = [
            "### CF IP 优选运行摘要", "",
            f"- 第 {self.prog.get('round', 1)} 轮 · 端口 **{self.port}**"
            f"（{'已扫完' if self.port_finished else '未扫完，下次继续'}）：**{cur:,} / {self.total:,}**（{cur / tot * 100:.2f}%）",
            f"- 本轮已完成端口 {len(done_ports)}/{len(self.a.ports)}：{','.join(map(str, done_ports)) or '（无）'}",
            f"- 本次扫描 {self.run_scanned:,} 个 IP，开放 {self.run_open:,}，延迟达标 {self.run_inrange:,}，验证通过 {self.run_verified:,}",
            f"- 待验证队列 {len(self.pending)} 条；累计优选 {len(self.results)} 条（IP:端口 唯一）",
            f"- 自动接力：{'已停止' if self.stop_chain else f'{self.a.wait_note}后触发下一次运行'}", "",
        ]
        if top:
            lines += ["| IP:端口 | TCP 延迟 | 机房 | 国家 |", "|---|---|---|---|"]
            lines += [f"| {r['IP_Port']} | {float(r['TCP_Latency_ms']):.1f} ms | {r['Colo']} | {r['Country']} |" for r in top]
        with open(path, "a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

    def export_outputs(self) -> None:
        """把 stop / port 写入 $GITHUB_OUTPUT，供 workflow 判断是否继续自动接力"""
        path = os.environ.get("GITHUB_OUTPUT")
        if not path:
            return
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"stop={'true' if self.stop_chain else 'false'}\n")
            f.write(f"port={self.port or ''}\n")


def parse_args():
    p = argparse.ArgumentParser(description="Cloudflare 反代 IP 优选：按端口队列接力 + 断点续跑 + 直连精筛")
    p.add_argument("--source", default=env_str("CF_SOURCE", "来源-1.txt"))
    p.add_argument("--ports", default=env_str("CF_PORTS", ",".join(map(str, DEFAULT_PORTS))),
                   help="端口队列（逗号分隔），每次运行只扫第一个未完成的端口")
    p.add_argument("--min-latency", default=env_str("CF_MIN_LATENCY_MS", "25"))
    p.add_argument("--max-latency", default=env_str("CF_MAX_LATENCY_MS", "350"))
    p.add_argument("--budget-min", default=env_str("CF_TIME_BUDGET_MIN", "50"))
    p.add_argument("--job-limit-min", default=env_str("CF_JOB_LIMIT_MIN", "60"))
    p.add_argument("--batch-size", default=env_str("CF_BATCH_SIZE", "2000"))
    p.add_argument("--concurrency", default=env_str("CF_SCAN_CONCURRENCY", "1500"))
    p.add_argument("--timeout-ms", default=env_str("CF_SCAN_TIMEOUT_MS", "1000"))
    p.add_argument("--samples", default=env_str("CF_SAMPLES", "3"))
    p.add_argument("--verify-script", default=env_str("CF_VERIFY_SCRIPT", "verify.py"))
    p.add_argument("--verify-concurrent", default=env_str("CF_VERIFY_CONCURRENT", "64"))
    p.add_argument("--verify-chunk", default=env_str("CF_VERIFY_CHUNK", "300"))
    p.add_argument("--verify-timeout", default=env_str("CF_VERIFY_TIMEOUT", "900"))
    p.add_argument("--min-v6-prefix", default=env_str("CF_MIN_V6_PREFIX", "112"))
    p.add_argument("--commit-every-min", default=env_str("CF_COMMIT_EVERY_MIN", "10"))
    p.add_argument("--out-dir", default=env_str("CF_OUT_DIR", "output"))
    p.add_argument("--wait-min", default=env_str("CF_NEXT_RUN_WAIT_MIN", "10"))
    p.add_argument("--loop-forever", action="store_true", default=env_str("CF_LOOP_FOREVER", "false").lower() == "true",
                   help="所有端口扫完后自动开始新一轮（默认扫完即停止自动接力）")
    p.add_argument("--reset-state", action="store_true", default=env_str("CF_RESET_STATE", "false").lower() == "true")
    p.add_argument("--clear-results", action="store_true", default=env_str("CF_CLEAR_RESULTS", "false").lower() == "true")
    r = p.parse_args()

    a = argparse.Namespace()
    a.source, a.verify_script, a.out_dir = r.source, r.verify_script, r.out_dir
    a.ports = parse_ports(r.ports)
    a.min_latency = to_num(r.min_latency, 25.0, float, lo=0)
    a.max_latency = to_num(r.max_latency, 350.0, float, lo=1)
    if a.min_latency > a.max_latency:
        log("::warning::最小延迟大于最大延迟，已交换")
        a.min_latency, a.max_latency = a.max_latency, a.min_latency
    a.budget_min = to_num(r.budget_min, 50.0, float, lo=0.001)
    a.job_limit_min = to_num(r.job_limit_min, 60.0, float, lo=15)
    a.batch_size = to_num(r.batch_size, 2000, int, lo=1)
    a.concurrency = to_num(r.concurrency, 1500, int, lo=1)
    a.timeout_ms = to_num(r.timeout_ms, 1000, int, lo=50)
    a.samples = to_num(r.samples, 3, int, lo=1, hi=10)
    a.verify_concurrent = to_num(r.verify_concurrent, 64, int, lo=1)
    a.verify_chunk = to_num(r.verify_chunk, 300, int, lo=1)
    a.verify_timeout = to_num(r.verify_timeout, 900, int, lo=30)
    a.min_v6_prefix = to_num(r.min_v6_prefix, 112, int, lo=1, hi=128)
    a.commit_every_min = to_num(r.commit_every_min, 10.0, float, lo=0)
    a.wait_note = f"等待 {to_num(r.wait_min, 10, int, lo=0)} 分钟"
    a.loop_forever = r.loop_forever
    a.reset_state, a.clear_results = r.reset_state, r.clear_results
    return a


def main() -> int:
    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    a = parse_args()
    runner = Runner(a)
    code = 0
    try:
        runner.run()
    except Abort as e:
        log(f"::error::{e}")
        code = 1
        if e.fatal:  # 配置类错误：继续接力只会反复失败，通知 workflow 停止
            runner.stop_chain = True
    except Exception:  # 未预期的程序错误：同样停止接力，避免无限循环
        traceback.print_exc()
        code = 1
        runner.stop_chain = True
    finally:
        runner.write_summary()
        runner.export_outputs()
    return code


if __name__ == "__main__":
    sys.exit(main())
