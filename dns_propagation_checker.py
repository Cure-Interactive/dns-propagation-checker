#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import ipaddress
import json
import os
import queue
import threading
import time
import tkinter as tk
from dataclasses import dataclass
from tkinter import messagebox, ttk
from typing import Any, Sequence

import customtkinter as ctk
import dns.exception
import dns.name
import dns.resolver

try:
  from CTkToolTip import CTkToolTip  # type: ignore
except Exception:
  CTkToolTip = None  # type: ignore

APP_TITLE = "DNS Propagation Checker - Cure Interactive"
DIR_SCRIPT = os.path.abspath(os.path.dirname(__file__))
PATH_CONFIG = os.path.join(DIR_SCRIPT, "config.json")
COMMON = ("1.1.1.1", "8.8.8.8", "9.9.9.9")
DEFAULT = {
  "window": {"width": 1450, "height": 880},
  "appearance_mode": "System",
  "color_theme": "blue",
  "hostnames": "example.com\nwww.example.com",
  "types": {"A": True, "AAAA": True, "CNAME": True, "NS": True, "MX": True},
  "use_system": True,
  "use_common": True,
  "custom_resolvers": "",
  "authoritative": True,
  "expand_cname": True,
  "poll_seconds": 0.0,
  "poll_count": 0,
  "timeout": 2.0,
  "lifetime": 4.0,
  "clear_each_cycle": False,
}


@dataclass(frozen=True)
class ResolverSpec:
  label: str
  nameservers: Sequence[str] | None


@dataclass
class Row:
  t: str
  host: str
  typ: str
  val: str
  ttl: int | None
  resolver: str
  status: str
  detail: str = ""


@dataclass
class RunCfg:
  hosts: list[str]
  qtypes: list[str]
  resolvers: list[ResolverSpec]
  auth: bool
  expand_cname: bool
  poll_seconds: float
  poll_count: int
  timeout: float
  lifetime: float
  clear_each_cycle: bool


def tooltip(*widgets: Any, text: str) -> None:
  if CTkToolTip is None:
    return
  for w in widgets:
    if w is None:
      continue
    try:
      old = getattr(w, "_cure_tooltip", None)
      if old is not None and hasattr(old, "destroy"):
        old.destroy()
    except Exception:
      pass
    try:
      w._cure_tooltip = CTkToolTip(w, message=text)  # type: ignore[attr-defined]
    except Exception:
      pass


def _read_json(path: str) -> dict:
  try:
    if not os.path.isfile(path):
      return {}
    with open(path, "r", encoding="utf-8") as f:
      d = json.load(f)
    return d if isinstance(d, dict) else {}
  except Exception:
    return {}


def _write_json(path: str, data: dict) -> None:
  tmp = path + ".tmp"
  with open(tmp, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)
  os.replace(tmp, path)


def load_cfg(path: str) -> dict:
  d = json.loads(json.dumps(DEFAULT))
  x = _read_json(path)
  if isinstance(x, dict):
    d.update(x)
    if isinstance(x.get("window"), dict):
      d["window"].update(x["window"])
    if isinstance(x.get("types"), dict):
      d["types"].update(x["types"])
  _write_json(path, d)
  return d


def ttl_human(v: int | None) -> str:
  if v is None:
    return "-"
  s = max(0, int(v))
  d, s = divmod(s, 86400)
  h, s = divmod(s, 3600)
  m, s = divmod(s, 60)
  return f"{d}d {h}h {m}m {s}s"


def mk_resolver(spec: ResolverSpec, timeout: float, lifetime: float) -> dns.resolver.Resolver:
  r = dns.resolver.Resolver(configure=(spec.nameservers is None))
  if spec.nameservers is not None:
    r.nameservers = list(spec.nameservers)
  r.timeout = timeout
  r.lifetime = lifetime
  return r


def fmt_rdata(rdata: dns.rdata.Rdata, typ: str) -> str:
  if typ == "MX":
    return f"{rdata.preference} {str(rdata.exchange).rstrip('.')}"
  if typ == "CNAME":
    return str(rdata.target).rstrip(".")
  if typ == "NS":
    return str(rdata).rstrip(".")
  return str(rdata)


def resolve_once(host: str, typ: str, spec: ResolverSpec, timeout: float, lifetime: float) -> list[Row]:
  t = dt.datetime.now().strftime("%H:%M:%S")
  rr = mk_resolver(spec, timeout, lifetime)
  try:
    ans = rr.resolve(host, typ, search=False, raise_on_no_answer=False)
  except dns.resolver.NXDOMAIN:
    return [Row(t, host, typ, "-", None, spec.label, "NXDOMAIN")]
  except dns.resolver.NoNameservers:
    return [Row(t, host, typ, "-", None, spec.label, "SERVFAIL", "No nameservers")]
  except dns.resolver.LifetimeTimeout:
    return [Row(t, host, typ, "-", None, spec.label, "TIMEOUT")]
  except dns.exception.DNSException as e:
    return [Row(t, host, typ, "-", None, spec.label, "ERROR", str(e))]
  if ans.rrset is None:
    return [Row(t, host, typ, "-", None, spec.label, "NO_RECORD")]
  ttl = int(ans.rrset.ttl)
  return [Row(t, host, typ, fmt_rdata(x, typ), ttl, spec.label, "OK") for x in ans]


def zone_cut(host: str, b: dns.resolver.Resolver) -> str | None:
  labs = dns.name.from_text(host).labels
  for i in range(0, len(labs) - 1):
    c = dns.name.Name(labs[i:]).to_text(omit_final_dot=True)
    try:
      b.resolve(c, "SOA", search=False)
      return c
    except dns.exception.DNSException:
      continue
  return None


def auth_specs(host: str, timeout: float, lifetime: float) -> list[ResolverSpec]:
  b = dns.resolver.Resolver(configure=True)
  b.timeout = timeout
  b.lifetime = lifetime
  z = zone_cut(host, b)
  if not z:
    return []
  try:
    nss = b.resolve(z, "NS", search=False)
  except dns.exception.DNSException:
    return []
  out: list[ResolverSpec] = []
  for ns in nss:
    n = str(ns.target).rstrip(".")
    ip = ""
    for typ in ("A", "AAAA"):
      try:
        a = b.resolve(n, typ, search=False)
        if a.rrset and len(a) > 0:
          ip = str(a[0])
          break
      except dns.exception.DNSException:
        pass
    if ip:
      out.append(ResolverSpec(f"auth:{n}({ip})", [ip]))
  return out


def expand_cname(rows: list[Row], timeout: float, lifetime: float) -> list[Row]:
  out: list[Row] = []
  seen: set[tuple[str, str]] = set()
  for r in rows:
    if r.status != "OK" or r.typ != "CNAME":
      continue
    k = (r.val, r.resolver)
    if k in seen:
      continue
    seen.add(k)
    if r.resolver == "system-default":
      spec = ResolverSpec("system-default", None)
    elif r.resolver.startswith("auth:"):
      l, u = r.resolver.rfind("("), r.resolver.rfind(")")
      ip = r.resolver[l + 1:u] if l != -1 and u > l else ""
      spec = ResolverSpec(r.resolver, [ip] if ip else None)
    else:
      spec = ResolverSpec(r.resolver, [r.resolver])
    arows = resolve_once(r.val, "A", spec, timeout, lifetime)
    for a in arows:
      a.detail = f"CNAME target of {r.host}"
      out.append(a)
  return out


def diagnostics(rows: list[Row]) -> list[str]:
  out: list[str] = []
  by_key: dict[tuple[str, str], dict[str, set[str]]] = {}
  for r in rows:
    if r.status != "OK":
      continue
    by_key.setdefault((r.host, r.typ), {}).setdefault(r.resolver, set()).add(r.val)
  for (h, t), rv in by_key.items():
    if len({tuple(sorted(v)) for v in rv.values()}) > 1:
      out.append(f"[MISMATCH] {h} {t}: " + ", ".join(f"{k}->{sorted(list(v))}" for k, v in rv.items()))
  cname: dict[str, set[str]] = {}
  a_map: dict[tuple[str, str], set[str]] = {}
  for r in rows:
    if r.status != "OK":
      continue
    if r.typ == "CNAME":
      cname.setdefault(r.host, set()).add(r.val)
    if r.typ == "A":
      a_map.setdefault((r.host, r.resolver), set()).add(r.val)
  for src, tgts in cname.items():
    for tgt in tgts:
      rv: dict[str, set[str]] = {}
      for (h, res), vals in a_map.items():
        if h == tgt:
          rv[res] = vals
      if len({tuple(sorted(v)) for v in rv.values()}) > 1:
        out.append(f"[CNAME->A MISMATCH] {src}->{tgt}: " + ", ".join(f"{k}->{sorted(list(v))}" for k, v in rv.items()))
  auth: dict[tuple[str, str], set[str]] = {}
  pub: dict[tuple[str, str], set[str]] = {}
  for r in rows:
    if r.status != "OK":
      continue
    key = (r.host, r.typ)
    if r.resolver.startswith("auth:"):
      auth.setdefault(key, set()).add(r.val)
    else:
      pub.setdefault(key, set()).add(r.val)
  for key, av in auth.items():
    pv = pub.get(key, set())
    if pv and av != pv:
      out.append(f"[AUTH DIFF] {key[0]} {key[1]} auth={sorted(list(av))} public={sorted(list(pv))}")
  return out or ["No obvious propagation mismatches detected in this sample."]


def run_cycle(cfg: RunCfg, status_cb) -> tuple[list[Row], list[str]]:
  rows: list[Row] = []
  for i, host in enumerate(cfg.hosts, start=1):
    status_cb(f"Resolving {host} ({i}/{len(cfg.hosts)})")
    specs = list(cfg.resolvers)
    if cfg.auth:
      specs.extend(auth_specs(host, cfg.timeout, cfg.lifetime))
    for typ in cfg.qtypes:
      for spec in specs:
        rows.extend(resolve_once(host, typ, spec, cfg.timeout, cfg.lifetime))
  if cfg.expand_cname:
    rows.extend(expand_cname(rows, cfg.timeout, cfg.lifetime))
  return rows, diagnostics(rows)


def worker(cfg: RunCfg, stop: threading.Event, q: queue.Queue[tuple[str, Any]]) -> None:
  n = 0
  while True:
    if stop.is_set():
      break
    n += 1
    q.put(("cycle_start", (n, dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))))
    rows, di = run_cycle(cfg, lambda s: q.put(("status", s)))
    q.put(("cycle", (n, rows, di, cfg.clear_each_cycle)))
    if cfg.poll_seconds <= 0:
      break
    if cfg.poll_count > 0 and n >= cfg.poll_count:
      break
    t0 = time.time()
    while True:
      if stop.is_set():
        break
      rem = cfg.poll_seconds - (time.time() - t0)
      if rem <= 0:
        break
      q.put(("status", f"Waiting {rem:0.1f}s before next cycle..."))
      time.sleep(min(rem, 0.25))
    if stop.is_set():
      break
  q.put(("done", None))


class App(ctk.CTk):
  def __init__(self) -> None:
    self.cfg = load_cfg(PATH_CONFIG)
    ctk.set_appearance_mode(str(self.cfg.get("appearance_mode", "System")))
    ctk.set_default_color_theme(str(self.cfg.get("color_theme", "blue")))
    super().__init__()
    self.title(APP_TITLE)
    self.geometry(f"{int(self.cfg['window']['width'])}x{int(self.cfg['window']['height'])}")
    self.minsize(1100, 680)
    self.q: queue.Queue[tuple[str, Any]] = queue.Queue()
    self.stop_event: threading.Event | None = None
    self.th: threading.Thread | None = None
    self.running = False
    self.v_status = tk.StringVar(value="Idle")
    self.v = {k: tk.BooleanVar(value=bool(self.cfg["types"].get(k, True))) for k in ("A", "AAAA", "CNAME", "NS", "MX")}
    self.v_system = tk.BooleanVar(value=bool(self.cfg.get("use_system", True)))
    self.v_common = tk.BooleanVar(value=bool(self.cfg.get("use_common", True)))
    self.v_auth = tk.BooleanVar(value=bool(self.cfg.get("authoritative", True)))
    self.v_expand = tk.BooleanVar(value=bool(self.cfg.get("expand_cname", True)))
    self.v_clear = tk.BooleanVar(value=bool(self.cfg.get("clear_each_cycle", False)))
    self.v_poll = tk.StringVar(value=str(self.cfg.get("poll_seconds", 0.0)))
    self.v_count = tk.StringVar(value=str(self.cfg.get("poll_count", 0)))
    self.v_timeout = tk.StringVar(value=str(self.cfg.get("timeout", 2.0)))
    self.v_life = tk.StringVar(value=str(self.cfg.get("lifetime", 4.0)))
    self._ui()
    self._tips()
    self._splash()
    self.protocol("WM_DELETE_WINDOW", self._close)
    self.after(120, self._poll)

  def _ui(self) -> None:
    self.grid_columnconfigure(0, weight=0); self.grid_columnconfigure(1, weight=1); self.grid_rowconfigure(0, weight=1)
    L = ctk.CTkFrame(self); R = ctk.CTkFrame(self)
    L.grid(row=0, column=0, sticky="ns", padx=(12, 8), pady=12); R.grid(row=0, column=1, sticky="nsew", padx=(8, 12), pady=12)
    L.grid_columnconfigure(0, weight=1); R.grid_columnconfigure(0, weight=1); R.grid_rowconfigure(1, weight=1)
    ctk.CTkLabel(L, text="Hostnames (one per line)", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, sticky="w", padx=10, pady=(10, 4))
    self.t_hosts = ctk.CTkTextbox(L, width=380, height=150); self.t_hosts.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 8))
    self.t_hosts.insert("1.0", str(self.cfg.get("hostnames", "")))
    tf = ctk.CTkFrame(L); tf.grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 8))
    for i, k in enumerate(("A", "AAAA", "CNAME", "NS", "MX")):
      ctk.CTkCheckBox(tf, text=k, variable=self.v[k]).grid(row=0, column=i, padx=8, pady=8, sticky="w")
    rf = ctk.CTkFrame(L); rf.grid(row=3, column=0, sticky="ew", padx=10, pady=(0, 8)); rf.grid_columnconfigure(0, weight=1)
    self.cb_system = ctk.CTkCheckBox(rf, text="Use system resolver", variable=self.v_system); self.cb_system.grid(row=0, column=0, sticky="w", padx=10, pady=(10, 4))
    self.cb_common = ctk.CTkCheckBox(rf, text="Compare 1.1.1.1 / 8.8.8.8 / 9.9.9.9", variable=self.v_common); self.cb_common.grid(row=1, column=0, sticky="w", padx=10, pady=(0, 6))
    ctk.CTkLabel(rf, text="Custom resolver IPs (comma-separated)").grid(row=2, column=0, sticky="w", padx=10, pady=(2, 2))
    self.e_res = ctk.CTkEntry(rf); self.e_res.grid(row=3, column=0, sticky="ew", padx=10, pady=(0, 10)); self.e_res.insert(0, str(self.cfg.get("custom_resolvers", "")))
    of = ctk.CTkFrame(L); of.grid(row=4, column=0, sticky="ew", padx=10, pady=(0, 8))
    self.cb_auth = ctk.CTkCheckBox(of, text="Query authoritative nameservers", variable=self.v_auth); self.cb_auth.grid(row=0, column=0, sticky="w", padx=10, pady=(10, 2))
    self.cb_expand = ctk.CTkCheckBox(of, text="Resolve CNAME targets (A)", variable=self.v_expand); self.cb_expand.grid(row=1, column=0, sticky="w", padx=10, pady=2)
    self.cb_clear = ctk.CTkCheckBox(of, text="Clear results each poll cycle", variable=self.v_clear); self.cb_clear.grid(row=2, column=0, sticky="w", padx=10, pady=(2, 10))
    pf = ctk.CTkFrame(L); pf.grid(row=5, column=0, sticky="ew", padx=10, pady=(0, 8))
    for i in range(4): pf.grid_columnconfigure(i, weight=1)
    self.e_poll = ctk.CTkEntry(pf, textvariable=self.v_poll); self.e_count = ctk.CTkEntry(pf, textvariable=self.v_count)
    self.e_timeout = ctk.CTkEntry(pf, textvariable=self.v_timeout); self.e_life = ctk.CTkEntry(pf, textvariable=self.v_life)
    for i, (lbl, e) in enumerate((("Poll sec", self.e_poll), ("Poll count", self.e_count), ("Timeout", self.e_timeout), ("Lifetime", self.e_life))):
      ctk.CTkLabel(pf, text=lbl).grid(row=0, column=i, padx=10, pady=(10, 2), sticky="w"); e.grid(row=1, column=i, padx=10, pady=(0, 10), sticky="ew")
    af = ctk.CTkFrame(L); af.grid(row=6, column=0, sticky="ew", padx=10, pady=(0, 10))
    af.grid_columnconfigure((0, 1, 2), weight=1)
    self.b_run = ctk.CTkButton(af, text="Run", command=self._run); self.b_stop = ctk.CTkButton(af, text="Stop", command=self._stop); self.b_save = ctk.CTkButton(af, text="Save Config", command=self._save)
    self.b_run.grid(row=0, column=0, padx=6, pady=10, sticky="ew"); self.b_stop.grid(row=0, column=1, padx=6, pady=10, sticky="ew"); self.b_save.grid(row=0, column=2, padx=6, pady=10, sticky="ew"); self.b_stop.configure(state="disabled")
    sf = ctk.CTkFrame(R); sf.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 6)); sf.grid_columnconfigure(1, weight=1)
    ctk.CTkLabel(sf, text="Status:").grid(row=0, column=0, padx=(10, 6), pady=8, sticky="w")
    ctk.CTkLabel(sf, textvariable=self.v_status).grid(row=0, column=1, padx=2, pady=8, sticky="w")
    self.pb = ctk.CTkProgressBar(sf, mode="indeterminate"); self.pb.grid(row=0, column=2, padx=(0, 10), pady=8, sticky="ew"); self.pb.set(0)
    rw = ctk.CTkFrame(R); rw.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 6)); rw.grid_columnconfigure(0, weight=1); rw.grid_rowconfigure(0, weight=1)
    cols = ("time", "host", "type", "value", "ttl", "ttl_human", "resolver", "status", "detail")
    self.tree = ttk.Treeview(rw, columns=cols, show="headings")
    for c, w, a in (("time", 80, "w"), ("host", 220, "w"), ("type", 70, "center"), ("value", 320, "w"), ("ttl", 80, "e"), ("ttl_human", 120, "w"), ("resolver", 260, "w"), ("status", 100, "center"), ("detail", 260, "w")):
      self.tree.heading(c, text=c.upper()); self.tree.column(c, width=w, anchor=a, stretch=(c in {"value", "detail"}))
    self.tree.tag_configure("ok", foreground="#56c271"); self.tree.tag_configure("warn", foreground="#d3a957"); self.tree.tag_configure("err", foreground="#e56d6d")
    ys = ttk.Scrollbar(rw, orient="vertical", command=self.tree.yview); xs = ttk.Scrollbar(rw, orient="horizontal", command=self.tree.xview)
    self.tree.configure(yscrollcommand=ys.set, xscrollcommand=xs.set); self.tree.grid(row=0, column=0, sticky="nsew"); ys.grid(row=0, column=1, sticky="ns"); xs.grid(row=1, column=0, sticky="ew")
    self.overlay = ctk.CTkFrame(rw); ctk.CTkLabel(self.overlay, text="Running DNS checks...", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=(30, 8)); self.ol_sub = ctk.CTkLabel(self.overlay, text="Please wait..."); self.ol_sub.pack(pady=(0, 22)); self.overlay.place_forget()
    dw = ctk.CTkFrame(R); dw.grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 6)); dw.grid_columnconfigure(0, weight=1); ctk.CTkLabel(dw, text="Diagnostics", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, sticky="w", padx=10, pady=(8, 2)); self.t_diag = ctk.CTkTextbox(dw, height=130); self.t_diag.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 10))
    lw = ctk.CTkFrame(R); lw.grid(row=3, column=0, sticky="ew", padx=10, pady=(0, 10)); lw.grid_columnconfigure(0, weight=1); ctk.CTkLabel(lw, text="Log", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, sticky="w", padx=10, pady=(8, 2)); self.t_log = ctk.CTkTextbox(lw, height=110); self.t_log.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 10))

  def _tips(self) -> None:
    tooltip(self.t_hosts, text="One hostname per line."); tooltip(self.cb_system, text="Use default system DNS configuration."); tooltip(self.cb_common, text="Add Cloudflare/Google/Quad9.")
    tooltip(self.e_res, text="Comma-separated resolver IPs."); tooltip(self.cb_auth, text="Query authoritative nameservers directly."); tooltip(self.cb_expand, text="Resolve A records for CNAME targets.")
    tooltip(self.e_poll, text="0 = run once."); tooltip(self.e_count, text="0 = infinite cycles."); tooltip(self.e_timeout, text="Resolver timeout per try."); tooltip(self.e_life, text="Query lifetime.")

  def _splash(self) -> None:
    s = ctk.CTkToplevel(self); s.title("Loading"); s.geometry("430x170"); s.transient(self); s.grab_set(); s.resizable(False, False)
    fr = ctk.CTkFrame(s); fr.pack(fill="both", expand=True, padx=12, pady=12)
    ctk.CTkLabel(fr, text="DNS Propagation Checker", font=ctk.CTkFont(size=20, weight="bold")).pack(pady=(20, 6))
    ctk.CTkLabel(fr, text="Loading UI and configuration...").pack(pady=2)
    p = ctk.CTkProgressBar(fr, mode="indeterminate"); p.pack(fill="x", padx=26, pady=(8, 12)); p.start()
    self.after(650, lambda: (p.stop(), s.grab_release(), s.destroy()))

  def _overlay(self, on: bool, text: str = "") -> None:
    if on:
      self.ol_sub.configure(text=text or "Please wait..."); self.overlay.place(relx=0.08, rely=0.2, relwidth=0.84, relheight=0.4); self.overlay.lift()
    else:
      self.overlay.place_forget()

  def _log(self, msg: str) -> None:
    self.t_log.insert("end", f"[{dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n"); self.t_log.see("end")

  def _state(self, run: bool) -> None:
    self.running = run
    if run:
      self.b_run.configure(state="disabled"); self.b_stop.configure(state="normal"); self.pb.start(); self._overlay(True, self.v_status.get())
    else:
      self.b_run.configure(state="normal"); self.b_stop.configure(state="disabled"); self.pb.stop(); self.pb.set(0); self._overlay(False)

  def _hosts(self) -> list[str]:
    out: list[str] = []; seen: set[str] = set()
    for ln in self.t_hosts.get("1.0", "end-1c").splitlines():
      h = ln.strip().rstrip(".")
      if not h:
        continue
      k = h.lower()
      if k in seen:
        continue
      seen.add(k); out.append(h)
    return out

  def _resolvers(self) -> list[ResolverSpec]:
    out: list[ResolverSpec] = []; seen: set[str] = set()
    if self.v_system.get():
      out.append(ResolverSpec("system-default", None)); seen.add("system-default")
    if self.v_common.get():
      for ip in COMMON:
        if ip not in seen:
          out.append(ResolverSpec(ip, [ip])); seen.add(ip)
    for p in [x.strip() for x in str(self.e_res.get() or "").split(",") if x.strip()]:
      try:
        ipaddress.ip_address(p)
      except Exception:
        raise ValueError(f"Invalid resolver IP: {p}")
      if p not in seen:
        out.append(ResolverSpec(p, [p])); seen.add(p)
    if not out:
      raise ValueError("Select at least one resolver source.")
    return out

  def _cfg_from_ui(self) -> RunCfg:
    hs = self._hosts()
    if not hs:
      raise ValueError("Provide at least one hostname.")
    qtypes = [k for k, v in self.v.items() if v.get()]
    if not qtypes:
      raise ValueError("Select at least one record type.")
    timeout = max(0.1, float(self.v_timeout.get() or "2.0")); life = max(timeout, float(self.v_life.get() or "4.0"))
    return RunCfg(hs, qtypes, self._resolvers(), bool(self.v_auth.get()), bool(self.v_expand.get()), max(0.0, float(self.v_poll.get() or "0")), max(0, int(float(self.v_count.get() or "0"))), timeout, life, bool(self.v_clear.get()))

  def _save(self) -> None:
    g = self.geometry().split("+")[0]; w, h = g.split("x", 1)
    data = {
      "window": {"width": int(w), "height": int(h)},
      "appearance_mode": self.cfg.get("appearance_mode", "System"),
      "color_theme": self.cfg.get("color_theme", "blue"),
      "hostnames": self.t_hosts.get("1.0", "end-1c"),
      "types": {k: bool(v.get()) for k, v in self.v.items()},
      "use_system": bool(self.v_system.get()),
      "use_common": bool(self.v_common.get()),
      "custom_resolvers": str(self.e_res.get() or "").strip(),
      "authoritative": bool(self.v_auth.get()),
      "expand_cname": bool(self.v_expand.get()),
      "poll_seconds": max(0.0, float(self.v_poll.get() or "0")),
      "poll_count": max(0, int(float(self.v_count.get() or "0"))),
      "timeout": max(0.1, float(self.v_timeout.get() or "2.0")),
      "lifetime": max(0.2, float(self.v_life.get() or "4.0")),
      "clear_each_cycle": bool(self.v_clear.get()),
    }
    _write_json(PATH_CONFIG, data); self.cfg = data; self._log("Saved config.json")

  def _run(self) -> None:
    if self.running:
      return
    try:
      cfg = self._cfg_from_ui()
    except Exception as e:
      messagebox.showerror(APP_TITLE, str(e)); return
    self._save(); self.t_diag.delete("1.0", "end")
    if cfg.clear_each_cycle or cfg.poll_seconds <= 0:
      self.tree.delete(*self.tree.get_children())
    self.stop_event = threading.Event()
    self.th = threading.Thread(target=worker, args=(cfg, self.stop_event, self.q), daemon=True)
    self._state(True); self.v_status.set("Starting..."); self._log("Run started."); self.th.start()

  def _stop(self) -> None:
    if self.stop_event is not None:
      self.stop_event.set(); self.v_status.set("Stopping..."); self._overlay(True, "Stopping worker..."); self._log("Stop requested.")

  def _poll(self) -> None:
    try:
      while True:
        kind, payload = self.q.get_nowait()
        if kind == "status":
          self.v_status.set(str(payload)); self._overlay(True, str(payload))
        elif kind == "cycle_start":
          n, stamp = payload; self.v_status.set(f"Cycle {n} started @ {stamp}"); self._log(f"Cycle {n} started.")
        elif kind == "cycle":
          n, rows, diags, clear_each = payload
          if clear_each:
            self.tree.delete(*self.tree.get_children())
          for r in rows:
            tag = "ok" if r.status == "OK" else ("warn" if r.status == "NO_RECORD" else "err")
            self.tree.insert("", "end", values=(r.t, r.host, r.typ, r.val, "-" if r.ttl is None else str(r.ttl), ttl_human(r.ttl), r.resolver, r.status, r.detail), tags=(tag,))
          self.t_diag.insert("end", f"--- Cycle {n} @ {dt.datetime.now().strftime('%H:%M:%S')} ---\n" + "\n".join(diags) + "\n\n"); self.t_diag.see("end")
          self.v_status.set(f"Cycle {n} complete ({len(rows)} rows)"); self._log(f"Cycle {n} complete ({len(rows)} rows).")
        elif kind == "done":
          self.v_status.set("Idle"); self._state(False); self._log("Run finished.")
    except queue.Empty:
      pass
    self.after(120, self._poll)

  def _close(self) -> None:
    try:
      if self.stop_event is not None:
        self.stop_event.set()
      self._save()
    except Exception:
      pass
    self.destroy()


def main() -> int:
  app = App()
  app.mainloop()
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
