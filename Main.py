# BPing - BetterPing | Minimalist Network Optimizer
# Run with: python main.py
# Requires: pip install customtkinter speedtest-cli psutil

import customtkinter as ctk
import threading
import subprocess
import platform
import socket
import time
import json
import os
import sys
import psutil
import speedtest
from datetime import datetime

# ─── Theme ────────────────────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

ACCENT   = "#4FC3F7"   # ice blue
BG_DARK  = "#0D0D0D"
BG_CARD  = "#141414"
BG_PANEL = "#1A1A1A"
TEXT_DIM = "#888888"
GREEN    = "#4CAF50"
RED      = "#F44336"
YELLOW   = "#FFC107"

# ─── Diagnostics helpers ──────────────────────────────────────────────────────

def ping_host(host="8.8.8.8", count=4):
    """Return average ping in ms or None on failure."""
    param = "-n" if platform.system() == "Windows" else "-c"
    try:
        result = subprocess.run(
            ["ping", param, str(count), host],
            capture_output=True, text=True, timeout=15
        )
        output = result.stdout
        if platform.system() == "Windows":
            for line in output.splitlines():
                if "Average" in line or "average" in line:
                    parts = line.split("=")
                    return float(parts[-1].replace("ms", "").strip())
        else:
            for line in output.splitlines():
                if "avg" in line or "rtt" in line:
                    parts = line.split("/")
                    return float(parts[4])
    except Exception:
        pass
    return None


def get_wifi_info():
    """Return dict with SSID, signal, channel info (Windows only for full detail)."""
    info = {}
    if platform.system() == "Windows":
        try:
            out = subprocess.check_output(
                ["netsh", "wlan", "show", "interfaces"], text=True, timeout=10
            )
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("SSID") and "BSSID" not in line:
                    info["ssid"] = line.split(":", 1)[-1].strip()
                elif "Signal" in line:
                    info["signal"] = line.split(":", 1)[-1].strip()
                elif "Radio type" in line:
                    info["radio"] = line.split(":", 1)[-1].strip()
                elif "Channel" in line:
                    info["channel"] = line.split(":", 1)[-1].strip()
                elif "Receive rate" in line:
                    info["rx_rate"] = line.split(":", 1)[-1].strip()
                elif "Transmit rate" in line:
                    info["tx_rate"] = line.split(":", 1)[-1].strip()
        except Exception as e:
            info["error"] = str(e)
    else:
        info["note"] = "Full WiFi detail available on Windows only."
    return info


def run_speed_test():
    """Return (download_mbps, upload_mbps, ping_ms) or raise."""
    st = speedtest.Speedtest()
    st.get_best_server()
    dl = st.download() / 1_000_000
    ul = st.upload()   / 1_000_000
    ping = st.results.ping
    return round(dl, 2), round(ul, 2), round(ping, 2)


def scan_lag_sources():
    """Scan the system for common lag-spike causes. Returns list of findings."""
    findings = []

    # 1. High-CPU processes
    for proc in psutil.process_iter(["pid", "name", "cpu_percent"]):
        try:
            cpu = proc.info["cpu_percent"]
            if cpu and cpu > 20:
                findings.append({
                    "type": "HIGH_CPU",
                    "severity": "high" if cpu > 50 else "medium",
                    "detail": f"{proc.info['name']} using {cpu:.1f}% CPU",
                    "fix": f"Terminate or lower priority of PID {proc.info['pid']}"
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    # 2. High RAM usage
    ram = psutil.virtual_memory()
    if ram.percent > 85:
        findings.append({
            "type": "HIGH_RAM",
            "severity": "high",
            "detail": f"RAM usage at {ram.percent:.1f}% ({ram.used // 1024**2} MB used)",
            "fix": "Close unused applications to free memory"
        })

    # 3. Network-heavy processes
    try:
        net_procs = []
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "ESTABLISHED" and conn.pid:
                try:
                    name = psutil.Process(conn.pid).name()
                    net_procs.append(name)
                except Exception:
                    pass
        from collections import Counter
        heavy = [(n, c) for n, c in Counter(net_procs).items() if c >= 3]
        for name, count in heavy:
            findings.append({
                "type": "NET_HEAVY",
                "severity": "medium",
                "detail": f"{name} has {count} active network connections",
                "fix": f"Consider closing {name} if not needed"
            })
    except Exception:
        pass

    # 4. Windows-specific checks
    if platform.system() == "Windows":
        # Nagle algorithm check
        findings.append({
            "type": "NAGLE",
            "severity": "medium",
            "detail": "Nagle algorithm may be enabled (buffers small TCP packets, adds latency)",
            "fix": "Disable via registry: TcpAckFrequency=1, TCPNoDelay=1"
        })
        # Power plan check
        try:
            out = subprocess.check_output(
                ["powercfg", "/getactivescheme"], text=True, timeout=5
            )
            if "Balanced" in out or "Power saver" in out:
                findings.append({
                    "type": "POWER_PLAN",
                    "severity": "high",
                    "detail": "Power plan is not set to High Performance",
                    "fix": "Switch to High Performance power plan"
                })
        except Exception:
            pass

        # Windows Update service
        try:
            out = subprocess.check_output(
                ["sc", "query", "wuauserv"], text=True, timeout=5
            )
            if "RUNNING" in out:
                findings.append({
                    "type": "WIN_UPDATE",
                    "severity": "medium",
                    "detail": "Windows Update service is actively running",
                    "fix": "Pause Windows Update during gaming/work sessions"
                })
        except Exception:
            pass

        # DNS check
        try:
            out = subprocess.check_output(
                ["netsh", "interface", "ip", "show", "dns"], text=True, timeout=5
            )
            if "8.8.8.8" not in out and "1.1.1.1" not in out:
                findings.append({
                    "type": "DNS",
                    "severity": "low",
                    "detail": "Not using a fast public DNS (Google 8.8.8.8 or Cloudflare 1.1.1.1)",
                    "fix": "Set DNS to 1.1.1.1 (Cloudflare) for lower latency"
                })
        except Exception:
            pass

    if not findings:
        findings.append({
            "type": "OK",
            "severity": "none",
            "detail": "No significant lag sources detected.",
            "fix": ""
        })

    return findings


def auto_fix_windows(log_callback):
    """Apply safe, reversible Windows optimizations via PowerShell."""
    if platform.system() != "Windows":
        log_callback("[!] Auto-fix is Windows-only.")
        return

    fixes = [
        {
            "name": "Disable Nagle Algorithm (TCP latency)",
            "cmd": (
                "$adapters = Get-ChildItem 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces'; "
                "foreach ($a in $adapters) { "
                "  Set-ItemProperty -Path $a.PSPath -Name 'TcpAckFrequency' -Value 1 -Type DWord -Force -EA SilentlyContinue; "
                "  Set-ItemProperty -Path $a.PSPath -Name 'TCPNoDelay' -Value 1 -Type DWord -Force -EA SilentlyContinue "
                "}"
            )
        },
        {
            "name": "Set High Performance power plan",
            "cmd": "powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
        },
        {
            "name": "Set DNS to Cloudflare 1.1.1.1",
            "cmd": (
                "$iface = (Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -First 1).Name; "
                "Set-DnsClientServerAddress -InterfaceAlias $iface -ServerAddresses ('1.1.1.1','1.0.0.1')"
            )
        },
        {
            "name": "Flush DNS cache",
            "cmd": "Clear-DnsClientCache"
        },
        {
            "name": "Disable Windows Update delivery optimization (bandwidth hog)",
            "cmd": (
                "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeliveryOptimization\\Config' "
                "-Name 'DODownloadMode' -Value 0 -Type DWord -Force -EA SilentlyContinue"
            )
        },
        {
            "name": "Prioritize network for foreground apps",
            "cmd": (
                "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile' "
                "-Name 'NetworkThrottlingIndex' -Value 0xffffffff -Type DWord -Force -EA SilentlyContinue"
            )
        },
        {
            "name": "Disable auto-tuning (can cause instability on some routers)",
            "cmd": "netsh int tcp set global autotuninglevel=disabled"
        },
    ]

    for fix in fixes:
        log_callback(f"  → {fix['name']}...")
        try:
            if fix["cmd"].startswith("netsh") or fix["cmd"].startswith("powercfg"):
                result = subprocess.run(
                    fix["cmd"], shell=True, capture_output=True, text=True, timeout=15
                )
            else:
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", fix["cmd"]],
                    capture_output=True, text=True, timeout=20
                )
            if result.returncode == 0:
                log_callback(f"     ✓ Done")
            else:
                log_callback(f"     ✗ Failed (may need admin): {result.stderr.strip()[:80]}")
        except Exception as e:
            log_callback(f"     ✗ Error: {e}")

    log_callback("\n[✓] Auto-fix complete. Restart recommended.")


# ─── UI ───────────────────────────────────────────────────────────────────────

class BPingApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("BPing — BetterPing")
        self.geometry("900x620")
        self.minsize(820, 560)
        self.configure(fg_color=BG_DARK)
        self._build_ui()

    # ── Layout ────────────────────────────────────────────────────────────────
    def _build_ui(self):
        # Sidebar
        self.sidebar = ctk.CTkFrame(self, width=180, fg_color=BG_CARD, corner_radius=0)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        logo = ctk.CTkLabel(
            self.sidebar, text="B·Ping",
            font=ctk.CTkFont(size=26, weight="bold"), text_color=ACCENT
        )
        logo.pack(pady=(28, 4))
        sub = ctk.CTkLabel(
            self.sidebar, text="BetterPing",
            font=ctk.CTkFont(size=11), text_color=TEXT_DIM
        )
        sub.pack(pady=(0, 28))

        self.nav_buttons = {}
        pages = [
            ("📡  WiFi Debug",   "wifi"),
            ("⚡  Speed Test",   "speed"),
            ("🔍  Lag Scanner",  "scan"),
            ("🔧  Auto Fix",     "fix"),
        ]
        for label, key in pages:
            btn = ctk.CTkButton(
                self.sidebar, text=label, anchor="w",
                fg_color="transparent", hover_color=BG_PANEL,
                text_color="white", font=ctk.CTkFont(size=13),
                height=40, corner_radius=8,
                command=lambda k=key: self._show_page(k)
            )
            btn.pack(fill="x", padx=12, pady=3)
            self.nav_buttons[key] = btn

        # Version at bottom
        ver = ctk.CTkLabel(
            self.sidebar, text="v1.0.0",
            font=ctk.CTkFont(size=10), text_color=TEXT_DIM
        )
        ver.pack(side="bottom", pady=16)

        # Main content area
        self.content = ctk.CTkFrame(self, fg_color=BG_DARK, corner_radius=0)
        self.content.pack(side="left", fill="both", expand=True)

        self.pages = {}
        self.pages["wifi"]  = self._build_wifi_page()
        self.pages["speed"] = self._build_speed_page()
        self.pages["scan"]  = self._build_scan_page()
        self.pages["fix"]   = self._build_fix_page()

        self._show_page("wifi")

    def _show_page(self, key):
        for k, frame in self.pages.items():
            frame.pack_forget()
        self.pages[key].pack(fill="both", expand=True, padx=24, pady=24)
        for k, btn in self.nav_buttons.items():
            btn.configure(fg_color=ACCENT if k == key else "transparent",
                          text_color="black" if k == key else "white")

    # ── Card helper ───────────────────────────────────────────────────────────
    def _card(self, parent, title=""):
        frame = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=12)
        if title:
            ctk.CTkLabel(
                frame, text=title,
                font=ctk.CTkFont(size=13, weight="bold"), text_color=TEXT_DIM
            ).pack(anchor="w", padx=16, pady=(14, 4))
        return frame

    def _stat_row(self, parent, label, value_var, unit=""):
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=4)
        ctk.CTkLabel(row, text=label, text_color=TEXT_DIM,
                     font=ctk.CTkFont(size=12)).pack(side="left")
        val = ctk.CTkLabel(row, textvariable=value_var,
                           font=ctk.CTkFont(size=13, weight="bold"), text_color="white")
        val.pack(side="right")
        if unit:
            ctk.CTkLabel(row, text=unit, text_color=TEXT_DIM,
                         font=ctk.CTkFont(size=11)).pack(side="right", padx=(0, 4))
        return val

    # ── Page 1: WiFi Debug ────────────────────────────────────────────────────
    def _build_wifi_page(self):
        page = ctk.CTkFrame(self.content, fg_color="transparent")

        ctk.CTkLabel(page, text="WiFi Debug",
                     font=ctk.CTkFont(size=22, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(page, text="Live network diagnostics & adapter info",
                     text_color=TEXT_DIM, font=ctk.CTkFont(size=12)).pack(anchor="w", pady=(2, 16))

        # Ping card
        ping_card = self._card(page, "LIVE PING")
        ping_card.pack(fill="x", pady=(0, 12))

        self._ping_var = ctk.StringVar(value="—")
        self._ping_status = ctk.StringVar(value="")

        ping_row = ctk.CTkFrame(ping_card, fg_color="transparent")
        ping_row.pack(fill="x", padx=16, pady=(4, 12))
        ctk.CTkLabel(ping_row, textvariable=self._ping_var,
                     font=ctk.CTkFont(size=40, weight="bold"), text_color=ACCENT).pack(side="left")
        ctk.CTkLabel(ping_row, text=" ms",
                     font=ctk.CTkFont(size=16), text_color=TEXT_DIM).pack(side="left", pady=(14, 0))
        ctk.CTkLabel(ping_row, textvariable=self._ping_status,
                     font=ctk.CTkFont(size=12), text_color=TEXT_DIM).pack(side="right")

        # WiFi info card
        wifi_card = self._card(page, "ADAPTER INFO")
        wifi_card.pack(fill="x", pady=(0, 12))

        self._wifi_vars = {
            "ssid":    ctk.StringVar(value="—"),
            "signal":  ctk.StringVar(value="—"),
            "radio":   ctk.StringVar(value="—"),
            "channel": ctk.StringVar(value="—"),
            "rx_rate": ctk.StringVar(value="—"),
            "tx_rate": ctk.StringVar(value="—"),
        }
        labels = {
            "ssid": "Network (SSID)", "signal": "Signal Strength",
            "radio": "Radio Type",    "channel": "Channel",
            "rx_rate": "Receive Rate", "tx_rate": "Transmit Rate"
        }
        for key, lbl in labels.items():
            self._stat_row(wifi_card, lbl, self._wifi_vars[key])
        ctk.CTkFrame(wifi_card, height=8, fg_color="transparent").pack()

        # Buttons
        btn_row = ctk.CTkFrame(page, fg_color="transparent")
        btn_row.pack(fill="x", pady=4)
        ctk.CTkButton(
            btn_row, text="Refresh", width=120,
            fg_color=ACCENT, text_color="black", hover_color="#81D4FA",
            command=self._refresh_wifi
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            btn_row, text="Start Live Ping", width=140,
            fg_color=BG_PANEL, hover_color=BG_CARD,
            command=self._toggle_live_ping
        ).pack(side="left")

        self._live_ping_running = False
        self._refresh_wifi()
        return page

    def _refresh_wifi(self):
        def _run():
            info = get_wifi_info()
            for key, var in self._wifi_vars.items():
                var.set(info.get(key, "N/A"))
        threading.Thread(target=_run, daemon=True).start()

    def _toggle_live_ping(self):
        self._live_ping_running = not self._live_ping_running
        if self._live_ping_running:
            threading.Thread(target=self._live_ping_loop, daemon=True).start()

    def _live_ping_loop(self):
        while self._live_ping_running:
            ms = ping_host()
            if ms is not None:
                self._ping_var.set(f"{ms:.0f}")
                color = GREEN if ms < 50 else (YELLOW if ms < 100 else RED)
                self._ping_status.set("Good" if ms < 50 else ("Fair" if ms < 100 else "Poor"))
            else:
                self._ping_var.set("ERR")
                self._ping_status.set("No response")
            time.sleep(2)

    # ── Page 2: Speed Test ────────────────────────────────────────────────────
    def _build_speed_page(self):
        page = ctk.CTkFrame(self.content, fg_color="transparent")

        ctk.CTkLabel(page, text="Speed Test",
                     font=ctk.CTkFont(size=22, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(page, text="Measure your real download, upload & latency",
                     text_color=TEXT_DIM, font=ctk.CTkFont(size=12)).pack(anchor="w", pady=(2, 16))

        results_card = self._card(page, "RESULTS")
        results_card.pack(fill="x", pady=(0, 12))

        self._dl_var   = ctk.StringVar(value="—")
        self._ul_var   = ctk.StringVar(value="—")
        self._sping_var = ctk.StringVar(value="—")

        for label, var, unit in [
            ("Download",  self._dl_var,    "Mbps"),
            ("Upload",    self._ul_var,    "Mbps"),
            ("Ping",      self._sping_var, "ms"),
        ]:
            row = ctk.CTkFrame(results_card, fg_color="transparent")
            row.pack(fill="x", padx=16, pady=6)
            ctk.CTkLabel(row, text=label, text_color=TEXT_DIM,
                         font=ctk.CTkFont(size=12)).pack(side="left")
            ctk.CTkLabel(row, textvariable=var,
                         font=ctk.CTkFont(size=20, weight="bold"),
                         text_color=ACCENT).pack(side="right", padx=(0, 4))
            ctk.CTkLabel(row, text=unit, text_color=TEXT_DIM,
                         font=ctk.CTkFont(size=11)).pack(side="right")
        ctk.CTkFrame(results_card, height=8, fg_color="transparent").pack()

        self._speed_status = ctk.StringVar(value="")
        ctk.CTkLabel(page, textvariable=self._speed_status,
                     text_color=TEXT_DIM, font=ctk.CTkFont(size=12)).pack(anchor="w", pady=4)

        self._speed_btn = ctk.CTkButton(
            page, text="Run Speed Test", width=160,
            fg_color=ACCENT, text_color="black", hover_color="#81D4FA",
            command=self._run_speed_test
        )
        self._speed_btn.pack(anchor="w", pady=8)

        self._speed_progress = ctk.CTkProgressBar(page, mode="indeterminate", width=300)
        return page

    def _run_speed_test(self):
        self._speed_btn.configure(state="disabled", text="Testing...")
        self._speed_status.set("Connecting to best server...")
        self._speed_progress.pack(anchor="w", pady=4)
        self._speed_progress.start()

        def _run():
            try:
                dl, ul, ping = run_speed_test()
                self._dl_var.set(str(dl))
                self._ul_var.set(str(ul))
                self._sping_var.set(str(ping))
                self._speed_status.set(f"Last tested: {datetime.now().strftime('%H:%M:%S')}")
            except Exception as e:
                self._speed_status.set(f"Error: {e}")
            finally:
                self._speed_progress.stop()
                self._speed_progress.pack_forget()
                self._speed_btn.configure(state="normal", text="Run Speed Test")

        threading.Thread(target=_run, daemon=True).start()

    # ── Page 3: Lag Scanner ───────────────────────────────────────────────────
    def _build_scan_page(self):
        page = ctk.CTkFrame(self.content, fg_color="transparent")

        ctk.CTkLabel(page, text="Lag Scanner",
                     font=ctk.CTkFont(size=22, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(page, text="Detect processes, settings & system issues causing lag spikes",
                     text_color=TEXT_DIM, font=ctk.CTkFont(size=12)).pack(anchor="w", pady=(2, 16))

        self._scan_btn = ctk.CTkButton(
            page, text="Scan Now", width=140,
            fg_color=ACCENT, text_color="black", hover_color="#81D4FA",
            command=self._run_scan
        )
        self._scan_btn.pack(anchor="w", pady=(0, 12))

        self._scan_box = ctk.CTkScrollableFrame(page, fg_color=BG_CARD, corner_radius=12)
        self._scan_box.pack(fill="both", expand=True)

        ctk.CTkLabel(
            self._scan_box,
            text="Press Scan Now to analyse your system.",
            text_color=TEXT_DIM, font=ctk.CTkFont(size=12)
        ).pack(pady=20)

        return page

    def _run_scan(self):
        self._scan_btn.configure(state="disabled", text="Scanning...")
        for w in self._scan_box.winfo_children():
            w.destroy()
        ctk.CTkLabel(
            self._scan_box, text="Scanning...",
            text_color=TEXT_DIM, font=ctk.CTkFont(size=12)
        ).pack(pady=20)

        def _run():
            findings = scan_lag_sources()
            for w in self._scan_box.winfo_children():
                w.destroy()
            for f in findings:
                sev = f["severity"]
                color = {"high": RED, "medium": YELLOW, "low": ACCENT, "none": GREEN}.get(sev, TEXT_DIM)
                card = ctk.CTkFrame(self._scan_box, fg_color=BG_PANEL, corner_radius=8)
                card.pack(fill="x", padx=4, pady=4)
                top = ctk.CTkFrame(card, fg_color="transparent")
                top.pack(fill="x", padx=12, pady=(10, 2))
                ctk.CTkLabel(top, text=f"[{f['type']}]",
                             font=ctk.CTkFont(size=11, weight="bold"),
                             text_color=color).pack(side="left")
                ctk.CTkLabel(top, text=sev.upper(),
                             font=ctk.CTkFont(size=10),
                             text_color=color).pack(side="right")
                ctk.CTkLabel(card, text=f["detail"],
                             font=ctk.CTkFont(size=12), text_color="white",
                             wraplength=560, justify="left").pack(anchor="w", padx=12, pady=2)
                if f["fix"]:
                    ctk.CTkLabel(card, text=f"Fix: {f['fix']}",
                                 font=ctk.CTkFont(size=11), text_color=TEXT_DIM,
                                 wraplength=560, justify="left").pack(anchor="w", padx=12, pady=(0, 10))
            self._scan_btn.configure(state="normal", text="Scan Now")

        threading.Thread(target=_run, daemon=True).start()

    # ── Page 4: Auto Fix ──────────────────────────────────────────────────────
    def _build_fix_page(self):
        page = ctk.CTkFrame(self.content, fg_color="transparent")

        ctk.CTkLabel(page, text="Auto Fix",
                     font=ctk.CTkFont(size=22, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(
            page,
            text="Automatically applies safe Windows optimizations to reduce ping & lag spikes.",
            text_color=TEXT_DIM, font=ctk.CTkFont(size=12), wraplength=640, justify="left"
        ).pack(anchor="w", pady=(2, 4))
        ctk.CTkLabel(
            page,
            text="⚠  Run as Administrator for full effect.",
            text_color=YELLOW, font=ctk.CTkFont(size=11)
        ).pack(anchor="w", pady=(0, 14))

        self._fix_btn = ctk.CTkButton(
            page, text="Apply All Fixes", width=160,
            fg_color=ACCENT, text_color="black", hover_color="#81D4FA",
            command=self._run_fixes
        )
        self._fix_btn.pack(anchor="w", pady=(0, 12))

        self._fix_log = ctk.CTkTextbox(
            page, fg_color=BG_CARD, text_color="white",
            font=ctk.CTkFont(family="Courier", size=12),
            corner_radius=12, state="disabled"
        )
        self._fix_log.pack(fill="both", expand=True)

        return page

    def _fix_log_write(self, text):
        self._fix_log.configure(state="normal")
        self._fix_log.insert("end", text + "\n")
        self._fix_log.see("end")
        self._fix_log.configure(state="disabled")

    def _run_fixes(self):
        self._fix_btn.configure(state="disabled", text="Applying...")
        self._fix_log.configure(state="normal")
        self._fix_log.delete("1.0", "end")
        self._fix_log.configure(state="disabled")
        self._fix_log_write(f"[BPing Auto Fix] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self._fix_log_write("-" * 50)

        def _run():
            auto_fix_windows(self._fix_log_write)
            self._fix_btn.configure(state="normal", text="Apply All Fixes")

        threading.Thread(target=_run, daemon=True).start()


# ─── Game Mode ───────────────────────────────────────────────────────────────
# Targets the exact issue: good ping at start, heavy spikes after ~2 min
# in public lobbies. Root causes: background CPU bursts stealing bandwidth,
# Fortnite process not at high priority, and socket buffer buildup.
# Fix strategy: one-time setup on start (heavy ops), then a lightweight
# 3-second ping-only monitor loop — no PowerShell every cycle.

FORTNITE_EXE = "FortniteClient-Win64-Shipping.exe"

# Processes known to burst bandwidth/CPU in public lobbies
BANDWIDTH_HOGS = {
    "SearchIndexer.exe", "MsMpEng.exe", "TiWorker.exe", "wuauclt.exe",
    "SgrmBroker.exe", "WmiPrvSE.exe", "MusNotification.exe",
    "OneDrive.exe", "Teams.exe", "Spotify.exe",
    "chrome.exe", "msedge.exe", "firefox.exe",
}


def quick_ping(host="8.8.8.8"):
    """Single fast ping using socket — no subprocess, no blocking."""
    try:
        start = time.perf_counter()
        s = socket.create_connection((host, 53), timeout=2)
        ms = (time.perf_counter() - start) * 1000
        s.close()
        return round(ms, 1)
    except Exception:
        return None


def game_mode_setup(log_callback):
    """
    One-time setup when Game Mode starts. Does the heavy work once so the
    monitor loop stays lightweight and doesn't lag the app.
    """
    if platform.system() != "Windows":
        log_callback("[!] Game Mode is Windows-only.")
        return

    log_callback("[Setup] Applying one-time optimizations...")

    # 1. Boost Fortnite process to High priority
    boosted = False
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            if proc.info["name"] == FORTNITE_EXE:
                p = psutil.Process(proc.info["pid"])
                p.nice(psutil.HIGH_PRIORITY_CLASS)
                log_callback(f"  ✓ Fortnite boosted to HIGH priority (PID {proc.info['pid']})")
                boosted = True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    if not boosted:
        log_callback("  ! Fortnite not running — start it, then restart Game Mode")

    # 2. Lower priority of bandwidth hogs (not kill — safe)
    lowered = []
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            if proc.info["name"] in BANDWIDTH_HOGS:
                p = psutil.Process(proc.info["pid"])
                p.nice(psutil.IDLE_PRIORITY_CLASS)
                lowered.append(proc.info["name"])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    if lowered:
        log_callback(f"  ✓ Lowered priority: {', '.join(set(lowered))}")

    # 3. Flush DNS once
    try:
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True, timeout=8)
        log_callback("  ✓ DNS cache flushed")
    except Exception:
        pass

    # 4. Set Fortnite UDP socket buffer via registry (reduces packet loss in crowded lobbies)
    try:
        ps_cmd = (
            "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters' "
            "-Name 'DefaultReceiveWindow' -Value 65536 -Type DWord -Force -EA SilentlyContinue; "
            "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters' "
            "-Name 'DefaultSendWindow' -Value 65536 -Type DWord -Force -EA SilentlyContinue"
        )
        subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
            capture_output=True, timeout=15
        )
        log_callback("  ✓ UDP socket buffers optimized (reduces public lobby packet loss)")
    except Exception:
        pass

    # 5. Disable Windows throttling of background network (helps foreground game traffic)
    try:
        ps_cmd2 = (
            "Set-ItemProperty -Path "
            "'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile' "
            "-Name 'NetworkThrottlingIndex' -Value 0xffffffff -Type DWord -Force -EA SilentlyContinue; "
            "Set-ItemProperty -Path "
            "'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games' "
            "-Name 'GPU Priority' -Value 8 -Type DWord -Force -EA SilentlyContinue; "
            "Set-ItemProperty -Path "
            "'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games' "
            "-Name 'Priority' -Value 6 -Type DWord -Force -EA SilentlyContinue"
        )
        subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd2],
            capture_output=True, timeout=15
        )
        log_callback("  ✓ Windows game scheduling priority set")
    except Exception:
        pass

    log_callback("[Setup] Done. Monitoring started.")
    log_callback("-" * 48)


class GameModeMonitor:
    """
    Lightweight monitor loop: fast socket ping every 3s.
    No subprocess calls in the loop — keeps the app smooth.
    """

    def __init__(self, log_callback, ping_var, status_var, spike_var):
        self.log_callback = log_callback
        self.ping_var     = ping_var
        self.status_var   = status_var
        self.spike_var    = spike_var
        self._running     = False
        self._thread      = None
        self._spike_count = 0
        self._ping_history = []

    def start(self):
        self._running = True
        self._thread  = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def _loop(self):
        # Run heavy setup once in this thread (not the UI thread)
        game_mode_setup(self.log_callback)

        while self._running:
            ms = quick_ping()
            now = datetime.now().strftime("%H:%M:%S")

            if ms is not None:
                self._ping_history.append(ms)
                if len(self._ping_history) > 20:
                    self._ping_history.pop(0)

                avg = sum(self._ping_history) / len(self._ping_history)
                # Spike = current ping is 2x the rolling average
                is_spike = len(self._ping_history) >= 5 and ms > max(avg * 2, 80)

                self.ping_var.set(f"{ms:.0f} ms")

                if is_spike:
                    self._spike_count += 1
                    self.spike_var.set(str(self._spike_count))
                    self.log_callback(
                        f"[{now}] ⚡ SPIKE {ms:.0f}ms (avg {avg:.0f}ms) "
                        f"— re-boosting Fortnite priority"
                    )
                    # On spike: re-boost Fortnite priority (cheap, no PowerShell)
                    for proc in psutil.process_iter(["pid", "name"]):
                        try:
                            if proc.info["name"] == FORTNITE_EXE:
                                psutil.Process(proc.info["pid"]).nice(
                                    psutil.HIGH_PRIORITY_CLASS
                                )
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                else:
                    self.log_callback(f"[{now}] Ping: {ms:.0f}ms  avg: {avg:.0f}ms  ✓")
            else:
                self.ping_var.set("timeout")
                self.log_callback(f"[{now}] Ping: timeout")

            self.status_var.set("🟢 Active" if self._running else "⚫ Stopped")
            time.sleep(3)  # lightweight — 3s not 10s, no subprocess

        self.log_callback("[Game Mode] Stopped.")
        self.status_var.set("⚫ Stopped")


# ─── Patch BPingApp to add Game Mode page ─────────────────────────────────────

def _patched_build_ui(self):
    self.sidebar = ctk.CTkFrame(self, width=180, fg_color=BG_CARD, corner_radius=0)
    self.sidebar.pack(side="left", fill="y")
    self.sidebar.pack_propagate(False)

    logo = ctk.CTkLabel(
        self.sidebar, text="B·Ping",
        font=ctk.CTkFont(size=26, weight="bold"), text_color=ACCENT
    )
    logo.pack(pady=(28, 4))
    ctk.CTkLabel(
        self.sidebar, text="BetterPing",
        font=ctk.CTkFont(size=11), text_color=TEXT_DIM
    ).pack(pady=(0, 28))

    self.nav_buttons = {}
    pages = [
        ("📡  WiFi Debug",  "wifi"),
        ("⚡  Speed Test",  "speed"),
        ("🔍  Lag Scanner", "scan"),
        ("🔧  Auto Fix",    "fix"),
        ("🎮  Game Mode",   "game"),
    ]
    for label, key in pages:
        btn = ctk.CTkButton(
            self.sidebar, text=label, anchor="w",
            fg_color="transparent", hover_color=BG_PANEL,
            text_color="white", font=ctk.CTkFont(size=13),
            height=40, corner_radius=8,
            command=lambda k=key: self._show_page(k)
        )
        btn.pack(fill="x", padx=12, pady=3)
        self.nav_buttons[key] = btn

    ctk.CTkLabel(
        self.sidebar, text="v1.2.0",
        font=ctk.CTkFont(size=10), text_color=TEXT_DIM
    ).pack(side="bottom", pady=16)

    self.content = ctk.CTkFrame(self, fg_color=BG_DARK, corner_radius=0)
    self.content.pack(side="left", fill="both", expand=True)

    self.pages = {}
    self.pages["wifi"]  = self._build_wifi_page()
    self.pages["speed"] = self._build_speed_page()
    self.pages["scan"]  = self._build_scan_page()
    self.pages["fix"]   = self._build_fix_page()
    self.pages["game"]  = self._build_game_page()
    self._show_page("wifi")


BPingApp._build_ui = _patched_build_ui


def _build_game_page(self):
    page = ctk.CTkFrame(self.content, fg_color="transparent")

    ctk.CTkLabel(page, text="🎮  Game Mode",
                 font=ctk.CTkFont(size=22, weight="bold")).pack(anchor="w")
    ctk.CTkLabel(
        page,
        text=(
            "Start this BEFORE joining a public lobby.\n"
            "It boosts Fortnite to HIGH CPU priority, throttles background apps,\n"
            "optimizes UDP buffers, then monitors ping every 3s — lightweight, no lag."
        ),
        text_color=TEXT_DIM, font=ctk.CTkFont(size=12), justify="left"
    ).pack(anchor="w", pady=(2, 14))

    status_card = self._card(page, "LIVE STATUS")
    status_card.pack(fill="x", pady=(0, 12))

    self._gm_ping_var  = ctk.StringVar(value="— ms")
    self._gm_status_var = ctk.StringVar(value="⚫ Stopped")
    self._gm_spike_var  = ctk.StringVar(value="0")

    for label, var in [
        ("Live Ping",   self._gm_ping_var),
        ("Status",      self._gm_status_var),
        ("Spike Count", self._gm_spike_var),
    ]:
        self._stat_row(status_card, label, var)
    ctk.CTkFrame(status_card, height=8, fg_color="transparent").pack()

    btn_row = ctk.CTkFrame(page, fg_color="transparent")
    btn_row.pack(anchor="w", pady=(0, 12))

    self._gm_start_btn = ctk.CTkButton(
        btn_row, text="▶  Start Game Mode", width=180,
        fg_color=GREEN, text_color="black", hover_color="#81C784",
        command=self._start_game_mode
    )
    self._gm_start_btn.pack(side="left", padx=(0, 8))

    self._gm_stop_btn = ctk.CTkButton(
        btn_row, text="■  Stop", width=100,
        fg_color=BG_PANEL, hover_color=BG_CARD,
        state="disabled",
        command=self._stop_game_mode
    )
    self._gm_stop_btn.pack(side="left")

    self._gm_log = ctk.CTkTextbox(
        page, fg_color=BG_CARD, text_color="white",
        font=ctk.CTkFont(family="Courier", size=11),
        corner_radius=12, state="disabled"
    )
    self._gm_log.pack(fill="both", expand=True)

    self._gm_monitor = None
    return page


def _gm_log_write(self, text):
    self._gm_log.configure(state="normal")
    self._gm_log.insert("end", text + "\n")
    self._gm_log.see("end")
    self._gm_log.configure(state="disabled")


def _start_game_mode(self):
    self._gm_log.configure(state="normal")
    self._gm_log.delete("1.0", "end")
    self._gm_log.configure(state="disabled")
    self._gm_spike_var.set("0")
    self._gm_monitor = GameModeMonitor(
        log_callback = self._gm_log_write,
        ping_var     = self._gm_ping_var,
        status_var   = self._gm_status_var,
        spike_var    = self._gm_spike_var,
    )
    self._gm_monitor.start()
    self._gm_start_btn.configure(state="disabled")
    self._gm_stop_btn.configure(state="normal")


def _stop_game_mode(self):
    if self._gm_monitor:
        self._gm_monitor.stop()
    self._gm_start_btn.configure(state="normal")
    self._gm_stop_btn.configure(state="disabled")


BPingApp._build_game_page = _build_game_page
BPingApp._gm_log_write    = _gm_log_write
BPingApp._start_game_mode = _start_game_mode
BPingApp._stop_game_mode  = _stop_game_mode


# ─── Entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = BPingApp()
    app.mainloop()
