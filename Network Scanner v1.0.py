import sys
import subprocess
import time
import socket
import platform
import csv
import re
import json
import ipaddress
from itertools import islice
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTextEdit, QLabel, QLineEdit, QMessageBox,
    QProgressBar, QTabWidget, QFileDialog, QTableWidget, QTableWidgetItem,
    QSpinBox, QComboBox, QGroupBox, QGridLayout, QFrame
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QTextCursor, QPixmap, QIcon

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# --------- Scan settings ----------
MAX_HOSTS_PER_NETWORK = 4096
MAX_TOTAL_HOSTS = 20000
LARGE_SCAN_CONFIRM_THRESHOLD = 6000
SCAN_CHUNK_SIZE = 512
PING_TIMEOUT = 2.5  # seconds for subprocess timeout
PING_CMD_TIMEOUT_MS = 700


# --------- Utility Functions ----------
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except:
            return "127.0.0.1"

def get_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except:
        return "N/A"

# --------- Network Helpers ----------
def get_network_interfaces():
    interfaces = []
    if HAS_PSUTIL:
        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            for iface_name, iface_addrs in addrs.items():
                iface_info = {
                    "name": iface_name,
                    "addresses": [],
                    "is_up": stats[iface_name].isup if iface_name in stats else False,
                    "speed": stats[iface_name].speed if iface_name in stats else 0,
                }
                for addr in iface_addrs:
                    if addr.family == socket.AF_INET:
                        iface_info["addresses"].append(
                            {
                                "ip": addr.address,
                                "netmask": addr.netmask,
                                "broadcast": getattr(addr, "broadcast", "N/A"),
                            }
                        )
                if iface_info["addresses"]:
                    interfaces.append(iface_info)
        except Exception:
            pass
    return interfaces


def get_arp_table():
    entries = []
    system = platform.system().lower()
    try:
        if system == "windows":
            result = subprocess.run(
                ["arp", "-a"],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
                timeout=5,
            )
        else:
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5)

        for line in result.stdout.splitlines():
            if system == "windows":
                match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})", line)
                if match:
                    entries.append({"ip": match.group(1), "mac": match.group(2)})
            else:
                match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})", line)
                if match:
                    entries.append({"ip": match.group(1), "mac": match.group(2)})
    except Exception:
        pass
    return entries


# --------- Ping / Port utilities ----------
def ping_once(host, timeout_ms=PING_CMD_TIMEOUT_MS):
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", host, "-n", "1", "-w", str(timeout_ms)]
    else:
        timeout_s = str(max(1, int(timeout_ms / 1000)))
        cmd = ["ping", "-c", "1", "-W", timeout_s, host]

    try:
        creation_flags = 0
        if system == "windows":
            creation_flags = subprocess.CREATE_NO_WINDOW

        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            creationflags=creation_flags,
            timeout=PING_TIMEOUT
        )
        return res.returncode == 0
    except Exception:
        return False

# --------- Port scan function ----------
def scan_port(host, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

# --------- Scan Thread -----------
class ScanWorker(QThread):
    progress = pyqtSignal(str)
    progress_value = pyqtSignal(int)
    found_ips = pyqtSignal(list)
    scan_stats = pyqtSignal(dict)

    def __init__(self, targets, max_workers=300, scope_label="auto scope"):
        super().__init__()
        self.targets = targets
        self.max_workers = max_workers
        self.scope_label = scope_label
        self._stopped = False
        self.start_time = None

    def run(self):
        self.start_time = time.time()
        ips_found = []
        total = len(self.targets)
        if total == 0:
            self.progress.emit(f"[{self.get_timestamp()}] No targets available for scanning.\n")
            self.scan_stats.emit({"total_scanned": 0, "found": 0, "elapsed_time": 0})
            self.found_ips.emit([])
            return

        self.progress.emit(f"[{self.get_timestamp()}] Starting scan on {self.scope_label} ({total} hosts)...\n")
        completed = 0
        with ThreadPoolExecutor(max_workers=min(self.max_workers, max(1, total))) as ex:
            idx = 0
            while idx < total and not self._stopped:
                chunk = self.targets[idx : idx + SCAN_CHUNK_SIZE]
                futures = {ex.submit(ping_once, addr): addr for addr in chunk}

                for fut in as_completed(futures):
                    addr = futures[fut]
                    completed += 1
                    try:
                        alive = fut.result()
                    except Exception:
                        alive = False

                    if alive:
                        hostname = get_hostname(addr)
                        ips_found.append((addr, hostname))
                        self.progress.emit(f"[{self.get_timestamp()}] [+] {addr} ({hostname}) is alive\n")

                    progress_pct = int((completed / total) * 100)
                    self.progress_value.emit(progress_pct)

                    if completed % 50 == 0:
                        self.progress.emit(f"[{self.get_timestamp()}] Scanned {completed}/{total} ({progress_pct}%)...\n")

                    if self._stopped:
                        self.progress.emit(f"[{self.get_timestamp()}] Scan stopped by user.\n")
                        break

                idx += SCAN_CHUNK_SIZE
                if self._stopped:
                    break

        elapsed_time = time.time() - self.start_time
        self.progress.emit(f"[{self.get_timestamp()}] Scan finished in {elapsed_time:.2f} seconds.\n")

        stats = {"total_scanned": completed, "found": len(ips_found), "elapsed_time": elapsed_time}
        self.scan_stats.emit(stats)
        self.found_ips.emit(sorted(ips_found, key=lambda x: socket.inet_aton(x[0])))

    def get_timestamp(self):
        return datetime.now().strftime("%H:%M:%S")

    def stop(self):
        self._stopped = True

# --------- Port Scan Thread -----------
class PortScanWorker(QThread):
    progress = pyqtSignal(str)
    progress_value = pyqtSignal(int)
    found_ports = pyqtSignal(list)

    def __init__(self, host, ports, max_workers=50):
        super().__init__()
        self.host = host
        self.ports = ports
        self.max_workers = max_workers
        self._stopped = False

    def run(self):
        open_ports = []
        total = len(self.ports)
        self.progress.emit(f"[{self.get_timestamp()}] Scanning {self.host} for {total} ports...\n")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = {ex.submit(scan_port, self.host, port): port for port in self.ports}
            completed = 0
            
            for fut in as_completed(futures):
                port = futures[fut]
                completed += 1
                try:
                    is_open = fut.result()
                except Exception:
                    is_open = False
                
                if is_open:
                    open_ports.append(port)
                    self.progress.emit(f"[{self.get_timestamp()}] [+] Port {port} is open\n")
                
                progress_pct = int((completed / total) * 100)
                self.progress_value.emit(progress_pct)
                
                if self._stopped:
                    self.progress.emit(f"[{self.get_timestamp()}] Port scan stopped.\n")
                    break
        
        self.progress.emit(f"[{self.get_timestamp()}] Port scan finished. Found {len(open_ports)} open ports.\n")
        self.found_ports.emit(sorted(open_ports))

    def get_timestamp(self):
        return datetime.now().strftime("%H:%M:%S")

    def stop(self):
        self._stopped = True

# --------- Ping Thread -----------
class PingWorker(QThread):
    output = pyqtSignal(str)
    finished_signal = pyqtSignal(str)

    def __init__(self, target, rounds=3, pings_per_round=5):
        super().__init__()
        self.target = target
        self.rounds = rounds
        self.pings_per_round = pings_per_round
        self._stopped = False

    def run(self):
        system = platform.system().lower()
        overall_success = 0
        overall_total = 0

        for round_num in range(self.rounds):
            if self._stopped:
                self.output.emit(f"<font color='gray'><b>[{self.get_timestamp()}] Ping stopped by user.</b></font><br>")
                break

            self.output.emit(f"<b>--- Round {round_num + 1} ---</b><br>")
            success_count = 0
            total_count = self.pings_per_round
            overall_total += total_count

            if system == "windows":
                cmd = ["ping", self.target, "-n", str(total_count)]
            else:
                cmd = ["ping", "-c", str(total_count), self.target]

            try:
                creationflags = 0
                if platform.system().lower() == "windows":
                    creationflags = subprocess.CREATE_NO_WINDOW

                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    creationflags=creationflags
)

                for line in proc.stdout:
                    if self._stopped:
                        proc.kill()
                        break
                    line = line.strip()
                    if line:
                        if "Reply" in line or "bytes from" in line:
                            success_count += 1
                        self.output.emit(f"[{self.get_timestamp()}] {line}<br>")
                proc.wait()
            except Exception as e:
                self.output.emit(f"<font color='red'>[{self.get_timestamp()}] Ping command failed: {e}</font><br>")

            overall_success += success_count
            loss_percent = int(((total_count - success_count) / total_count) * 100)
            if success_count == total_count:
                result = f"<font color='green'> Round {round_num+1} Result: Host reachable (0% loss)</font><br>"
            elif success_count > 0:
                result = f"<font color='orange'> Round {round_num+1} Result: Partial success ({loss_percent}% loss)</font><br>"
            else:
                result = f"<font color='red'> Round {round_num+1} Result: Host unreachable (100% loss)</font><br>"
            self.output.emit(result)

            if round_num < self.rounds - 1 and not self._stopped:
                for _ in range(1):
                    if self._stopped:
                        break
                    time.sleep(1)

        overall_loss = int(((overall_total - overall_success) / overall_total) * 100)
        if overall_success == overall_total:
            final_result = f"<font color='green'><b>✅ Summary: Ready to use (0% loss)</b></font><br>"
        elif overall_success > 0:
            final_result = f"<font color='orange'><b>🟡 Summary: Partial success ({overall_loss}% loss)</b></font><br>"
        else:
            final_result = f"<font color='red'><b>❌ Summary: Host unreachable (100% loss)</b></font><br>"

        self.finished_signal.emit(final_result)

    def get_timestamp(self):
        return datetime.now().strftime("%H:%M:%S")

    def stop(self):
        self._stopped = True


class DNSLookupWorker(QThread):
    result = pyqtSignal(str)

    def __init__(self, target, lookup_type="forward"):
        super().__init__()
        self.target = target
        self.lookup_type = lookup_type

    def run(self):
        try:
            if self.lookup_type == "forward":
                ip = socket.gethostbyname(self.target)
                self.result.emit(f"✅ {self.target} → {ip}")
            else:
                hostname, aliases, _ = socket.gethostbyaddr(self.target)
                text = f"✅ {self.target} → {hostname}"
                if aliases:
                    text += f"\nAliases: {', '.join(aliases)}"
                self.result.emit(text)
        except socket.gaierror as e:
            self.result.emit(f"❌ DNS Lookup failed: {e}")
        except Exception as e:
            self.result.emit(f"❌ Error: {e}")


class TracerouteWorker(QThread):
    output = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, target, max_hops=30):
        super().__init__()
        self.target = target
        self.max_hops = max_hops
        self._stopped = False

    def run(self):
        system = platform.system().lower()
        if system == "windows":
            cmd = ["tracert", "-h", str(self.max_hops), self.target]
        else:
            cmd = ["traceroute", "-m", str(self.max_hops), self.target]

        try:
            creationflags = 0
            if system == "windows":
                creationflags = subprocess.CREATE_NO_WINDOW

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                creationflags=creationflags,
            )

            for line in proc.stdout:
                if self._stopped:
                    proc.kill()
                    break
                line = line.strip()
                if line:
                    self.output.emit(f"[{self.get_timestamp()}] {line}")
            proc.wait()
        except Exception as e:
            self.output.emit(f"❌ Traceroute failed: {e}")

        self.finished.emit()

    def get_timestamp(self):
        return datetime.now().strftime("%H:%M:%S")

    def stop(self):
        self._stopped = True

# ---------------- Main GUI ----------------
class PingApp(QWidget):
    def __init__(self):
        super().__init__()
        self.scan_thread = None
        self.ping_thread = None
        self.port_scan_thread = None
        self.dns_thread = None
        self.traceroute_thread = None
        self.local_ip = get_local_ip()
        self.scan_results = []
        self.subnets = []
        self.subnet_lookup = {}
        self.monitor_timer = QTimer()
        self.monitor_timer.setInterval(5000)
        self.monitor_timer.timeout.connect(self.update_network_stats)
        self.init_ui()
        self.refresh_network_info()
        self.monitor_timer.start()

    def init_ui(self):
        self.setWindowIcon(QIcon("icon.png"))
        self.setWindowTitle("Network Management Suite v3.1 - Professional Edition")
        self.setGeometry(100, 40, 1400, 900)
        self.setMinimumSize(1200, 750)

        self.setStyleSheet(
            """
        QWidget {
            background: qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:1,
                                        stop:0 #0f172a,
                                        stop:1 #1e293b);
            color: #f1f5f9;
            font-family: 'Segoe UI', Arial, sans-serif;
            font-size: 13px;
        }

        QGroupBox {
            font-weight: bold;
            border: 2px solid #38bdf8;
            border-radius: 10px;
            margin-top: 12px;
            padding-top: 18px;
            background-color: rgba(15, 23, 42, 0.8);
        }

        QGroupBox::title {
            subcontrol-origin: margin;
            left: 12px;
            padding: 0 6px;
            color: #7dd3fc;
            font-size: 13px;
        }

        QLineEdit, QTextEdit, QTableWidget, QSpinBox, QComboBox {
            background-color: rgba(15, 23, 42, 0.9);
            color: #f8fafc;
            border: 1px solid rgba(248, 250, 252, 0.15);
            border-radius: 6px;
            padding: 8px;
            selection-background-color: #38bdf8;
            font-size: 13px;
        }

        QPushButton {
            border-radius: 8px;
            padding: 10px 18px;
            color: white;
            background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                              stop:0 #0ea5e9, stop:1 #22d3ee);
            font-weight: bold;
            letter-spacing: 0.5px;
            min-height: 32px;
        }

        QPushButton:hover {
            background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                              stop:0 #38bdf8, stop:1 #67e8f9);
        }

        QPushButton:pressed {
            background-color: #0c4a6e;
        }

        QPushButton:disabled {
            background-color: rgba(100, 116, 139, 0.4);
            color: rgba(226, 232, 240, 0.6);
        }

        QLabel {
            color: #f8fafc;
            font-size: 13px;
        }

        QTabWidget::pane {
            border: 2px solid rgba(56, 189, 248, 0.6);
            border-radius: 10px;
            background: rgba(15, 23, 42, 0.95);
            top: -1px;
        }

        QTabBar::tab {
            background: rgba(56, 189, 248, 0.2);
            color: #e2e8f0;
            padding: 12px 28px;
            border-top-left-radius: 8px;
            border-top-right-radius: 8px;
            margin-right: 4px;
            font-weight: bold;
            font-size: 13px;
        }

        QTabBar::tab:selected {
            background: rgba(14, 165, 233, 0.85);
            color: white;
            border-bottom: 2px solid #fbbf24;
        }

        QProgressBar {
            border: 1px solid rgba(248, 250, 252, 0.2);
            border-radius: 6px;
            text-align: center;
            background-color: rgba(15, 23, 42, 0.8);
            color: white;
            height: 24px;
            font-weight: bold;
        }

        QProgressBar::chunk {
            background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                              stop:0 #22d3ee, stop:1 #a5b4fc);
            border-radius: 5px;
        }

        QTableWidget {
            gridline-color: rgba(148, 163, 184, 0.4);
            background-color: rgba(15, 23, 42, 0.9);
            font-size: 13px;
        }

        QHeaderView::section {
            background-color: rgba(15, 118, 110, 0.9);
            color: #f8fafc;
            padding: 8px;
            border: none;
            font-weight: bold;
            font-size: 13px;
        }

        QScrollBar:vertical {
            background: rgba(15, 23, 42, 0.8);
            width: 12px;
            border-radius: 6px;
            margin: 0;
        }

        QScrollBar::handle:vertical {
            background: #22d3ee;
            min-height: 24px;
            border-radius: 6px;
        }

        QFrame {
            background-color: rgba(15, 23, 42, 0.6);
            border: 1px solid rgba(248, 250, 252, 0.1);
            border-radius: 10px;
        }
        """
        )

        main_layout = QVBoxLayout()
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(15, 15, 15, 15)

        header_layout = QHBoxLayout()
        info_frame = QFrame()
        info_frame.setFixedHeight(130)
        info_layout = QHBoxLayout()
        info_layout.setSpacing(15)

        card1 = QFrame()
        card1.setStyleSheet("QFrame { background-color: rgba(45, 90, 135, 0.3); border: 1px solid #2d5a87; border-radius: 6px; }")
        card1_layout = QVBoxLayout()
        card1_layout.setContentsMargins(10, 5, 10, 5)
        card1_title = QLabel("Local IP Address")
        card1_title.setStyleSheet("color: #4fc3f7; font-weight: bold; font-size: 10px;")
        self.card1_value = QLabel(self.local_ip)
        self.card1_value.setStyleSheet("color: white; font-size: 18px; font-weight: 900;")
        card1_layout.addWidget(card1_title)
        card1_layout.addWidget(self.card1_value)
        card1.setLayout(card1_layout)

        card2 = QFrame()
        card2.setStyleSheet("QFrame { background-color: rgba(45, 90, 135, 0.3); border: 1px solid #2d5a87; border-radius: 6px; }")
        card2_layout = QVBoxLayout()
        card2_layout.setContentsMargins(10, 5, 10, 5)
        card2_title = QLabel("Hostname")
        card2_title.setStyleSheet("color: #4fc3f7; font-weight: bold; font-size: 10px;")
        self.card2_value = QLabel(socket.gethostname())
        self.card2_value.setStyleSheet("color: white; font-size: 18px; font-weight: 900;")
        card2_layout.addWidget(card2_title)
        card2_layout.addWidget(self.card2_value)
        card2.setLayout(card2_layout)

        card3 = QFrame()
        card3.setStyleSheet("QFrame { background-color: rgba(45, 90, 135, 0.3); border: 1px solid #2d5a87; border-radius: 6px; }")
        card3_layout = QVBoxLayout()
        card3_layout.setContentsMargins(10, 5, 10, 5)
        card3_title = QLabel("Network Status")
        card3_title.setStyleSheet("color: #4fc3f7; font-weight: bold; font-size: 10px;")
        self.card3_value = QLabel("🟢 Online")
        self.card3_value.setStyleSheet("color: #4caf50; font-size: 18px; font-weight: 900;")
        card3_layout.addWidget(card3_title)
        card3_layout.addWidget(self.card3_value)
        card3.setLayout(card3_layout)

        info_layout.addWidget(card1)
        info_layout.addWidget(card2)
        info_layout.addWidget(card3)
        info_layout.addStretch()
        info_frame.setLayout(info_layout)
        header_layout.addWidget(info_frame)
        main_layout.addLayout(header_layout)

        target_row = QHBoxLayout()
        target_label = QLabel("Target:")
        target_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Enter IP address or hostname")
        self.ip_input.setText(self.local_ip)
        self.ip_input.setStyleSheet("font-size: 14px; padding: 8px;")
        target_row.addWidget(target_label)
        target_row.addWidget(self.ip_input)
        main_layout.addLayout(target_row)

        tabs = QTabWidget()
        tabs.addTab(self.create_dashboard_tab(), "📊 Dashboard")
        tabs.addTab(self.create_scan_tab(), "🔍 Network Scanner")
        tabs.addTab(self.create_ping_tab(), "📡 Ping & Connectivity")
        tabs.addTab(self.create_port_scan_tab(), "🚪 Port Scanner")
        tabs.addTab(self.create_dns_tab(), "🌐 DNS & Traceroute")
        tabs.addTab(self.create_network_info_tab(), "📋 Network Information")
        tabs.addTab(self.create_developer_tab(), "👨‍💻 Developer")
        main_layout.addWidget(tabs)

        log_group = QGroupBox("Activity Log")
        log_layout = QVBoxLayout()
        self.text_area = QTextEdit()
        self.text_area.setReadOnly(True)
        self.text_area.setMaximumHeight(160)
        self.text_area.setStyleSheet("font-family: 'Cascadia Mono', 'Consolas', monospace; font-size: 13px;")
        log_layout.addWidget(self.text_area)
        log_group.setLayout(log_layout)
        main_layout.addWidget(log_group)

        self.setLayout(main_layout)

    # ---- Tab builders ----
    def create_dashboard_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(15)

        actions_group = QGroupBox("Quick Actions")
        actions_layout = QGridLayout()
        self.quick_scan_btn = QPushButton("Quick Network Scan")
        self.quick_ping_btn = QPushButton("Ping Target")
        self.quick_dns_btn = QPushButton("DNS Lookup")
        self.quick_trace_btn = QPushButton("Traceroute")
        self.health_btn = QPushButton("Run Health Check")
        self.refresh_info_btn = QPushButton("Refresh Network Info")
        self.quick_scan_btn.clicked.connect(self.quick_network_scan)
        self.quick_ping_btn.clicked.connect(self.quick_ping)
        self.quick_dns_btn.clicked.connect(self.quick_dns_lookup)
        self.quick_trace_btn.clicked.connect(self.quick_traceroute)
        self.health_btn.clicked.connect(self.run_health_check)
        self.refresh_info_btn.clicked.connect(self.refresh_network_info)
        actions_layout.addWidget(self.quick_scan_btn, 0, 0)
        actions_layout.addWidget(self.quick_ping_btn, 0, 1)
        actions_layout.addWidget(self.quick_dns_btn, 1, 0)
        actions_layout.addWidget(self.quick_trace_btn, 1, 1)
        actions_layout.addWidget(self.health_btn, 2, 0)
        actions_layout.addWidget(self.refresh_info_btn, 2, 1)
        actions_group.setLayout(actions_layout)
        layout.addWidget(actions_group)

        stats_group = QGroupBox("Live Network Statistics")
        stats_layout = QVBoxLayout()
        self.stats_text = QTextEdit()
        self.stats_text.setReadOnly(True)
        self.stats_text.setMaximumHeight(220)
        self.stats_text.setStyleSheet("font-size: 13px; font-family: 'Cascadia Mono', 'Consolas';")
        stats_layout.addWidget(self.stats_text)
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)

        layout.addStretch()
        tab.setLayout(layout)
        return tab

    def create_scan_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(10)

        scope_group = QGroupBox("Scan Scope")
        scope_layout = QGridLayout()
        scope_layout.addWidget(QLabel("Detected Networks:"), 0, 0)
        self.subnet_combo = QComboBox()
        self.subnet_combo.addItem("Detecting interfaces...", userData="ALL")
        scope_layout.addWidget(self.subnet_combo, 0, 1, 1, 3)
        self.refresh_scope_btn = QPushButton("🔄 Detect")
        self.refresh_scope_btn.clicked.connect(self.refresh_network_info)
        scope_layout.addWidget(self.refresh_scope_btn, 0, 4)

        scope_layout.addWidget(QLabel("Speed Profile:"), 1, 0)
        self.scan_speed_combo = QComboBox()
        self.scan_speed_combo.addItems(["Eco", "Balanced", "Turbo"])
        scope_layout.addWidget(self.scan_speed_combo, 1, 1)

        self.scan_scope_details = QLabel("Awaiting interface data...")
        self.scan_scope_details.setStyleSheet("color: #7dd3fc; font-weight: bold; font-size: 13px;")
        scope_layout.addWidget(self.scan_scope_details, 1, 2, 1, 3)

        scope_group.setLayout(scope_layout)
        layout.addWidget(scope_group)

        scan_btn_layout = QHBoxLayout()
        self.scan_btn = QPushButton("▶ Start Scan")
        self.stop_scan_btn = QPushButton("⏹ Stop Scan")
        self.export_btn = QPushButton("💾 Export Results")
        self.stop_scan_btn.setEnabled(False)
        self.export_btn.setEnabled(False)
        self.scan_btn.clicked.connect(self.on_scan)
        self.stop_scan_btn.clicked.connect(self.on_stop_scan)
        self.export_btn.clicked.connect(self.export_results)
        scan_btn_layout.addWidget(self.scan_btn)
        scan_btn_layout.addWidget(self.stop_scan_btn)
        scan_btn_layout.addWidget(self.export_btn)
        layout.addLayout(scan_btn_layout)

        self.scan_progress = QProgressBar()
        layout.addWidget(self.scan_progress)

        self.stats_label = QLabel("Ready to scan...")
        self.stats_label.setStyleSheet("font-weight: bold; font-size: 14px; color: #7dd3fc;")
        layout.addWidget(self.stats_label)

        results_group = QGroupBox("Scan Results")
        results_layout = QVBoxLayout()
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(2)
        self.results_table.setHorizontalHeaderLabels(["IP Address", "Hostname"])
        self.results_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.results_table.itemDoubleClicked.connect(self.on_table_double_click)
        results_layout.addWidget(self.results_table)
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)

        tab.setLayout(layout)
        return tab

    def create_ping_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(10)

        settings_group = QGroupBox("Ping Settings")
        settings_layout = QHBoxLayout()
        settings_layout.addWidget(QLabel("Rounds:"))
        self.ping_rounds_spin = QSpinBox()
        self.ping_rounds_spin.setRange(1, 10)
        self.ping_rounds_spin.setValue(3)
        settings_layout.addWidget(self.ping_rounds_spin)
        settings_layout.addWidget(QLabel("Pings per round:"))
        self.pings_per_round_spin = QSpinBox()
        self.pings_per_round_spin.setRange(1, 20)
        self.pings_per_round_spin.setValue(5)
        settings_layout.addWidget(self.pings_per_round_spin)
        settings_layout.addStretch()
        settings_group.setLayout(settings_layout)
        layout.addWidget(settings_group)

        ping_btn_layout = QHBoxLayout()
        self.ping_btn = QPushButton("▶ Start Ping")
        self.stop_ping_btn = QPushButton("⏹ Stop Ping")
        self.stop_ping_btn.setEnabled(False)
        self.ping_btn.setStyleSheet("background-color: #4caf50;")
        self.stop_ping_btn.setStyleSheet("background-color: #f44336;")
        self.ping_btn.clicked.connect(self.on_start_ping)
        self.stop_ping_btn.clicked.connect(self.on_stop_ping)
        ping_btn_layout.addWidget(self.ping_btn)
        ping_btn_layout.addWidget(self.stop_ping_btn)
        layout.addLayout(ping_btn_layout)

        output_group = QGroupBox("Ping Output")
        output_layout = QVBoxLayout()
        self.ping_output = QTextEdit()
        self.ping_output.setReadOnly(True)
        self.ping_output.setStyleSheet("font-family: 'Cascadia Mono', 'Consolas'; font-size: 13px;")
        output_layout.addWidget(self.ping_output)
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)
        tab.setLayout(layout)
        return tab

    def create_port_scan_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(10)

        settings_group = QGroupBox("Port Scan Settings")
        settings_layout = QGridLayout()
        settings_layout.addWidget(QLabel("Port Range:"), 0, 0)
        self.port_start_spin = QSpinBox()
        self.port_start_spin.setRange(1, 65535)
        self.port_start_spin.setValue(1)
        settings_layout.addWidget(self.port_start_spin, 0, 1)
        settings_layout.addWidget(QLabel("to"), 0, 2)
        self.port_end_spin = QSpinBox()
        self.port_end_spin.setRange(1, 65535)
        self.port_end_spin.setValue(1000)
        settings_layout.addWidget(self.port_end_spin, 0, 3)
        settings_layout.addWidget(QLabel("Preset:"), 0, 4)
        self.port_preset = QComboBox()
        self.port_preset.addItems(["Custom", "Common (1-1000)", "Well-known (1-1023)", "All (1-65535)"])
        self.port_preset.currentIndexChanged.connect(self.on_port_preset_changed)
        settings_layout.addWidget(self.port_preset, 0, 5)
        settings_group.setLayout(settings_layout)
        layout.addWidget(settings_group)

        port_btn_layout = QHBoxLayout()
        self.port_scan_btn = QPushButton("▶ Start Port Scan")
        self.stop_port_scan_btn = QPushButton("⏹ Stop Port Scan")
        self.stop_port_scan_btn.setEnabled(False)
        self.port_scan_btn.clicked.connect(self.on_start_port_scan)
        self.stop_port_scan_btn.clicked.connect(self.on_stop_port_scan)
        port_btn_layout.addWidget(self.port_scan_btn)
        port_btn_layout.addWidget(self.stop_port_scan_btn)
        layout.addLayout(port_btn_layout)

        self.port_progress = QProgressBar()
        layout.addWidget(self.port_progress)

        output_group = QGroupBox("Port Scan Results")
        output_layout = QVBoxLayout()
        self.port_output = QTextEdit()
        self.port_output.setReadOnly(True)
        self.port_output.setStyleSheet("font-family: 'Cascadia Mono', 'Consolas'; font-size: 13px;")
        output_layout.addWidget(self.port_output)
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)
        tab.setLayout(layout)
        return tab

    def create_dns_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(10)

        dns_group = QGroupBox("DNS Lookup")
        dns_layout = QVBoxLayout()
        lookup_layout = QHBoxLayout()
        self.dns_input = QLineEdit()
        self.dns_input.setPlaceholderText("Enter hostname or IP address")
        self.dns_input.setText(self.ip_input.text())
        self.dns_type_combo = QComboBox()
        self.dns_type_combo.addItems(["Forward DNS (Hostname → IP)", "Reverse DNS (IP → Hostname)"])
        self.dns_lookup_btn = QPushButton("🔍 Lookup")
        self.dns_lookup_btn.clicked.connect(self.on_dns_lookup)
        lookup_layout.addWidget(QLabel("Target:"))
        lookup_layout.addWidget(self.dns_input)
        lookup_layout.addWidget(self.dns_type_combo)
        lookup_layout.addWidget(self.dns_lookup_btn)
        dns_layout.addLayout(lookup_layout)
        self.dns_result = QTextEdit()
        self.dns_result.setReadOnly(True)
        self.dns_result.setMaximumHeight(160)
        self.dns_result.setStyleSheet("font-family: 'Cascadia Mono', 'Consolas'; font-size: 13px;")
        dns_layout.addWidget(QLabel("Result:"))
        dns_layout.addWidget(self.dns_result)
        dns_group.setLayout(dns_layout)
        layout.addWidget(dns_group)

        trace_group = QGroupBox("Traceroute")
        trace_layout = QVBoxLayout()
        trace_input_layout = QHBoxLayout()
        self.trace_input = QLineEdit()
        self.trace_input.setPlaceholderText("Enter target hostname or IP")
        self.trace_input.setText(self.ip_input.text())
        self.trace_hops_spin = QSpinBox()
        self.trace_hops_spin.setRange(1, 64)
        self.trace_hops_spin.setValue(30)
        self.trace_btn = QPushButton("🔍 Traceroute")
        self.trace_btn.clicked.connect(self.on_traceroute)
        trace_input_layout.addWidget(QLabel("Target:"))
        trace_input_layout.addWidget(self.trace_input)
        trace_input_layout.addWidget(QLabel("Max Hops:"))
        trace_input_layout.addWidget(self.trace_hops_spin)
        trace_input_layout.addWidget(self.trace_btn)
        trace_layout.addLayout(trace_input_layout)
        self.trace_output = QTextEdit()
        self.trace_output.setReadOnly(True)
        self.trace_output.setStyleSheet("font-family: 'Cascadia Mono', 'Consolas'; font-size: 13px;")
        trace_layout.addWidget(QLabel("Traceroute Output:"))
        trace_layout.addWidget(self.trace_output)
        trace_group.setLayout(trace_layout)
        layout.addWidget(trace_group)
        layout.addStretch()
        tab.setLayout(layout)
        return tab

    def create_network_info_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(10)

        interfaces_group = QGroupBox("Network Interfaces")
        interfaces_layout = QVBoxLayout()
        self.interfaces_table = QTableWidget()
        self.interfaces_table.setColumnCount(4)
        self.interfaces_table.setHorizontalHeaderLabels(["Interface", "IP Address", "Netmask", "Status"])
        interfaces_layout.addWidget(self.interfaces_table)
        interfaces_group.setLayout(interfaces_layout)
        layout.addWidget(interfaces_group)

        arp_group = QGroupBox("ARP Table")
        arp_layout = QVBoxLayout()
        arp_btn_layout = QHBoxLayout()
        self.refresh_arp_btn = QPushButton("🔄 Refresh ARP Table")
        self.refresh_arp_btn.clicked.connect(self.refresh_arp_table)
        arp_btn_layout.addWidget(self.refresh_arp_btn)
        arp_btn_layout.addStretch()
        arp_layout.addLayout(arp_btn_layout)
        self.arp_table = QTableWidget()
        self.arp_table.setColumnCount(2)
        self.arp_table.setHorizontalHeaderLabels(["IP Address", "MAC Address"])
        arp_layout.addWidget(self.arp_table)
        arp_group.setLayout(arp_layout)
        layout.addWidget(arp_group)
        tab.setLayout(layout)
        return tab

    def create_developer_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(12)

        info_group = QGroupBox("Developer Information")
        info_layout = QGridLayout()
        info_layout.addWidget(QLabel("Name:"), 0, 0)
        name_label = QLabel("Mr.Patchara Al-umaree")
        name_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #4fc3f7;")
        info_layout.addWidget(name_label, 0, 1)
        info_layout.addWidget(QLabel("Email:"), 1, 0)
        email_label = QLabel("<a href='mailto:Patcharaalumaree@gmail.com'>Patcharaalumaree@gmail.com</a>")
        email_label.setOpenExternalLinks(True)
        info_layout.addWidget(email_label, 1, 1)
        info_layout.addWidget(QLabel("Role:"), 2, 0)
        info_layout.addWidget(QLabel("Network Operations & Solutions Architect"), 2, 1)
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)

        vision_group = QGroupBox("Mission & Vision")
        vision_layout = QVBoxLayout()
        vision_text = QTextEdit()
        vision_text.setReadOnly(True)
        vision_text.setMaximumHeight(180)
        vision_text.setPlainText(
            "• Deliver enterprise-grade troubleshooting tools that remain lightweight and portable.\n"
            "• Provide one-click diagnostics so teams can resolve incidents faster.\n"
            "• Keep interfaces focused on clarity, accuracy, and actionable insights.\n"
            "• Continuously expand capabilities to cover the entire network lifecycle."
        )
        vision_layout.addWidget(vision_text)
        vision_group.setLayout(vision_layout)
        layout.addWidget(vision_group)

        focus_group = QGroupBox("Current Focus Areas")
        focus_layout = QVBoxLayout()
        focus_layout.addWidget(QLabel("✔ Unified network scanning across all adapters"))
        focus_layout.addWidget(QLabel("✔ Rapid health checks and smart logging"))
        focus_layout.addWidget(QLabel("✔ Modular design for future automations"))
        focus_group.setLayout(focus_layout)
        layout.addWidget(focus_group)

        layout.addStretch()
        tab.setLayout(layout)
        return tab

    # ---- Quick actions ----
    def quick_network_scan(self):
        self.on_scan()

    def quick_ping(self):
        self.on_start_ping()

    def quick_dns_lookup(self):
        self.dns_input.setText(self.ip_input.text())
        self.on_dns_lookup()

    def quick_traceroute(self):
        self.trace_input.setText(self.ip_input.text())
        self.on_traceroute()

    def run_health_check(self):
        target = self.ip_input.text().strip() or self.local_ip
        tests = [
            ("Loopback", "127.0.0.1"),
            ("Selected Target", target),
            ("Internet (8.8.8.8)", "8.8.8.8"),
        ]
        self.append_log(f"[{self.get_timestamp()}] Running quick health check...\n")
        all_ok = True
        for label, host in tests:
            result = ping_once(host, timeout_ms=800)
            status = "PASS" if result else "FAIL"
            all_ok = all_ok and result
            color = "green" if result else "red"
            self.append_log(f"[{self.get_timestamp()}] {label}: <font color='{color}'>{status}</font> ({host})\n")

        if HAS_PSUTIL:
            try:
                net_io = psutil.net_io_counters()
                self.append_log(
                    f"[{self.get_timestamp()}] Traffic totals - Sent: {net_io.bytes_sent:,} bytes, "
                    f"Received: {net_io.bytes_recv:,} bytes\n"
                )
            except Exception:
                pass

        if all_ok:
            self.card3_value.setText("🟢 Healthy Link")
            self.card3_value.setStyleSheet("color: #4caf50; font-size: 14px; font-weight: bold;")
            QMessageBox.information(self, "Health Check", "All connectivity tests passed.")
        else:
            self.card3_value.setText("🟠 Attention")
            self.card3_value.setStyleSheet("color: #ffb74d; font-size: 14px; font-weight: bold;")
            QMessageBox.warning(self, "Health Check", "One or more connectivity tests failed. See log for details.")

    # ---- Network info helpers ----
    def refresh_network_info(self):
        interfaces = get_network_interfaces()
        self.interfaces_table.setRowCount(len(interfaces))
        self.subnets = []
        self.subnet_lookup = {}
        total_hosts = 0
        for row, iface in enumerate(interfaces):
            self.interfaces_table.setItem(row, 0, QTableWidgetItem(iface["name"]))
            if iface["addresses"]:
                self.interfaces_table.setItem(row, 1, QTableWidgetItem(iface["addresses"][0]["ip"]))
                self.interfaces_table.setItem(row, 2, QTableWidgetItem(iface["addresses"][0]["netmask"]))
            else:
                self.interfaces_table.setItem(row, 1, QTableWidgetItem("N/A"))
                self.interfaces_table.setItem(row, 2, QTableWidgetItem("N/A"))
            status = "🟢 Up" if iface["is_up"] else "🔴 Down"
            self.interfaces_table.setItem(row, 3, QTableWidgetItem(status))

            for addr in iface.get("addresses", []):
                try:
                    network = ipaddress.IPv4Network(f"{addr['ip']}/{addr['netmask']}", strict=False)
                except Exception:
                    continue
                host_count = max(0, network.num_addresses - 2)
                total_hosts += host_count
                key = f"{iface['name']}|{network}"
                subnet_entry = {
                    "name": iface["name"],
                    "network": network,
                    "cidr": str(network),
                    "host_count": host_count,
                    "key": key,
                }
                self.subnets.append(subnet_entry)
                self.subnet_lookup[key] = subnet_entry

        if hasattr(self, "subnet_combo"):
            self.populate_subnet_combo(total_hosts)

        self.interfaces_table.resizeColumnsToContents()
        self.refresh_arp_table()
        self.update_network_stats()
        self.append_log(f"[{self.get_timestamp()}] Network information refreshed.\n")

    def populate_subnet_combo(self, total_hosts=0):
        if not hasattr(self, "subnet_combo"):
            return
        current_data = self.subnet_combo.currentData()
        self.subnet_combo.blockSignals(True)
        self.subnet_combo.clear()
        if self.subnets:
            self.subnet_combo.addItem("All detected networks", userData="ALL")
            for subnet in self.subnets:
                label = f"{subnet['name']} • {subnet['cidr']} ({subnet['host_count']} hosts)"
                self.subnet_combo.addItem(label, userData=subnet["key"])
        else:
            self.subnet_combo.addItem("No active IPv4 interfaces found", userData=None)
        if current_data is not None:
            idx = self.subnet_combo.findData(current_data)
            if idx >= 0:
                self.subnet_combo.setCurrentIndex(idx)
        self.subnet_combo.blockSignals(False)
        summary = (
            f"Detected {len(self.subnets)} networks / {total_hosts} hosts"
            if self.subnets
            else "No IPv4 networks detected"
        )
        self.scan_scope_details.setText(summary)

    def build_scan_targets(self):
        if not self.subnets:
            return []
        data = self.subnet_combo.currentData()
        if data == "ALL" or data is None:
            selected_subnets = self.subnets
        elif isinstance(data, str):
            subnet = self.subnet_lookup.get(data)
            selected_subnets = [subnet] if subnet else []
        else:
            selected_subnets = []

        targets = []
        truncated = []
        for subnet in selected_subnets:
            try:
                hosts_iter = subnet["network"].hosts()
            except Exception:
                hosts_iter = []
            limited_hosts = [str(ip) for ip in islice(hosts_iter, MAX_HOSTS_PER_NETWORK)]
            targets.extend(limited_hosts)
            if subnet["host_count"] > MAX_HOSTS_PER_NETWORK:
                truncated.append(subnet["cidr"])

        unique_targets = sorted(set(targets), key=lambda ip: socket.inet_aton(ip))
        if len(unique_targets) > MAX_TOTAL_HOSTS:
            unique_targets = unique_targets[:MAX_TOTAL_HOSTS]
            truncated.append("global-total")

        details = f"Scope: {len(unique_targets)} hosts selected"
        if truncated:
            details += " (limits applied)"
        self.scan_scope_details.setText(details)

        if truncated:
            self.append_log(
                f"[{self.get_timestamp()}] Scan limited to {len(unique_targets)} hosts "
                f"to keep the UI responsive.\n"
            )

        return unique_targets

    def refresh_arp_table(self):
        arp_entries = get_arp_table()
        self.arp_table.setRowCount(len(arp_entries))
        for row, entry in enumerate(arp_entries):
            self.arp_table.setItem(row, 0, QTableWidgetItem(entry["ip"]))
            self.arp_table.setItem(row, 1, QTableWidgetItem(entry["mac"]))
        self.arp_table.resizeColumnsToContents()

    def update_network_stats(self):
        stats_text = f"Network Statistics - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        stats_text += "=" * 50 + "\n"
        if HAS_PSUTIL:
            try:
                net_io = psutil.net_io_counters()
                stats_text += f"Bytes Sent: {net_io.bytes_sent:,}\n"
                stats_text += f"Bytes Received: {net_io.bytes_recv:,}\n"
                stats_text += f"Packets Sent: {net_io.packets_sent:,}\n"
                stats_text += f"Packets Received: {net_io.packets_recv:,}\n"
                stats_text += f"Errors In: {net_io.errin}\n"
                stats_text += f"Errors Out: {net_io.errout}\n"
                stats_text += f"Drops In: {net_io.dropin}\n"
                stats_text += f"Drops Out: {net_io.dropout}\n"
            except Exception:
                stats_text += "Unable to retrieve network statistics.\n"
        else:
            stats_text += "Install psutil for detailed statistics.\nRun: pip install psutil\n"

        arp_entries = get_arp_table()
        stats_text += f"\nARP Table Entries: {len(arp_entries)}\n"
        interfaces = get_network_interfaces()
        stats_text += f"Active Interfaces: {len(interfaces)}\n"
        self.stats_text.setPlainText(stats_text)

    def on_port_preset_changed(self, index):
        if index == 1:  # Common
            self.port_start_spin.setValue(1)
            self.port_end_spin.setValue(1000)
        elif index == 2:  # Well-known
            self.port_start_spin.setValue(1)
            self.port_end_spin.setValue(1023)
        elif index == 3:  # All
            self.port_start_spin.setValue(1)
            self.port_end_spin.setValue(65535)

    # ---------- scan handlers ----------
    def on_scan(self):
        self.results_table.setRowCount(0)
        self.scan_results = []
        targets = self.build_scan_targets()
        if not targets:
            QMessageBox.warning(self, "Network Scope", "No IPv4 targets detected. Refresh network info first.")
            return

        if len(targets) > LARGE_SCAN_CONFIRM_THRESHOLD:
            reply = QMessageBox.question(
                self,
                "Confirm Large Scan",
                f"This will scan {len(targets)} hosts. Continue?",
                QMessageBox.Yes | QMessageBox.No,
            )
            if reply == QMessageBox.No:
                return

        speed_map = {"Eco": 80, "Balanced": 200, "Turbo": 400}
        speed_profile = self.scan_speed_combo.currentText()
        max_workers = speed_map.get(speed_profile, 300)

        scope_label = self.subnet_combo.currentText()
        self.append_log(f"[{self.get_timestamp()}] Preparing to scan {len(targets)} hosts ({scope_label})...\n")
        self.scan_btn.setEnabled(False)
        self.stop_scan_btn.setEnabled(True)
        self.export_btn.setEnabled(False)
        self.scan_progress.setValue(0)
        self.stats_label.setText("Scanning...")
        
        self.scan_thread = ScanWorker(targets, max_workers=max_workers, scope_label=scope_label)
        self.scan_thread.progress.connect(self.append_log)
        self.scan_thread.progress_value.connect(self.scan_progress.setValue)
        self.scan_thread.found_ips.connect(self.show_scan_results)
        self.scan_thread.scan_stats.connect(self.show_scan_stats)
        self.scan_thread.start()

    def on_stop_scan(self):
        if self.scan_thread:
            self.scan_thread.stop()
            self.scan_thread = None
            self.stop_scan_btn.setEnabled(False)
            self.scan_btn.setEnabled(True)
            self.append_log(f"[{self.get_timestamp()}] Requested to stop scan...\n")

    def show_scan_results(self, ips):
        self.scan_results = ips
        self.results_table.setRowCount(len(ips))
        for row, (ip, hostname) in enumerate(ips):
            self.results_table.setItem(row, 0, QTableWidgetItem(ip))
            self.results_table.setItem(row, 1, QTableWidgetItem(hostname))
        self.results_table.resizeColumnsToContents()
        self.scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)
        self.export_btn.setEnabled(len(ips) > 0)
        self.scan_thread = None

    def show_scan_stats(self, stats):
        stats_text = f"Scanned: {stats['total_scanned']} | Found: {stats['found']} | Time: {stats['elapsed_time']:.2f}s"
        self.stats_label.setText(stats_text)

    def on_table_double_click(self, item):
        row = item.row()
        ip = self.results_table.item(row, 0).text()
        self.ip_input.setText(ip)
        self.dns_input.setText(ip)
        self.trace_input.setText(ip)

    def export_results(self):
        if not self.scan_results:
            QMessageBox.warning(self, "Export Error", "No results to export.")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Export Scan Results",
            f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            "CSV Files (*.csv);;Text Files (*.txt);;JSON Files (*.json)",
        )

        if filename:
            try:
                if filename.endswith(".csv"):
                    with open(filename, "w", newline="", encoding="utf-8") as f:
                        writer = csv.writer(f)
                        writer.writerow(["IP Address", "Hostname", "Scan Date"])
                        for ip, hostname in self.scan_results:
                            writer.writerow([ip, hostname, datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
                elif filename.endswith(".json"):
                    data = {
                        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "results": [{"ip": ip, "hostname": hostname} for ip, hostname in self.scan_results],
                    }
                    with open(filename, "w", encoding="utf-8") as f:
                        json.dump(data, f, indent=2)
                else:
                    with open(filename, "w", encoding="utf-8") as f:
                        f.write(f"Network Scan Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write("=" * 50 + "\n")
                        for ip, hostname in self.scan_results:
                            f.write(f"{ip}\t{hostname}\n")
                QMessageBox.information(self, "Export Success", f"Results exported to {filename}")
                self.append_log(f"[{self.get_timestamp()}] Results exported to {filename}\n")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export: {e}")

    # ---------- ping handlers ----------
    def on_start_ping(self):
        target = self.ip_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Input Error", "Please enter or select a target IP.")
            return
        self.ping_output.clear()
        self.ping_btn.setEnabled(False)
        self.stop_ping_btn.setEnabled(True)
        
        rounds = self.ping_rounds_spin.value()
        pings_per_round = self.pings_per_round_spin.value()
        
        self.ping_thread = PingWorker(target, rounds, pings_per_round)
        self.ping_thread.output.connect(self.append_ping_output)
        self.ping_thread.finished_signal.connect(self.on_ping_finished)
        self.ping_thread.start()

    def on_stop_ping(self):
        if self.ping_thread:
            self.ping_thread.stop()
            self.append_ping_output("Stopping ping...<br>")
            self.stop_ping_btn.setEnabled(False)

    def on_ping_finished(self, summary_html):
        self.append_ping_output(summary_html)
        self.ping_btn.setEnabled(True)
        self.stop_ping_btn.setEnabled(False)
        self.ping_thread = None

    def append_ping_output(self, message):
        self.ping_output.append(message)
        self.ping_output.moveCursor(QTextCursor.End)

    # ---------- port scan handlers ----------
    def on_start_port_scan(self):
        target = self.ip_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Input Error", "Please enter a target IP.")
            return
        
        start_port = self.port_start_spin.value()
        end_port = self.port_end_spin.value()
        
        if start_port > end_port:
            QMessageBox.warning(self, "Input Error", "Start port must be less than or equal to end port.")
            return
        
        ports = list(range(start_port, end_port + 1))
        if len(ports) > 10000:
            reply = QMessageBox.question(
                self, "Confirm", 
                f"Scanning {len(ports)} ports may take a long time. Continue?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.No:
                return
        
        self.port_output.clear()
        self.port_scan_btn.setEnabled(False)
        self.stop_port_scan_btn.setEnabled(True)
        self.port_progress.setValue(0)
        
        self.port_scan_thread = PortScanWorker(target, ports)
        self.port_scan_thread.progress.connect(self.append_port_output)
        self.port_scan_thread.progress_value.connect(self.port_progress.setValue)
        self.port_scan_thread.found_ports.connect(self.on_port_scan_finished)
        self.port_scan_thread.start()

    def on_stop_port_scan(self):
        if self.port_scan_thread:
            self.port_scan_thread.stop()
            self.append_port_output("Stopping port scan...\n")
            self.stop_port_scan_btn.setEnabled(False)

    def on_port_scan_finished(self, open_ports):
        if open_ports:
            self.append_port_output(f"\n[{self.get_timestamp()}] Open ports: {', '.join(map(str, open_ports))}\n")
        else:
            self.append_port_output(f"\n[{self.get_timestamp()}] No open ports found.\n")
        self.port_scan_btn.setEnabled(True)
        self.stop_port_scan_btn.setEnabled(False)
        self.port_scan_thread = None

    def append_port_output(self, message):
        self.port_output.append(message)
        self.port_output.moveCursor(QTextCursor.End)

    # ---------- DNS / traceroute handlers ----------
    def on_dns_lookup(self):
        target = self.dns_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Input Error", "Please enter a target.")
            return
        lookup_type = "forward" if self.dns_type_combo.currentIndex() == 0 else "reverse"
        self.dns_result.clear()
        self.dns_result.append(f"Looking up: {target} ({lookup_type})...")
        self.dns_thread = DNSLookupWorker(target, lookup_type)
        self.dns_thread.result.connect(self.dns_result.setPlainText)
        self.dns_thread.start()

    def on_traceroute(self):
        target = self.trace_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Input Error", "Please enter a target.")
            return
        self.trace_output.clear()
        self.trace_output.append(f"Traceroute to {target}...\n")
        self.trace_btn.setEnabled(False)
        self.traceroute_thread = TracerouteWorker(target, self.trace_hops_spin.value())
        self.traceroute_thread.output.connect(self.append_trace_output)
        self.traceroute_thread.finished.connect(lambda: self.trace_btn.setEnabled(True))
        self.traceroute_thread.start()

    def append_trace_output(self, message):
        self.trace_output.append(message)
        self.trace_output.moveCursor(QTextCursor.End)

    def get_timestamp(self):
        return datetime.now().strftime("%H:%M:%S")

    def append_log(self, message):
        self.text_area.append(message)
        self.text_area.moveCursor(QTextCursor.End)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = PingApp()
    win.show()
    sys.exit(app.exec_())
