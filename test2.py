import sys
import subprocess
import time
import socket
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTextEdit, QLabel, QLineEdit, QListWidget, QMessageBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QTextCursor


# --------- Utility: get local IP (not 127.0.0.1) ----------
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


# --------- Ping function -------------
def ping_once(host, timeout_ms=1000):
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", host, "-n", "1", "-w", str(timeout_ms)]
    else:
        timeout_s = str(max(1, int(timeout_ms / 1000)))
        cmd = ["ping", "-c", "1", "-W", timeout_s, host]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True)
        return res.returncode == 0
    except Exception:
        return False


# --------- Scan Thread -----------
class ScanWorker(QThread):
    progress = pyqtSignal(str)
    found_ips = pyqtSignal(list)

    def __init__(self, network_prefix, max_workers=100):
        super().__init__()
        self.network_prefix = network_prefix
        self.max_workers = max_workers
        self._stopped = False

    def run(self):
        ips_found = []
        self.progress.emit(f"Starting scan on {self.network_prefix}0/24 ...\n")
        addresses = [f"{self.network_prefix}{i}" for i in range(1, 255)]
        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = {ex.submit(ping_once, addr): addr for addr in addresses}
            completed = 0
            total = len(futures)
            for fut in as_completed(futures):
                addr = futures[fut]
                completed += 1
                try:
                    alive = fut.result()
                except Exception:
                    alive = False
                if alive:
                    ips_found.append(addr)
                    self.progress.emit(f"[+] {addr} is alive\n")
                if completed % 20 == 0:
                    self.progress.emit(f"Scanned {completed}/{total}...\n")
                if self._stopped:
                    self.progress.emit("Scan stopped.\n")
                    break
        self.progress.emit("Scan finished.\n")
        self.found_ips.emit(sorted(ips_found))

    def stop(self):
        self._stopped = True


# --------- Ping Thread -----------
class PingWorker(QThread):
    output = pyqtSignal(str)
    finished_signal = pyqtSignal(str)  # ✅ เปลี่ยนให้ส่งผลรวม

    def __init__(self, target):
        super().__init__()
        self.target = target
        self._stopped = False

    def run(self):
        system = platform.system().lower()
        overall_success = 0
        overall_total = 0

        for round_num in range(3):
            if self._stopped:
                self.output.emit("<font color='gray'><b>Ping stopped by user.</b></font><br>")
                break

            self.output.emit(f"<b>--- Round {round_num + 1} ---</b><br>")
            success_count = 0
            total_count = 5
            overall_total += total_count

            if system == "windows":
                cmd = ["ping", self.target, "-n", "5"]
            else:
                cmd = ["ping", "-c", "5", self.target]

            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                for line in proc.stdout:
                    if self._stopped:
                        proc.kill()
                        break
                    line = line.strip()
                    if line:
                        if "Reply" in line or "bytes from" in line:
                            success_count += 1
                        self.output.emit(line + "<br>")
                proc.wait()
            except Exception as e:
                self.output.emit(f"<font color='red'>Ping command failed: {e}</font><br>")

            overall_success += success_count
            # summarize round
            loss_percent = int(((total_count - success_count) / total_count) * 100)
            if success_count == total_count:
                result = f"<font color='green'>✅ Round {round_num+1} Result: Host reachable (0% loss)</font><br>"
            elif success_count > 0:
                result = f"<font color='orange'>🟡 Round {round_num+1} Result: Partial success ({loss_percent}% loss)</font><br>"
            else:
                result = f"<font color='red'>❌ Round {round_num+1} Result: Host unreachable (100% loss)</font><br>"
            self.output.emit(result)

            # wait 1s before next round
            if round_num < 2 and not self._stopped:
                for _ in range(1):
                    if self._stopped:
                        break
                    time.sleep(1)

        # --- ส่งผลรวมสุดท้ายตอนจบ ---
        overall_loss = int(((overall_total - overall_success) / overall_total) * 100)
        if overall_success == overall_total:
            final_result = f"<font color='green'><b>✅ Ping Summary: Host fully reachable (0% loss)</b></font><br>"
        elif overall_success > 0:
            final_result = f"<font color='orange'><b>🟡 Ping Summary: Partial success ({overall_loss}% loss)</b></font><br>"
        else:
            final_result = f"<font color='red'><b>❌ Ping Summary: Host unreachable (100% loss)</b></font><br>"

        self.finished_signal.emit(final_result)  # ส่งกลับ GUI

    def stop(self):
        self._stopped = True

# ---------------- Main GUI ----------------
class PingApp(QWidget):
    def __init__(self):
        super().__init__()
        self.scan_thread = None
        self.ping_thread = None
        self.local_ip = get_local_ip()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Ping Scanner (no nmap)")
        self.setGeometry(400, 250, 600, 420)

        layout = QVBoxLayout()

        # --- Host IP (read-only) ---
        host_line = QHBoxLayout()
        host_label = QLabel("Host IP:")
        self.host_ip_display = QLineEdit(self.local_ip)
        self.host_ip_display.setReadOnly(True)
        host_line.addWidget(host_label)
        host_line.addWidget(self.host_ip_display)
        layout.addLayout(host_line)

        # --- Target input and Scan ---
        ip_line = QHBoxLayout()
        # Target IP input
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Enter target IP (or select from scan results)")
        self.ip_input.setText("10.101.10.240")  # ✅ ตั้งค่าเริ่มต้น

        self.scan_btn = QPushButton("Scan")
        self.stop_scan_btn = QPushButton("Stop")
        self.stop_scan_btn.setEnabled(False)
        self.scan_btn.clicked.connect(self.on_scan)
        self.stop_scan_btn.clicked.connect(self.on_stop_scan)
        ip_line.addWidget(QLabel("Target IP:"))
        ip_line.addWidget(self.ip_input)
        ip_line.addWidget(self.scan_btn)
        ip_line.addWidget(self.stop_scan_btn)
        layout.addLayout(ip_line)

        # --- Scan results ---
        self.ip_list = QListWidget()
        self.ip_list.setMaximumHeight(80)
        self.ip_list.itemClicked.connect(self.select_ip)
        layout.addWidget(QLabel("Scan Results:"))
        layout.addWidget(self.ip_list)

        # --- Log window ---
        self.text_area = QTextEdit()
        self.text_area.setReadOnly(True)
        self.text_area.setMaximumHeight(80)
        layout.addWidget(QLabel("Log:"))
        layout.addWidget(self.text_area)

        # --- Control buttons ---
        btn_line = QHBoxLayout()
        self.ping_btn = QPushButton("Start Ping")
        self.stop_ping_btn = QPushButton("Stop Ping")
        self.stop_ping_btn.setEnabled(False)
        self.ping_btn.clicked.connect(self.on_start_ping)
        self.stop_ping_btn.clicked.connect(self.on_stop_ping)
        btn_line.addWidget(self.ping_btn)
        btn_line.addWidget(self.stop_ping_btn)
        layout.addLayout(btn_line)

        self.setLayout(layout)

    # ---------- scan handlers ----------
    def on_scan(self):
        self.ip_list.clear()
        self.text_area.append("Preparing to scan...\n")
        local_ip = self.local_ip
        if local_ip.startswith("127.") or local_ip == "0.0.0.0":
            QMessageBox.warning(self, "Network Error", "Cannot determine local IP.")
            return
        parts = local_ip.split(".")
        prefix = ".".join(parts[0:3]) + "."
        self.text_area.append(f"Local IP: {local_ip} -> scanning {prefix}0/24\n")
        self.scan_btn.setEnabled(False)
        self.stop_scan_btn.setEnabled(True)
        self.scan_thread = ScanWorker(prefix)
        self.scan_thread.progress.connect(self.append_log)
        self.scan_thread.found_ips.connect(self.show_scan_results)
        self.scan_thread.start()

    def on_stop_scan(self):
        if self.scan_thread:
            self.scan_thread.stop()
            self.scan_thread = None
            self.stop_scan_btn.setEnabled(False)
            self.scan_btn.setEnabled(True)
            self.append_log("Requested to stop scan...\n")

    def show_scan_results(self, ips):
        self.ip_list.clear()
        if not ips:
            self.append_log("No hosts responded.\n")
        else:
            for ip in ips:
                self.ip_list.addItem(ip)
            self.append_log(f"Found {len(ips)} hosts.\n")
        self.scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)

    # ---------- ping handlers ----------
    def on_start_ping(self):
        target = self.ip_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Input Error", "Please enter or select a target IP.")
            return
        self.text_area.clear()
        self.ping_btn.setEnabled(False)
        self.stop_ping_btn.setEnabled(True)
        self.ping_thread = PingWorker(target)
        self.ping_thread.output.connect(self.append_log)
        self.ping_thread.finished_signal.connect(self.on_ping_finished)
        self.ping_thread.start()

    def on_stop_ping(self):
        if self.ping_thread:
            self.ping_thread.stop()
            self.append_log("Stopping ping...\n")
            self.stop_ping_btn.setEnabled(False)

    def on_ping_finished(self, summary_html):
        self.append_log(summary_html)   # แสดงผลรวม
        self.ping_btn.setEnabled(True)
        self.stop_ping_btn.setEnabled(False)
        self.ping_thread = None


    def select_ip(self, item):
        self.ip_input.setText(item.text())

    # -------- append_log ----------
    def append_log(self, message):
        self.text_area.append(message)
        self.text_area.moveCursor(QTextCursor.End)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = PingApp()
    win.show()
    sys.exit(app.exec_())
