"""
Log-Based Threat Detection Tool - GUI (Tkinter + ttkbootstrap)
Enhanced: Rule Management Tab (Option 1 layout)

Features added:
- Rule Management tab with full-width rule table
- Inline Add Rule with duplicate-by-name and duplicate-by-pattern checks
- Remove Rule with confirmation popup
- Auto-refresh of table + combobox on changes
- Existing detection GUI features retained
- Export separate PDF report per attack type (reportlab)
FIXED: Implemented HTML escaping for log snippets to prevent ReportLab XML parsing errors from XSS payloads.
ADDED: Export Reports button to the main detection toolbar.
MODIFIED: Added administrator/root privilege check at startup.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import ttkbootstrap as tb
from ttkbootstrap.scrolled import ScrolledText
import re
from collections import OrderedDict
from html import unescape as html_unescape, escape as html_escape # MODIFIED: ADDED html_escape
from urllib.parse import unquote as url_unquote
import base64
import json
import csv
import os
import platform # NEW: For OS detection
import ctypes # NEW: For Windows admin check
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle # MODIFIED: ADDED ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch #Required for proper paragraph definition
import datetime
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
import textwrap
import mplcursors
import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
import hashlib
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import time
import urllib.parse
import html



BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BLOCK_FILE = os.path.join(BASE_DIR, "blocked_ips.txt")



def load_blocked_ips():
    if not os.path.exists(BLOCK_FILE):
        return set()

    with open(BLOCK_FILE) as f:
        return set(line.strip() for line in f if line.strip())


def add_blocked_ip(ip):
    path = os.path.join(os.path.dirname(__file__), "blocked_ips.txt")
    with open(path, "a") as f:
        f.write(ip + "\n")


def load_ioc_ips():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(base_dir, "ioc_ips.txt")

    try:
        with open(path, "r") as f:
            ips = set(line.strip() for line in f if line.strip())
            print(f"[IOC] Loaded {len(ips)} IPs")
            return ips
    except FileNotFoundError:
        print("[IOC] ioc_ips.txt NOT FOUND")
        return set()



# --------------------
# EMAIL CONFIG (RUNTIME)
# --------------------

EMAIL_ENABLED = True
EMAIL_ALREADY_SENT = False

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

SENDER_EMAIL = ""
SENDER_PASSWORD = ""
RECEIVER_EMAIL = ""


def update_email_settings(enabled, sender, password, receiver):
    global EMAIL_ENABLED, SENDER_EMAIL, SENDER_PASSWORD, RECEIVER_EMAIL
    EMAIL_ENABLED = enabled
    SENDER_EMAIL = sender
    SENDER_PASSWORD = password
    RECEIVER_EMAIL = receiver


def reset_email_flag():
    global EMAIL_ALREADY_SENT
    EMAIL_ALREADY_SENT = False


def send_email_alert(subject, body):
    global EMAIL_ALREADY_SENT

    if EMAIL_ALREADY_SENT or not EMAIL_ENABLED:
        return

    if not SENDER_EMAIL or not SENDER_PASSWORD or not RECEIVER_EMAIL:
        print("Email settings incomplete")
        return

    try:
        msg = MIMEMultipart()
        msg["From"] = SENDER_EMAIL
        msg["To"] = RECEIVER_EMAIL
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)
        server.quit()

        EMAIL_ALREADY_SENT = True
        print("Email sent")

    except Exception as e:
        print("Email failed:", e)

# --------------------
# Default Patterns + Severity
# --------------------
DEFAULT_PATTERNS = OrderedDict([
    ("Failed Login",         (r"\b(failed|unauthorized|invalid password|authentication failure|login failed)\b", "MEDIUM")),
    ("SQL Injection",        (r"(union\s+select|select\s+\*|drop\s+table|--|;--|\bOR\b.+\=.+)", "HIGH")),
    ("XSS",                  (r"(<script\b|javascript:|onerror=|onload=)", "HIGH")),
    ("Directory Traversal",  (r"(\.\./|\.\.\\|/etc/passwd)", "HIGH")),
    ("Error/Denied",         (r"\b(error|denied|forbidden|403|500|502|401)\b", "LOW")),
    ("Multiple Failed Login", (r"\b(failed login|authentication failure|invalid user)\b", "MEDIUM")),
    ("Credential Stuffing Probe", (r"(username=|login=|user=).{1,120}(password=|pass=)", "HIGH")),
    ("Command Injection / Shell", (r"(;|\|\||&&|\$\(.*\)|wget\b|curl\b|\|\s*sh\b|\bexec\b)", "HIGH")),
    ("Local File Inclusion (LFI)", (r"(\.\./\.\./|\.\.\\\.\.|/etc/passwd)", "HIGH")),
    ("SSRF / Internal URL fetch", (r"(http://127\.0\.0\.1|localhost|169\.254|0\.0\.0\.0)", "HIGH")),
    ("Encoded Path Traversal", (r"(%2e%2e%2f|%252e%252e%252f)", "HIGH")),
    ("Sensitive File Access", (r"(/etc/passwd|/etc/shadow|wp-config.php|id_rsa|\.git/)", "HIGH")),
    ("Discovery Scan", (r"(/robots\.txt|/sitemap\.xml|\.git/)", "LOW")),
    ("Repeated 4xx/5xx", (r"\b(401|403|404|500|502|503|504)\b", "LOW")),
    ("Open Redirect", (r"(redirect=|return=|next=)\s*(https?://)", "MEDIUM")),
])

# --------------------
# Log parsing helpers
# --------------------
APACHE_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - '
    r'\[(?P<time>.*?)\] "(?P<request>.*?)" (?P<status>\d{3})'
)

def parse_log_line(line: str):
    line = line.rstrip("\n")
    m = APACHE_PATTERN.search(line)
    if m:
        return (m.group("time"), m.group("ip"), m.group("request"), m.group("status"), line)
    ip_m = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
    timestamp_m = re.search(r'(\d{4}[-/]\d{2}[-/]\d{2}[T\s]\d{2}:\d{2}:\d{2})', line)
    ts = timestamp_m.group(1) if timestamp_m else "-"
    ip = ip_m.group(1) if ip_m else "N/A"
    req = line[:120].strip() + ("..." if len(line) > 120 else "")
    return (ts, ip, req, "-", line)

def normalize_input(text):

    """
    Decode URL-encoded and HTML-escaped payloads
    """
    if not text:
        return text

    try:
        # URL decode (%3C, %2F, etc.)
        decoded = urllib.parse.unquote(text)

        # HTML unescape (&lt; &gt; &amp;)
        decoded = html.unescape(decoded)

        return decoded
    except Exception:
        return text


# --------------------
# Normalization / decoding utilities
# --------------------
def try_base64_decode(s: str):
    tokens = re.findall(r'([A-Za-z0-9+/]{12,}={0,2})', s)
    decoded_parts = []
    for tok in tokens:
        try:
            b = base64.b64decode(tok, validate=True)
            if all((32 <= bch <= 126) or bch in (9,10,13) for bch in b):
                decoded_parts.append(b.decode('utf-8', errors='ignore'))
        except Exception:
            continue
    return " ".join(decoded_parts) if decoded_parts else ""

def normalize_line(line: str):
    parts = [line]
    try:
        u = url_unquote(line)
        if u != line:
            parts.append(u)
    except Exception:
        pass
    try:
        h = html_unescape(line)
        if h != line:
            parts.append(h)
    except Exception:
        pass
    b = try_base64_decode(line)
    if b:
        parts.append(b)
    seen = set()
    combined = []
    for p in parts:
        if p not in seen:
            combined.append(p)
            seen.add(p)
    return " \n ".join(combined)

# --------------------
# Detection engine
# --------------------
class RuleSet:
    def __init__(self):
        self.patterns = OrderedDict(DEFAULT_PATTERNS)
        self.blocked_ips = load_blocked_ips()
        self.compiled_rules = self._compile_rules()

    def _compile_rules(self):
        compiled = []
        for name, (pattern, severity) in self.patterns.items():
            try:
                cregex = re.compile(pattern, re.IGNORECASE)
                compiled.append((name, cregex, severity))
            except re.error:
                continue
        return compiled

    def add_rule(self, name, regex, severity="LOW"):
        self.patterns[name] = (regex, severity.upper())
        self.compiled_rules = self._compile_rules()

    def remove_rule(self, name):
        if name in self.patterns:
            del self.patterns[name]
            self.compiled_rules = self._compile_rules()

    def save_to_file(self, path):
        with open(path, "w") as f:
            json.dump(self.patterns, f, indent=2)

    def load_from_file(self, path):
        with open(path, "r") as f:
            data = json.load(f)
        self.patterns = OrderedDict((k, tuple(v)) for k, v in data.items())
        self.compiled_rules = self._compile_rules()
def detect_threats(normalized_line: str, rules: RuleSet):
    results = []
    for name, cregex, severity in rules.compiled_rules:
        if cregex.search(normalized_line):
            results.append((name, severity))
    return results

# --------------------
# GUI Class
# --------------------
class LogThreatGUI:
    def __init__(self, root):
        self.ioc_ips = load_ioc_ips()
        self.blocked_ips = load_blocked_ips()
        self.blocked_ips = set()

        if os.path.exists(BLOCK_FILE):
            with open(BLOCK_FILE, "r") as f:
                for line in f:
                    ip = line.strip()
                    if ip:
                        self.blocked_ips.add(ip)


        self.root = root
        self.root.title("Log Based Threat Detection - Tool")
        self.root.geometry("1200x780")
        self.style = tb.Style("cyborg")
        self.rules = RuleSet()
        self.current_file = None
        self.detections = []
        self.detection_history = []
        self.last_email_time = 0
        EMAIL_COOLDOWN = 300   # 5 minutes
        self.detected_logs = []



        self._build_menu()
        self._build_notebook()
        # --------------------
        # Dashboard Figures
        # --------------------

        # Side overview pie (right side)
        self.fig_sidepie = Figure(figsize=(3,3))
        self.ax_sidepie = self.fig_sidepie.add_subplot(111)
        self.canvas_sidepie = FigureCanvasTkAgg(
            self.fig_sidepie,
            master=self.tab_dashboard
        )
        self.canvas_sidepie.get_tk_widget().pack(side="right", padx=6)
        


        # Log Threat Trend chart (bottom)
        self.fig_line = Figure(figsize=(10,3))
        self.ax_line = self.fig_line.add_subplot(111)
        self.canvas_line = FigureCanvasTkAgg(
            self.fig_line,
            master=self.tab_dashboard
        )
        self.canvas_line.get_tk_widget().pack(side="bottom", fill="x", pady=6)

        self._configure_tree_tags()
        self.status_var.set("Ready")

    def _build_menu(self):
        menubar = tk.Menu(self.root)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Open Log File...", command=self.open_file)
        filemenu.add_command(label="Export Results to CSV...", command=self.export_csv)
        # Per-attack-type export (one PDF per attack type)
        filemenu.add_command(label="Export Reports (Per Attack Type)...", command=self.export_pdf_per_attack_type)
        filemenu.add_separator()
        filemenu.add_command(label="Save Rules...", command=self.save_rules)
        filemenu.add_command(label="Load Rules...", command=self.load_rules)
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=filemenu)

        helpmenu = tk.Menu(menubar, tearoff=0)
        helpmenu.add_command(label="About", command=lambda: messagebox.showinfo("About", "Log Threat Tool v1.1"))
        menubar.add_cascade(label="Help", menu=helpmenu)

        self.root.config(menu=menubar)

    def _build_notebook(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=8)

        # Tab 1: Main (Log viewer + Results)
        self.tab_main = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_main, text="Main")

        # Dashboard tab: placed right after "Main"
        self._build_dashboard_tab()


        # Top: Log viewer
        top_frame = ttk.LabelFrame(self.tab_main, text="Log Viewer")
        top_frame.pack(fill="both", expand=True, padx=10, pady=(6,6))
        self.log_text = ScrolledText(top_frame, height=18, bootstyle="secondary")
        self.log_text.pack(fill="both", expand=True, padx=6, pady=6)

        # Toolbar for main tab
        toolbar = ttk.Frame(self.tab_main)
        toolbar.pack(fill="x", padx=10, pady=(0,6))
        ttk.Button(toolbar, text="Open Log", command=self.open_file).pack(side="left", padx=4)
        ttk.Button(toolbar, text="Run Detection", command=self.run_detection).pack(side="left", padx=4)
        ttk.Button(toolbar, text="Clear Results", command=self.clear_results).pack(side="left", padx=4)

        ttk.Label(toolbar, text="Filter (Threat name):").pack(side="left", padx=(20,4))
        self.filter_var = tk.StringVar()
        self.filter_entry = ttk.Entry(toolbar, textvariable=self.filter_var, width=20)
        self.filter_entry.pack(side="left")
        ttk.Button(toolbar, text="Apply Filter", command=self.apply_filter).pack(side="left", padx=4)
        ttk.Button(toolbar, text="Clear Filter", command=self.clear_filter).pack(side="left", padx=4)
        
        # ADDED: Export Reports button after Clear Filter
        ttk.Button(toolbar, text="Export Reports", command=self.export_pdf_per_attack_type).pack(side="left", padx=4) # NEW LINE

        # Bottom: Results
        bottom_frame = ttk.LabelFrame(self.tab_main, text="Detected Threats")
        bottom_frame.pack(fill="both", expand=True, padx=10, pady=(0,10))
        columns = ("Time", "IP", "Threat", "Severity", "Raw")
        self.tree = ttk.Treeview(bottom_frame, columns=columns, show="headings", height=12)
        for col in columns:
            self.tree.heading(col, text=col)
            if col == "Raw":
                self.tree.column(col, width=520, anchor="w")
            elif col == "Threat":
                self.tree.column(col, width=220, anchor="center")
            elif col == "Severity":
                self.tree.column(col, width=100, anchor="center")
            else:
                self.tree.column(col, width=150, anchor="center")
        vsb = ttk.Scrollbar(bottom_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True, padx=6, pady=6)
        
        # Mail Settings tab
        self.tab_mail = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_mail, text="Mail Settings")
        self.build_mail_tab()

        # Tab 2: Rule Management
        self.tab_rules = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_rules, text="Rule Management")

        # Rules table (full-width)
        rules_frame = ttk.LabelFrame(self.tab_rules, text="Rules")
        rules_frame.pack(fill="both", expand=False, padx=10, pady=(6,6))

        self.rules_table = ttk.Treeview(rules_frame, columns=("Name", "Pattern", "Severity"), show="headings", height=10)
        self.rules_table.heading("Name", text="Rule Name")
        self.rules_table.heading("Pattern", text="Regex Pattern")
        self.rules_table.heading("Severity", text="Severity")
        self.rules_table.column("Name", width=260, anchor="w")
        self.rules_table.column("Pattern", width=700, anchor="w")
        self.rules_table.column("Severity", width=120, anchor="center")
        vsb_rules = ttk.Scrollbar(rules_frame, orient="vertical", command=self.rules_table.yview)
        self.rules_table.configure(yscrollcommand=vsb_rules.set)
        vsb_rules.pack(side="right", fill="y")
        self.rules_table.pack(fill="both", expand=True, padx=6, pady=6)

        # Add / Remove section below table
        ar_frame = ttk.Frame(self.tab_rules)
        ar_frame.pack(fill="x", expand=False, padx=10, pady=(6,12))

        # Add Rule column
        add_frame = ttk.LabelFrame(ar_frame, text="Add Rule (Name + Regex + Severity)")
        add_frame.pack(side="left", fill="both", expand=True, padx=(0,6))

        ttk.Label(add_frame, text="Rule Name:").grid(row=0, column=0, sticky="w", padx=6, pady=(6,2))
        self.add_name = ttk.Entry(add_frame, width=40)
        self.add_name.grid(row=0, column=1, sticky="w", padx=6, pady=(6,2))

        ttk.Label(add_frame, text="Regex Pattern:").grid(row=1, column=0, sticky="w", padx=6, pady=(2,2))
        self.add_pattern = ttk.Entry(add_frame, width=80)
        self.add_pattern.grid(row=1, column=1, sticky="w", padx=6, pady=(2,2))

        ttk.Label(add_frame, text="Severity:").grid(row=2, column=0, sticky="w", padx=6, pady=(2,8))
        self.add_sev_var = tk.StringVar(value="LOW")
        sev_frame = ttk.Frame(add_frame)
        sev_frame.grid(row=2, column=1, sticky="w", padx=6, pady=(2,8))
        ttk.Radiobutton(sev_frame, text="HIGH", variable=self.add_sev_var, value="HIGH").pack(side="left", padx=6)
        ttk.Radiobutton(sev_frame, text="MEDIUM", variable=self.add_sev_var, value="MEDIUM").pack(side="left", padx=6)
        ttk.Radiobutton(sev_frame, text="LOW", variable=self.add_sev_var, value="LOW").pack(side="left", padx=6)

        ttk.Button(add_frame, text="Add Rule", command=self.add_rule_inline).grid(row=3, column=1, sticky="e", padx=6, pady=(0,8))

        # Remove Rule column
        remove_frame = ttk.LabelFrame(ar_frame, text="Remove Rule")
        remove_frame.pack(side="left", fill="both", expand=False, padx=(6,0), ipadx=6)

        ttk.Label(remove_frame, text="Select rule to remove:").pack(anchor="w", padx=6, pady=(8,2))
        self.remove_combo = ttk.Combobox(remove_frame, values=[], state="readonly", width=40)
        self.remove_combo.pack(padx=6, pady=(0,8))
        ttk.Button(remove_frame, text="Remove Selected Rule", command=self.remove_rule_inline).pack(padx=6, pady=(0,8), anchor="e")

        # Status bar
        self.status_var = tk.StringVar(value="Initializing...")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, anchor="w")
        status_bar.pack(fill="x", padx=6, pady=(0,6))

        # initial populate
        self.refresh_rules_view()

    def build_mail_tab(self):
        frame = ttk.Frame(self.tab_mail)
        frame.pack(fill="both", expand=True, padx=20, pady=20)

        self.var_mail_enabled = tk.BooleanVar(value=True)
        self.var_sender = tk.StringVar()
        self.var_password = tk.StringVar()
        self.var_receiver = tk.StringVar()
 
        ttk.Checkbutton(
            frame,
            text="Enable Email Alerts",
            variable=self.var_mail_enabled
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=8)

        ttk.Label(frame, text="Sender Email").grid(row=1, column=0, sticky="w")
        ttk.Entry(frame, textvariable=self.var_sender, width=40).grid(row=1, column=1)

        ttk.Label(frame, text="App Password").grid(row=2, column=0, sticky="w")
        ttk.Entry(frame, textvariable=self.var_password, show="*", width=40).grid(row=2, column=1)

        ttk.Label(frame, text="Receiver Email").grid(row=3, column=0, sticky="w")
        ttk.Entry(frame, textvariable=self.var_receiver, width=40).grid(row=3, column=1)

        ttk.Button(
            frame,
            text="Apply Settings",
            command=self.apply_mail_settings
        ).grid(row=4, column=1, sticky="e", pady=15)

    def apply_mail_settings(self):
        update_email_settings(
            self.var_mail_enabled.get(),
            self.var_sender.get().strip(),
            self.var_password.get().strip(),
            self.var_receiver.get().strip()
        )
        messagebox.showinfo(
            "Mail Settings",
            "Email settings updated successfully"
        )

    def _configure_tree_tags(self):
        try:
            # Improve contrast for Detected Threat rows
            self.tree.tag_configure("HIGH", background="#FFD6D6", foreground="black")
            self.tree.tag_configure("MEDIUM", background="#FFE7B3", foreground="black")
            self.tree.tag_configure("LOW", background="#DFFFDF", foreground="black")

            # Optional: default row styling
            self.tree.tag_configure("DEFAULT", foreground="black")

        except Exception:
            pass
        try:
            self.rules_table.tag_configure("odd", background="#1e1e1e")
            self.rules_table.tag_configure("even", background="#141414")
        except Exception:
            pass


    # --------------------
    # Dashboard (matplotlib embedded)
    # --------------------
    def _build_dashboard_tab(self):
        """Create Dashboard tab with a donut (severity) and bar (threat counts) charts."""
        self.tab_dashboard = ttk.Frame(self.notebook)
        
        self.notebook.add(self.tab_dashboard, text="Dashboard")

        # Top summary frame (percentages)
        top_sum = ttk.Frame(self.tab_dashboard)
        top_sum.pack(fill="x", padx=10, pady=(8,4))

        self.summary_label = ttk.Label(top_sum, text="No data yet", anchor="w")
        self.summary_label.pack(fill="x")

        self.build_summary_cards(self.tab_dashboard)

        # Charts frame
        charts_frame = ttk.Frame(self.tab_dashboard)
        charts_frame.pack(fill="both", expand=True, padx=10, pady=8)


        # Left: donut/pie for severity
        pie_frame = ttk.LabelFrame(charts_frame, text="Severity Distribution")
        pie_frame.pack(side="left", fill="both", expand=True, padx=(0,6))

        self.fig_pie = Figure(figsize=(3.0, 2.4), dpi=100)
        self.ax_pie = self.fig_pie.add_subplot(111)
        self.ax_pie.axis("equal")
        self.canvas_pie = FigureCanvasTkAgg(self.fig_pie, master=pie_frame)
        self.canvas_pie.get_tk_widget().pack(fill="both", expand=True)

        # Right: histogram of threats
        bar_frame = ttk.LabelFrame(charts_frame, text="Threats Present (Counts)")
        bar_frame.pack(side="left", fill="both", expand=True, padx=(6,0))

        self.fig_bar = Figure(figsize=(6.2, 2.7), dpi=100)
        self.ax_bar = self.fig_bar.add_subplot(111)
        self.canvas_bar = FigureCanvasTkAgg(self.fig_bar, master=bar_frame)
        self.canvas_bar.get_tk_widget().pack(fill="both", expand=True)


        # initial empty draw
        self._draw_empty_dashboard()
       
        
        


    def _draw_empty_dashboard(self):
        # helper to show initial empty charts
        self.ax_pie.clear()
        wedges = self.ax_pie.pie([1], labels=["No Data"], startangle=90)
        self.ax_pie.set_title("Severity Distribution")
        self.fig_pie.tight_layout()
        self.fig_bar.tight_layout()

        self.canvas_pie.draw()

        self.ax_bar.clear()
        self.ax_bar.text(0.5, 0.5, "No threats detected", ha="center", va="center", transform=self.ax_bar.transAxes)
        self.ax_bar.set_xticks([])
        self.ax_bar.set_yticks([])
        
        self.fig_pie.tight_layout()
        self.fig_bar.tight_layout()

        self.canvas_bar.draw()


    def _draw_pie_chart(self):

        self.ax_pie.clear()

        if not self.detections:
            self.canvas_pie.draw()
            return

        # -----------------------
        # TOP 5 THREAT TYPES PIE
        # -----------------------

        threat_counts = {}

        for d in self.detections:
            t = d["type"]
            threat_counts[t] = threat_counts.get(t, 0) + 1

        # Sort by highest count
        threats_sorted = sorted(
            threat_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )

        top_five = threats_sorted[:5]

        labels = [item[0] for item in top_five]
        values = [item[1] for item in top_five]

        total = sum(values)

        percentages = [
            f"{(v/total)*100:.1f}%"
            for v in values
        ]

        # ---- DRAW DONUT PIE ----
        wedges, _ = self.ax_pie.pie(
            values,
            labels=labels,
            startangle=90,
            autopct="%1.1f%%",
            counterclock=False,
            wedgeprops=dict(width=0.45)
        )

        self.ax_pie.set_title("Top 5 Threat Categories")

        self.ax_pie.axis("equal")
        self.fig_pie.tight_layout()


    def draw_log_trend_analysis(self):

        self.ax_trend.clear()

        # Group detections by date
        time_counts = {}

        for d in self.detections:
            t = d["time"][:10]   # YYYY-MM-DD
            time_counts[t] = time_counts.get(t, 0) + 1

        if not time_counts:
            self.canvas_trend.draw()
            return

        dates = sorted(time_counts)
        values = [time_counts[d] for d in dates]

        # ---- STYLE TO MATCH SAMPLE GRAPH ----

        # Smooth line
        self.ax_trend.plot(
            dates,
            values,
            color="#4DA3F7",
            linewidth=3.5,
            marker="o"
        )

        # Filled area beneath line
        self.ax_trend.fill_between(
            dates,
            values,
            color="#4DA3F7",
            alpha=0.35
        )

        # Axis labels
        self.ax_trend.set_title("Log Threat Trend Analysis", fontsize=11)
        self.ax_trend.set_ylabel("Threat Count")
        self.ax_trend.set_xlabel("Time")

        # Clean look like SOC dashboards
        self.ax_trend.grid(True, linestyle="--", linewidth=0.5, alpha=0.6)
        self.ax_trend.tick_params(axis="x", rotation=30)

        # Compact layout
        self.fig_trend.tight_layout(pad=1)

        self.canvas_trend.draw()


    def update_dashboard(self):

        # build counts
        sev_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        threat_counts = {}
        total = len(self.detections or [])

        for d in (self.detections or []):
            sev = (d.get("severity") or "LOW").upper()
            sev_counts.setdefault(sev, 0)
            sev_counts[sev] += 1
            tname = d.get("threat") or "Unknown"
            threat_counts[tname] = threat_counts.get(tname, 0) + 1

        # Severity donut/pie
        self.ax_pie.clear()
        sizes = [sev_counts["HIGH"], sev_counts["MEDIUM"], sev_counts["LOW"]]
        labels = []
        colors = []
        # define colors that match your tree tags background style
        if sum(sizes) == 0:
            labels = ["No Data"]
            sizes = [1]
            colors = ["#cccccc"]
            wedges = self.ax_pie.pie(sizes, labels=labels, startangle=90)
        else:
            labels = []
            colors = []
            for k, col in (("HIGH", "#e62626"), ("MEDIUM", "#f6c667"), ("LOW", "#8af58a")):
                labels.append(f"{k} ({sev_counts[k]})")
                colors.append(col)
            wedges, texts, autotexts = self.ax_pie.pie(
                sizes, labels=labels, autopct=lambda pct: f"{pct:.1f}%" if sum(sizes) > 0 else "",
                startangle=90, colors=colors, textprops=dict(color="black")
            )
            # center circle to make it donut-like
            centre_circle = self.fig_pie.gca().add_artist(self.fig_pie.gca().patch)
            # simpler donut effect: a white circle
            self.ax_pie.add_artist(self.ax_pie.Circle((0, 0), 0.65, color="white"))
        self.ax_pie.set_title("Severity Distribution")
        self.fig_pie.tight_layout()
        self.fig_bar.tight_layout()

        self.canvas_pie.draw()
        self.draw_log_trend_analysis()
        

        # Threats bar chart
        self.ax_bar.clear()
        if not threat_counts:
            self.ax_bar.text(0.5, 0.5, "No threats detected", ha="center", va="center", transform=self.ax_bar.transAxes)
            self.ax_bar.set_xticks([])
            self.ax_bar.set_yticks([])
        else:
            # sort by count desc
            items = sorted(threat_counts.items(), key=lambda x: x[1], reverse=True)
            names = [i[0] for i in items]
            counts = [i[1] for i in items]

            # a color per bar by using severity of first match for that threat
            bar_colors = []
            for name in names:
                sev = None
                for d in self.detections:
                    if d.get("threat") == name:
                        sev = (d.get("severity") or "LOW").upper()
                        break
                if sev == "HIGH":
                    bar_colors.append("#e62626")
                elif sev == "MEDIUM":
                    bar_colors.append("#f6c667")
                else:
                    bar_colors.append("#8af58a")

            x = range(len(names))
            bars = self.ax_bar.bar(x, counts, tick_label=names, color=bar_colors)
            self.ax_bar.set_ylabel("Count")
            self.ax_bar.set_title("Threats by Type")
            self.ax_bar.set_xticklabels(names, rotation=45, ha="right", fontsize=8)
            # show count labels on top
            for bar in bars:
                height = bar.get_height()
                self.ax_bar.annotate(f'{int(height)}', xy=(bar.get_x() + bar.get_width() / 2, height),
                                     xytext=(0, 3), textcoords="offset points", ha="center", va="bottom", fontsize=8)
            self.ax_bar.set_ylim(0, max(counts) * 1.2)
        self.fig_pie.tight_layout()
        self.fig_bar.tight_layout()

        self.canvas_bar.draw()
        

        self.draw_log_trend_analysis()

        # summary label showing totals and percent
        if total == 0:
            self.summary_label.config(text="No detections yet. Run detection to populate the Dashboard.")
        else:
            high = sev_counts["HIGH"]
            med = sev_counts["MEDIUM"]
            low = sev_counts["LOW"]
            self.summary_label.config(text=f"Total events: {total} — HIGH: {high} ({(high/total*100):.1f}%), MEDIUM: {med} ({(med/total*100):.1f}%), LOW: {low} ({(low/total*100):.1f}%)")
        print("Dashboard detections:", len(self.detections))

    def build_summary_cards(self, parent):

        container = ttk.Frame(parent)
        container.pack(fill="x", pady=6)

        self.kpi_labels = {}

        titles = [
            "Total Events",
            "High Severity",
            "Medium Severity",
            "Low Severity"
        ]

        for t in titles:
            card = ttk.Frame(container, padding=10)
            card.pack(side="left", expand=True, fill="x", padx=6)

            title = ttk.Label(card, text=t, font=("Segoe UI", 10))
            title.pack()

            value = ttk.Label(card, text="0", font=("Segoe UI", 18, "bold"))
            value.pack()

            self.kpi_labels[t] = value
    
    def force_dashboard_refresh(self):
        # ---- DEBUG/ROBUST SEVERITY COUNTING 
       
        try:
            det_len = len(self.detections)
        except Exception:
            det_len = 0

        # show sample of first items for quick debugging (safe: not too large)
        _sample = None
        try:
            _sample = self.detections[:3] if det_len else None
        except Exception:
            _sample = None

        # short debug message in status so you can see it in the UI immediately
        try:
            self.status_var.set(f"DBG: detections={det_len}, sample={_sample}")
        except Exception:
            pass

        # If self.detections is empty, attempt common fallbacks where code may have stored results
        if det_len == 0:
            for candidate_name in ("_detections", "detections_list", "results", "last_scan_results", "parsed_results"):
                cand = getattr(self, candidate_name, None)
                try:
                    if cand and len(cand):
                        self.detections = cand
                        det_len = len(self.detections)
                        _sample = self.detections[:3]
                        try:
                            self.status_var.set(f"DBG: using fallback {candidate_name} ({det_len})")
                        except Exception:
                            pass
                        break
                except Exception:
                    pass

        # Final check: if still zero, show a persistent debug label and continue (prevents crash)
        if det_len == 0:
            try:
                # show explicit debug text in your summary label so it doesn't get missed
                self.summary_label.config(text="DEBUG: no detections (len=0). Check assignment of self.detections")
            except Exception:
                pass
            # set safe defaults so rest of function won't crash
            severity_map = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
            high, medium, low = 0, 0, 0
            total = 0
        else:
            # Normal counting from the available list of dict-like detection items
            severity_map = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for d in self.detections:
                try:
                    # Try multiple keys and normalize
                    sev = str(d.get("severity", d.get("risk", d.get("level", d.get("severity_level", "LOW"))))).upper()
                except Exception:
                  
                    try:
                        sev = str(getattr(d, "severity", getattr(d, "risk", getattr(d, "level", "LOW")))).upper()
                    except Exception:
                        sev = "LOW"

                if sev == "HIGH":
                    severity_map["HIGH"] += 1
                elif sev == "MEDIUM":
                    severity_map["MEDIUM"] += 1
                else:
                    severity_map["LOW"] += 1

            high = severity_map["HIGH"]
            medium = severity_map["MEDIUM"]
            low = severity_map["LOW"]
            total = high + medium + low


        # -------------------------
        # UPDATE KPI SUMMARY CARDS
        # -------------------------
        try:
            self.kpi_labels["Total Events"].config(text=str(total))
            self.kpi_labels["High Severity"].config(text=str(high))
            self.kpi_labels["Medium Severity"].config(text=str(medium))
            self.kpi_labels["Low Severity"].config(text=str(low))
        except Exception as e:
            print("KPI update error:", e)


    
        try:
            if getattr(self, "debug_label", None):
                self.debug_label.config(text=f"DBG detections={len(self.detections)} H/M/L={high}/{medium}/{low}")
        except Exception:
            pass
        # ---- end debug/robust block ----

        try:
            # ------------------------
            # TOP-5 DONUT (robust, legend-based layout to avoid label overlap)
            # ------------------------
            self.ax_pie.clear()

            # count threats
            threat_counts = {}
            for d in self.detections:
                t = d.get("threat") or d.get("type") or "Unknown"
                threat_counts[t] = threat_counts.get(t, 0) + 1

            top5 = sorted(threat_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            labels = [x[0] for x in top5]
            sizes = [x[1] for x in top5]

            TOTAL = sum(sizes)

            # If no data -> show message
            if TOTAL == 0:
                self.ax_pie.text(
                    0.5, 0.5, "NO DATA",
                    ha="center", va="center", transform=self.ax_pie.transAxes
                )
                # ensure no legend from previous run
                try:
                    self.ax_pie.legend_.remove()
                except Exception:
                    pass
            else:
                # percent threshold to display autopct
                pct_threshold = 5.0  # show slice percent if >= 5%

                def autopct_conditional(pct):
                    # percentage of the pie (0..100)
                    return f"{pct:.1f}%" if pct >= pct_threshold else ""

                # Draw donut 
                wedges, texts, autotexts = self.ax_pie.pie(
                    sizes,
                    labels=None,               
                    autopct=autopct_conditional,
                    startangle=90,
                    pctdistance=0.70,
                    wedgeprops=dict(width=0.48, edgecolor='white'),
                    colors=plt.cm.tab10.colors,
                    textprops={'fontsize': 9, 'color': 'black'}
                )

                # center circle for donut look
                centre_circle = plt.Circle((0, 0), 0.50, fc="white", linewidth=0)
                self.ax_pie.add_artist(centre_circle)

                # Create a right-side legend with label, count and % text
                legend_items = []
                for lbl, val in zip(labels, sizes):
                    pct = (val / TOTAL * 100) if TOTAL else 0
                    legend_items.append(f"{lbl} — {val} ({pct:.1f}%)")

                try:
                    if getattr(self, "_donut_legend", None) is not None:
                        try:
                            self._donut_legend.remove()
                        except Exception:
                            pass
                    self._donut_legend = self.ax_pie.legend(
                        wedges,
                        legend_items,
                        title="Top 5",
                        loc="center left",
                        bbox_to_anchor=(0.79, 0.5),
                        fontsize=9,
                        frameon=False
                    )
                except Exception:
                    
                    self.ax_pie.text(1.02, 0.5, "\n".join(legend_items), transform=self.ax_pie.transAxes,
                                    ha="left", va="center", fontsize=9, color="black")

           
            self.ax_pie.set_title("Top 5 Threat Categories")
            self.fig_pie.subplots_adjust(left=0.02, right=0.75, top=0.9, bottom=0.05)
            self.canvas_pie.draw()
           

            # ------------------------
            # BAR CHART (Top N threat types)
            # ------------------------
            self.ax_bar.clear()

            if not threat_counts:
                self.ax_bar.text(0.5, 0.5, "No threats detected", ha="center", va="center", transform=self.ax_bar.transAxes)
                self.ax_bar.set_xticks([])
                self.ax_bar.set_yticks([])
                self.canvas_bar.draw()
            else:
                items = sorted(threat_counts.items(), key=lambda x: x[1], reverse=True)
                topN = items[:10]  # show top 10
                names = [n for n, c in topN]
                counts = [c for n, c in topN]

                wrapped_names = ["\n".join(textwrap.wrap(n, 12)) for n in names]

                bars = self.ax_bar.bar(range(len(names)), counts, color="#4d94ff")
                self.ax_bar.set_xticks(range(len(wrapped_names)))
                self.ax_bar.set_xticklabels(wrapped_names, fontsize=8)
                self.ax_bar.set_ylabel("Occurrences")
                self.ax_bar.set_title("Threats by Type")
                self.ax_bar.tick_params(axis="x", rotation=0)

                try:
                    self.fig_bar.tight_layout(pad=1)
                except Exception:
                    pass
                self.canvas_bar.draw()

                total_detections = sum(counts) if counts else 0

                try:
                    self.bar_cursor = getattr(self, "bar_cursor", None)
                except Exception:
                    self.bar_cursor = None

                
                self.bar_cursor = mplcursors.cursor(bars, hover=True)

               
                self._active_sel = None

                @self.bar_cursor.connect("add")
                def _on_add(sel):
                    try:
                        ct = int(sel.target[1])
                    except Exception:
                        try:
                            ct = int(sel.artist[sel.index].get_height())
                        except Exception:
                            ct = 0
                    pct = (ct / total_detections) * 100 if total_detections else 0
                    sel.annotation.set_text(f"{ct} threats\n{pct:.1f}%")

                  
                    try:
                        if getattr(self, "_active_sel", None) is not None and self._active_sel is not sel:
                            self._active_sel.annotation.set_visible(False)
                    except Exception:
                        pass
                    self._active_sel = sel

                
                def _on_axes_leave(event):
                    try:
                        if getattr(self, "_active_sel", None):
                            self._active_sel.annotation.set_visible(False)
                            self._active_sel = None
                            self.canvas_bar.draw_idle()
                    except Exception:
                        pass

                # we overwrite bar_cursor each time
                self.canvas_bar.mpl_connect("axes_leave_event", _on_axes_leave)
           

            # ------------------------
            # SIDE OVERVIEW PIE (Severity - professional 0% handling)
            # ------------------------

            self.ax_sidepie.clear()

            side_vals = [high, medium, low]
            side_labels = ["High", "Medium", "Low"]
            side_colors = ["red", "orange", "green"]

            plot_vals = []
            plot_labels = []
            plot_colors = []

            zero_items = []

            for v, lbl, col in zip(side_vals, side_labels, side_colors):
                if v > 0:
                    plot_vals.append(v)
                    plot_labels.append(lbl)
                    plot_colors.append(col)
                else:
                    zero_items.append(lbl)

            # Draw pie 
            if sum(plot_vals) > 0:
                self.ax_sidepie.pie(
                    plot_vals,
                    labels=plot_labels,
                    colors=plot_colors,
                    autopct=lambda p: f"{p:.0f}%",
                    startangle=90,
                    pctdistance=0.70,
                    labeldistance=1.10
                )

          
            y_pos = -1.25
            for item in zero_items:
                self.ax_sidepie.text(
                    0,
                    y_pos,
                    f"{item}: 0%",
                    ha="center",
                    va="top",
                    fontsize=9,
                    color="white"
                )
                y_pos -= 0.18

           
            self.ax_sidepie.set_ylim(-1.6, 1.2)

            self.ax_sidepie.set_title("Risk Overview")

            try:
                self.fig_sidepie.tight_layout(pad=1)
            except Exception:
                pass

            self.canvas_sidepie.draw()

            # ------------------------
            # LOG THREAT TREND (per-file history)
            # ------------------------
          
            try:
                # append current run count
                self.detection_history.append(len(self.detections))
            except Exception:
                self.detection_history = [len(self.detections)]

             # -------------------------
            # SUMMARY TEXT (top line)
            # -------------------------
            sev_total = high + medium + low
            if sev_total == 0:
                self.summary_label.config(text="No detections yet.")
            else:
                self.summary_label.config(
                    text=f"TOTAL: {total} | HIGH: {high} ({(high/total*100) if total else 0:.1f}%) | "
                        f"MEDIUM: {medium} ({(medium/total*100) if total else 0:.1f}%) | "
                        f"LOW: {low} ({(low/total*100) if total else 0:.1f}%)"
                )

            self.root.update_idletasks()

            self.ax_line.clear()
            x = list(range(1, len(self.detection_history) + 1))
            y = self.detection_history

            if x and y:
                self.ax_line.plot(x, y, marker="o", linewidth=2.2)
                self.ax_line.fill_between(x, y, alpha=0.35)
            self.ax_line.set_title("Log Threat Trend Analysis")
            self.ax_line.set_ylabel("Threat Count")
            self.ax_line.set_xlabel("Scan Cycle")
            try:
                self.fig_trend.tight_layout(pad=1)
            except Exception:
                pass
            self.canvas_line.draw()

            
            self.status_var.set(f"Detection complete. Threats found: {total}")

        except Exception as ex:
            try:
                self.status_var.set(f"Dashboard error: {ex}")
            except Exception:
                pass
            import traceback
            traceback.print_exc()
          
    # --------------------
    # File operations
    # --------------------
    def open_file(self):
        self.detection_history = []

        path = filedialog.askopenfilename(title="Select log file", filetypes=(("Log files","*.log;*.txt;*.*"),))
        if not path:
            return
        self.current_file = path
        try:
            with open(path, "r", errors="ignore") as f:
                data = f.read()
            self.log_text.delete("1.0", tk.END)
            self.log_text.insert(tk.END, data)
            self.status_var.set(f"Loaded: {os.path.basename(path)}")
            self.notebook.select(self.tab_main)
            self.root.after(200, lambda: self.force_dashboard_refresh())



        except Exception as e:
            messagebox.showerror("Error", f"Unable to open file:\n{e}")

    def save_rules(self):
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON","*.json")], title="Save rules to...")
        if not path:
            return
        try:
            self.rules.save_to_file(path)
            messagebox.showinfo("Saved", f"Rules saved to {path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save rules:\n{e}")

    def load_rules(self):
        path = filedialog.askopenfilename(title="Load rules file", filetypes=[("JSON","*.json")])
        if not path:
            return
        try:
            self.rules.load_from_file(path)
            messagebox.showinfo("Loaded", f"Rules loaded from {path}")
            self.refresh_rules_view()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load rules:\n{e}")

    def build_kpi_cards(self, parent):

        row = ttk.Frame(parent)
        row.pack(fill="x", pady=6)

        self.kpi = {}

        for label in ["Total Events", "High Severity", "Medium Severity", "Low Severity"]:
            box = ttk.Frame(row, padding=12)
            box.pack(side="left", expand=True, fill="x", padx=6)

            ttk.Label(box, text=label, font=("Segoe UI", 10)).pack()
            val = ttk.Label(box, text="0", font=("Segoe UI", 18, "bold"))
            val.pack()

            self.kpi[label] = val



    # --------------------
    # Detection / Results
    # --------------------
    def run_detection(self):
        start_time = time.time()

        self.tree.delete(*self.tree.get_children())
        self.detections = []

        content = self.log_text.get("1.0", tk.END).splitlines()

        rows_to_insert = []
        total_found = 0
        high_count = 0
        high_threats = {}

        new_blocked_ips = set()

        for line in content:
            ts, ip, req, status, raw = parse_log_line(line)
            clean_ip = ip.strip()

            if clean_ip in ("", "N/A", "-", "UNKNOWN"):
                continue

            normalized = normalize_input(raw)

            # ---- IOC CHECK (NEW IP ONLY) ----
            if clean_ip in self.ioc_ips and clean_ip not in self.blocked_ips:
                self.blocked_ips.add(clean_ip)
                new_blocked_ips.add(clean_ip)

                rows_to_insert.append(
                    (ts, clean_ip, "Threat Intel Match (IOC) – AUTO BLOCKED", "HIGH", raw)
                )

                self.detections.append({
                    "time": ts,
                    "ip": clean_ip,
                    "threat": "Threat Intel Match (IOC)",
                    "severity": "HIGH",
                    "raw": raw
                })

                high_count += 1
                high_threats["IOC Match"] = high_threats.get("IOC Match", 0) + 1
                continue

            # ---- AUTO-BLOCK ENFORCEMENT ----
            if clean_ip in self.blocked_ips:
                rows_to_insert.append(
                    (ts, clean_ip, "AUTO-BLOCKED IP (Previously Flagged)", "HIGH", raw)
                )
                continue

            # ---- RULE CHECK ----
            matches = detect_threats(normalized, self.rules)

            for rule_name, severity in matches:
                rows_to_insert.append((ts, clean_ip, rule_name, severity, raw))

                self.detections.append({
                    "time": ts,
                    "ip": clean_ip,
                    "threat": rule_name,
                    "severity": severity,
                    "raw": raw
                })

                total_found += 1

                if severity == "HIGH":
                    high_count += 1
                    high_threats[rule_name] = high_threats.get(rule_name, 0) + 1

        # ---- WRITE BLOCKED IPs ONCE ----
        if new_blocked_ips:
            with open(BLOCK_FILE, "a") as f:
                for ip in new_blocked_ips:
                    f.write(ip + "\n")

            print(f"[AUTO-BLOCK] {len(new_blocked_ips)} IPs saved")

        # ---- INSERT RESULTS ----
        for r in rows_to_insert:
            tag = r[3] if r[3] in ("HIGH", "MEDIUM", "LOW") else "LOW"
            self.tree.insert("", tk.END, values=r, tags=(tag,))

        # ---- SEND EMAIL (ONCE, ONLY IF HIGH) ----
        if high_count > 0:
            threat_lines = "\n".join(
                f"- {name}: {count}" for name, count in high_threats.items()
            )

            body = (
                "🚨 SECURITY ALERT – HIGH SEVERITY THREATS DETECTED 🚨\n\n"
                f"Total High Severity Events: {high_count}\n\n"
                "Top Threats:\n"
                f"{threat_lines}\n\n"
                "⚠️ Immediate investigation is recommended."
            )

            send_email_alert(
                subject="🚨 SECURITY ALERT – High Severity Threats Detected",
                body=body
            )

        elapsed = round(time.time() - start_time, 2)

        self.status_var.set(
            f"Detection complete | Threats: {len(self.detections)} | Time: {elapsed}s"
        )

        messagebox.showinfo(
            "Complete",
            f"Detection finished in {elapsed} seconds\nThreats found: {len(self.detections)}"
        )

        self.root.after(200, lambda: self.force_dashboard_refresh())




    def clear_results(self):
        self.tree.delete(*self.tree.get_children())
        self.detections = []
        self.status_var.set("Results cleared")
        self.root.after(200, lambda: self.force_dashboard_refresh())



    def apply_filter(self):
        term = self.filter_var.get().strip().lower()
        for iid in self.tree.get_children():
            vals = self.tree.item(iid, "values")
            threat = vals[2].lower() if len(vals) > 2 else ""
            if term and term not in threat:
                self.tree.detach(iid)
            else:
                try:
                    self.tree.reattach(iid, '', 'end')
                except Exception:
                    pass

    def clear_filter(self):
        self.filter_var.set("")
        self.tree.delete(*self.tree.get_children())
        for d in self.detections:
            tag = d.get("severity", "LOW")
            self.tree.insert("", tk.END, values=(d["time"], d["ip"], d["threat"], d["severity"], d["raw"]), tags=(tag,))
        self.status_var.set("Filter cleared")

    # --------------------
    # Rule Management helpers
    # --------------------
    def refresh_rules_view(self):
        # table
        self.rules_table.delete(*self.rules_table.get_children())
        for idx, (name, (pattern, severity)) in enumerate(self.rules.patterns.items()):
            tag = "even" if idx % 2 == 0 else "odd"
            self.rules_table.insert("", tk.END, values=(name, pattern, severity), tags=(tag,))
        # refresh combobox
        names = list(self.rules.patterns.keys())
        self.remove_combo['values'] = names
        if names:
            self.remove_combo.current(0)
        
        self.add_name.delete(0, tk.END)
        self.add_pattern.delete(0, tk.END)
        self.add_sev_var.set("LOW")

    def add_rule_inline(self):
        name = self.add_name.get().strip()
        pattern = self.add_pattern.get().strip()
        severity = self.add_sev_var.get().strip().upper()
        if not name or not pattern:
            messagebox.showwarning("Missing", "Please provide both Rule Name and Regex pattern.")
            return
        # duplicate name check (case-insensitive)
        existing_names = [n.lower() for n in self.rules.patterns.keys()]
        if name.lower() in existing_names:
            messagebox.showerror("Duplicate Rule", f"Rule name '{name}' already exists.")
            return
        # duplicate pattern check (exact string match)
        existing_patterns = [p for (_, (p, _)) in self.rules.patterns.items()]
        if pattern in existing_patterns:
            messagebox.showerror("Duplicate Pattern", "An identical regex pattern already exists as a rule.")
            return
        # validate regex
        try:
            re.compile(pattern)
        except re.error as err:
            messagebox.showerror("Invalid Regex", f"Regex compilation error:\n{err}")
            return
        # add
        self.rules.add_rule(name, pattern, severity)
        messagebox.showinfo("Added", f"Rule '{name}' added successfully.")
        self.refresh_rules_view()

    def remove_rule_inline(self):
        sel = self.remove_combo.get()
        if not sel:
            messagebox.showwarning("No selection", "Please select a rule to remove.")
            return
        confirm = messagebox.askyesno("Confirm Remove", f"Are you sure you want to remove rule '{sel}'?")
        if not confirm:
            return
        if sel in self.rules.patterns:
            self.rules.remove_rule(sel)
            messagebox.showinfo("Removed", f"Rule '{sel}' removed successfully.")
            self.refresh_rules_view()
        else:
            messagebox.showerror("Error", "Selected rule not found.")

    # --------------------
    # Export
    # --------------------
    def export_csv(self):
        if not self.detections:
            messagebox.showwarning("No data", "No detections to export. Run detection first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")], title="Export CSV")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=["time","ip","threat","severity","raw"])
                writer.writeheader()
                for row in self.detections:
                    writer.writerow(row)
            messagebox.showinfo("Exported", f"Detections exported to {path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export CSV:\n{e}")

    def export_pdf_per_attack_type(self):
        """
        Generate a separate PDF per attack type (grouped by 'threat' field).
        The user selects an output folder; one file per attack type is created.
        """
        if not self.detections:
            messagebox.showwarning("No Data", "Run detection first.")
            return

        out_dir = filedialog.askdirectory(title="Select output folder for PDF reports")
        if not out_dir:
            return

        # Group detections by threat name
        grouped = {}
        for d in self.detections:
            attack = d.get("threat", "Unknown")
            grouped.setdefault(attack, []).append(d)

        styles = getSampleStyleSheet()
        # MODIFIED: Add custom style for Paragraphs in table cells for text wrapping
        styles.add(ParagraphStyle(name='TableText', fontName='Helvetica', fontSize=8, leading=10, alignment=0)) # ADDED
        
        created_files = []

        for attack_type, rows in grouped.items():
            # safe filename
            safe_name = attack_type.replace("/", "-").replace(" ", "_")
            filename = f"{safe_name}.pdf"
            file_path = os.path.join(out_dir, filename)

            try:
                doc = SimpleDocTemplate(file_path, pagesize=A4, leftMargin=24, rightMargin=24, topMargin=24, bottomMargin=24)
                story = []

                # Title & summary
                story.append(Paragraph(f"{attack_type} - Threat Report", styles["Title"]))
                story.append(Spacer(1, 8))
                story.append(Paragraph(f"Total Events: {len(rows)}", styles["Normal"]))
                story.append(Paragraph(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))
                story.append(Spacer(1, 12))

                # Table header
                data = [["Time", "IP", "Severity", "Log Snippet"]]

                # Build rows
                for d in rows:
                    ts = d.get("time", "-")
                    ip = d.get("ip", "-")
                    sev = d.get("severity", "-")
                    raw = (d.get("raw") or "").replace("\n", " ").strip()
                    if len(raw) > 300:
                        raw = raw[:297] + "..."
                        
                    # CRITICAL FIX: Escape raw log snippet to prevent ReportLab's XML parser from breaking
                    escaped_raw = html_escape(raw) # ADDED
                    
                    # MODIFIED: Use Paragraph objects for all cells to enable escaping and text wrapping
                    data.append([
                        Paragraph(ts, styles["TableText"]), 
                        Paragraph(ip, styles["TableText"]), 
                        Paragraph(sev, styles["TableText"]), 
                        Paragraph(escaped_raw, styles["TableText"])
                    ]) # MODIFIED

                # Column widths (Adjusted for the use of Paragraphs and to utilize available width: 547 pts)
                col_widths = [110, 80, 70, 287] # MODIFIED
                table = Table(data, colWidths=col_widths, repeatRows=1)

                # Styling
                style_cmds = [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2f4f4f")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 10),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.grey),
                    ("BOX", (0, 0), (-1, -1), 0.25, colors.grey),
                    ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 1), (-1, -1), 8),
                    # NEW: Explicit alignment commands for Paragraphs
                    ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                    ('ALIGN', (2, 1), (2, -1), 'CENTER'), # Center align severity
                    ('ALIGN', (0, 1), (1, -1), 'LEFT'),  # Left align Time/IP
                    ('ALIGN', (3, 1), (3, -1), 'LEFT'),  # Left align Log Snippet
                ] # MODIFIED with new alignment commands

                # Row coloring by severity
                for idx, d in enumerate(rows, start=1):
                    sev = (d.get("severity") or "").upper()
                    if sev == "HIGH":
                        style_cmds.append(("BACKGROUND", (0, idx), (-1, idx), colors.Color(1, 0.85, 0.85)))
                    elif sev == "MEDIUM":
                        style_cmds.append(("BACKGROUND", (0, idx), (-1, idx), colors.Color(1, 0.97, 0.85)))
                    else:
                        style_cmds.append(("BACKGROUND", (0, idx), (-1, idx), colors.Color(0.9, 1, 0.9)))

                table.setStyle(TableStyle(style_cmds))

                story.append(table)
                story.append(Spacer(1, 12))
                story.append(Paragraph(f"Report generated by Log Threat Tool on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))

                # Build file
                doc.build(story)
                created_files.append(file_path)
            except Exception as e:
                # Don't abort the whole run if one file fails; show later
                print(f"Failed to create {file_path}: {e}")

        if created_files:
            messagebox.showinfo("Done", f"Created {len(created_files)} PDF(s) in:\n{out_dir}")
        else:
            messagebox.showwarning("No Reports", "No reports were created. Check write permissions or try a different folder.")

# --------------------
# Privilege Check (NEW)
# --------------------
def is_admin():
    """Check if the script is running with administrative/root privileges."""
    try:
        if platform.system() == "Windows":
            # Windows check: checks if current user token has Admin group SID
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:
            # Linux/macOS check: checks for effective UID being 0 (root)
            return os.geteuid() == 0
    except Exception:
        # Fallback for systems where checks are unavailable or error occurs
        return False

# --------------------
# Main (UPDATED)
# --------------------
def main():
    # ---------- Admin privilege check ----------
    if not is_admin():
        if platform.system() == "Windows":
            messagebox.showerror(
                "Permission Denied",
                "This application requires administrator privileges.\nRun as Administrator."
            )
        else:
            messagebox.showerror(
                "Permission Denied",
                "This application requires root privileges.\nRun with: sudo python threat_tool.py"
            )
        return

    # ---------- Login Flow ----------
if __name__ == "__main__":
    root = tk.Tk()
    LogThreatGUI(root)
    root.mainloop()