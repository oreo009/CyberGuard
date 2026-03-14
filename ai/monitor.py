import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import time
import os
import sys
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.dates as mdates
from datetime import datetime

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from ai.algorithms import bfs, dfs, a_star_defense

class SecurityMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("CyberGuard AI Defense System")
        self.root.geometry("1200x700")  # Reduced from 1400x900
        self.root.configure(bg='#0a0a0a')
        self.root.resizable(True, True)

        # State variables
        self.system_status = tk.StringVar(value="SAFE")
        self.threat_level = tk.StringVar(value="LOW")
        self.attack_type = tk.StringVar(value="None")
        self.ai_response = tk.StringVar(value="Monitoring")
        self.defense_status = tk.StringVar(value="MONITORING")

        # Statistics
        self.brute_count = tk.IntVar(value=0)
        self.sql_count = tk.IntVar(value=0)
        self.dos_count = tk.IntVar(value=0)
        self.blocked_ips = tk.IntVar(value=0)

        # Log tracking
        self.last_line_count = 0
        self.last_event_time = time.time()

        # Defense process
        self.defense_active = False
        self.defense_start = 0
        self.defense_step = 0

        # Attack timeline for line graph
        self.attack_times = []
        self.attack_counts = []

        # Setup GUI
        self.setup_gui()

        # Start update loop
        self.update_dashboard()

    def setup_gui(self):
        # Configure root for grid layout - minimal expansion
        self.root.grid_rowconfigure(1, weight=0)  # Don't expand to fill
        self.root.grid_columnconfigure(0, weight=1)

        # Title Banner - Row 0 - more compact
        title_frame = tk.Frame(self.root, bg='#1a1a2e', relief='raised', bd=2)
        title_frame.grid(row=0, column=0, sticky='ew', padx=5, pady=(5, 2))
        title_frame.grid_columnconfigure(0, weight=1)

        tk.Label(title_frame, text="CYBERGUARD AI DEFENSE SYSTEM", font=("Arial", 20, "bold"),
                fg='white', bg='#1a1a2e').grid(row=0, column=0, pady=(8, 2))
        tk.Label(title_frame, text="Real-Time Threat Detection Dashboard", font=("Arial", 10),
                fg='lightgray', bg='#1a1a2e').grid(row=1, column=0, pady=(0, 8))

        # Main content frame - Row 1 - compact
        main_frame = tk.Frame(self.root, bg='#0a0a0a')
        main_frame.grid(row=1, column=0, sticky='ew', padx=5, pady=(2, 5))
        # Remove weight=1 to prevent expansion
        main_frame.grid_columnconfigure((0, 1, 2), weight=1)

        # Row 1: Status panels - compact height
        status_frame = tk.Frame(main_frame, bg='#0a0a0a')
        status_frame.grid(row=0, column=0, columnspan=3, sticky='ew', pady=(0, 5))
        status_frame.grid_columnconfigure((0, 1, 2), weight=1)

        # System Status Panel
        self.status_label = self.create_status_panel(status_frame, "SYSTEM STATUS", self.system_status, 'green', 0, 0)

        # Threat Level Panel
        self.threat_label = self.create_status_panel(status_frame, "THREAT LEVEL", self.threat_level, 'green', 0, 1)

        # Attack Type Panel
        self.create_status_panel(status_frame, "ATTACK TYPE", self.attack_type, 'white', 0, 2)

        # Row 2: Attack Activity Graph - smaller
        self.create_line_graph(main_frame, 1, 0, 3)

        # Row 3: Attack Distribution Graph - smaller
        self.create_bar_graph(main_frame, 2, 0, 3)

        # Row 4: Bottom panels - compact
        bottom_frame = tk.Frame(main_frame, bg='#0a0a0a')
        bottom_frame.grid(row=3, column=0, columnspan=3, sticky='ew', pady=(5, 0))
        bottom_frame.grid_columnconfigure((0, 1, 2), weight=1)

        # Attack Statistics Panel
        self.create_stats_panel(bottom_frame, 0, 0)

        # AI Response Panel
        self.create_ai_panel(bottom_frame, 0, 1)

        # Threat Feed Panel
        self.create_feed_panel(bottom_frame, 0, 2)

    def create_status_panel(self, parent, title, var, color, row, col):
        frame = tk.Frame(parent, bg='#2a2a3e', relief='raised', bd=2, height=50)  # Reduced height
        frame.grid(row=row, column=col, padx=3, pady=3, sticky='ew')  # Reduced padding
        frame.grid_propagate(False)  # Prevent frame from shrinking

        tk.Label(frame, text=title, font=("Arial", 10, "bold"), fg='white', bg='#2a2a3e').pack(pady=(5, 2))
        font_size = 16  # Reduced font size
        label = tk.Label(frame, textvariable=var, font=("Arial", font_size, "bold"), fg=color, bg='#2a2a3e')
        label.pack(expand=True)
        return label

    def create_line_graph(self, parent, row, col, colspan):
        frame = tk.Frame(parent, bg='#2a2a3e', relief='raised', bd=2)
        frame.grid(row=row, column=col, columnspan=colspan, sticky='ew', padx=3, pady=3)
        frame.grid_rowconfigure(1, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        tk.Label(frame, text="ATTACK ACTIVITY OVER TIME", font=("Arial", 12, "bold"),
                fg='white', bg='#2a2a3e').grid(row=0, column=0, pady=(5, 3), sticky='n')

        self.line_fig = plt.Figure(figsize=(10, 3), dpi=100, facecolor='#2a2a3e')  # Smaller: 10x3
        self.line_fig.tight_layout(pad=1.0)
        self.line_ax = self.line_fig.add_subplot(111)
        self.line_ax.set_facecolor('#1a1a2e')
        self.line_ax.tick_params(colors='white', labelsize=8)
        self.line_ax.spines['bottom'].set_color('white')
        self.line_ax.spines['top'].set_color('white')
        self.line_ax.spines['right'].set_color('white')
        self.line_ax.spines['left'].set_color('white')
        self.line_ax.xaxis.label.set_color('white')
        self.line_ax.yaxis.label.set_color('white')
        self.line_ax.title.set_color('white')
        self.line_ax.grid(True, alpha=0.3, color='white')

        self.line_canvas = FigureCanvasTkAgg(self.line_fig, master=frame)
        self.line_canvas.get_tk_widget().grid(row=1, column=0, sticky='nsew', padx=5, pady=(3, 5))

    def create_bar_graph(self, parent, row, col, colspan):
        frame = tk.Frame(parent, bg='#2a2a3e', relief='raised', bd=2)
        frame.grid(row=row, column=col, columnspan=colspan, sticky='ew', padx=3, pady=3)
        frame.grid_rowconfigure(1, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        tk.Label(frame, text="ATTACK DISTRIBUTION", font=("Arial", 12, "bold"),
                fg='white', bg='#2a2a3e').grid(row=0, column=0, pady=(5, 3), sticky='n')

        self.bar_fig = plt.Figure(figsize=(10, 2.5), dpi=100, facecolor='#2a2a3e')  # Smaller: 10x2.5
        self.bar_fig.tight_layout(pad=2.0)
        self.bar_ax = self.bar_fig.add_subplot(111)
        self.bar_ax.set_facecolor('#1a1a2e')
        self.bar_ax.tick_params(colors='white', labelsize=10)
        self.bar_ax.spines['bottom'].set_color('white')
        self.bar_ax.spines['top'].set_color('white')
        self.bar_ax.spines['right'].set_color('white')
        self.bar_ax.spines['left'].set_color('white')
        self.bar_ax.xaxis.label.set_color('white')
        self.bar_ax.yaxis.label.set_color('white')
        self.bar_ax.title.set_color('white')

        self.bar_canvas = FigureCanvasTkAgg(self.bar_fig, master=frame)
        self.bar_canvas.get_tk_widget().grid(row=1, column=0, sticky='nsew', padx=5, pady=(3, 5))

    def create_stats_panel(self, parent, row, col):
        frame = tk.Frame(parent, bg='#2a2a3e', relief='raised', bd=2)
        frame.grid(row=row, column=col, sticky='ew', padx=3, pady=3)

        tk.Label(frame, text="ATTACK STATISTICS", font=("Arial", 12, "bold"),
                fg='white', bg='#2a2a3e').pack(pady=(5, 8))

        # Create formatted stat labels
        self.create_formatted_stat(frame, "Brute Force", self.brute_count)
        self.create_formatted_stat(frame, "SQL Injection", self.sql_count)
        self.create_formatted_stat(frame, "DoS Attacks", self.dos_count)
        self.create_formatted_stat(frame, "Blocked IPs", self.blocked_ips)

    def create_formatted_stat(self, parent, label_text, var):
        stat_frame = tk.Frame(parent, bg='#2a2a3e')
        stat_frame.pack(fill=tk.X, padx=8, pady=2)

        tk.Label(stat_frame, text=f"{label_text}:", font=("Arial", 10), fg='lightgray', bg='#2a2a3e').pack(side=tk.LEFT)
        tk.Label(stat_frame, textvariable=var, font=("Arial", 11, "bold"), fg='white', bg='#2a2a3e').pack(side=tk.RIGHT)

    def create_ai_panel(self, parent, row, col):
        frame = tk.Frame(parent, bg='#2a2a3e', relief='raised', bd=2)
        frame.grid(row=row, column=col, sticky='ew', padx=3, pady=3)

        tk.Label(frame, text="AI RESPONSE", font=("Arial", 12, "bold"),
                fg='white', bg='#2a2a3e').pack(pady=(5, 8))

        self.ai_label = tk.Label(frame, textvariable=self.ai_response, font=("Arial", 11, "bold"),
                                fg='cyan', bg='#2a2a3e', wraplength=180, justify='center')
        self.ai_label.pack(expand=True)

    def create_feed_panel(self, parent, row, col):
        frame = tk.Frame(parent, bg='#2a2a3e', relief='raised', bd=2)
        frame.grid(row=row, column=col, sticky='ew', padx=3, pady=3)
        frame.grid_rowconfigure(1, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        tk.Label(frame, text="LIVE THREAT FEED", font=("Arial", 12, "bold"),
                fg='white', bg='#2a2a3e').grid(row=0, column=0, pady=(5, 3), sticky='n')

        self.threat_feed = scrolledtext.ScrolledText(frame, wrap=tk.WORD, height=8,
                                                    bg='#1a1a2e', fg='lightgray', font=("Courier", 9),
                                                    relief='flat', borderwidth=0)
        self.threat_feed.grid(row=1, column=0, sticky='nsew', padx=5, pady=(3, 5))

    def read_log_file(self):
        """Read all lines from security.log"""
        log_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs", "security.log")
        if os.path.exists(log_file):
            with open(log_file, 'r', encoding='utf-8-sig') as f:
                return f.readlines()
        return []

    def detect_new_event(self, logs):
        """Check if there are new log entries"""
        current_count = len(logs)
        if current_count > self.last_line_count:
            # New lines detected
            new_lines = logs[self.last_line_count:]
            self.last_line_count = current_count
            return new_lines
        return []

    def process_event(self, event):
        """Process a new log event and update state"""
        print("New event detected:", event.strip())
        current_time = datetime.now().strftime("[%H:%M:%S]")
        self.threat_feed.insert(tk.END, f"{current_time} {event.strip()}\n")
        self.threat_feed.see(tk.END)  # Auto-scroll to bottom

        if 'FAILED LOGIN' in event or 'BRUTE FORCE SUSPECTED' in event:
            self.attack_type.set("Brute Force Attack")
            self.brute_count.set(self.brute_count.get() + 1)
            self.threat_level.set("HIGH")
            if not self.defense_active:
                self.defense_active = True
                self.defense_start = time.time()
                self.defense_step = 0
        elif 'SQL_INJECTION_ATTEMPT' in event:
            self.attack_type.set("SQL Injection Attack")
            self.sql_count.set(self.sql_count.get() + 1)
            self.threat_level.set("HIGH")
            if not self.defense_active:
                self.defense_active = True
                self.defense_start = time.time()
                self.defense_step = 0
        elif 'DOS_ATTACK' in event:
            self.attack_type.set("DoS Attack")
            self.dos_count.set(self.dos_count.get() + 1)
            self.threat_level.set("CRITICAL")
            if not self.defense_active:
                self.defense_active = True
                self.defense_start = time.time()
                self.defense_step = 0
        elif 'UPLOAD_ATTEMPT' in event:
            # Count as DoS attempt
            self.dos_count.set(self.dos_count.get() + 1)

        # Update attack timeline
        now = datetime.now()
        self.attack_times.append(now)
        self.attack_counts.append(len([t for t in self.attack_times if (now - t).seconds < 300]))  # Last 5 minutes

    def update_dashboard(self):
        """Update the GUI dashboard every 2 seconds"""
        logs = self.read_log_file()
        new_events = self.detect_new_event(logs)

        # Process new events
        for event in new_events:
            self.process_event(event)

        # Handle defense process animation
        if self.defense_active:
            elapsed = time.time() - self.defense_start
            steps = [
                ("UNDER ATTACK", "red", "Threat Detected\nAnalyzing..."),
                ("UNDER ATTACK", "red", "AI Analyzing\nPattern..."),
                ("AI DEFENDING", "yellow", "Deploying\nDefense"),
                ("AI DEFENDING", "yellow", "Blocking\nAttacker"),
                ("SAFE", "green", "System\nSecured")
            ]
            step_duration = 2.0  # seconds per step
            current_step = int(elapsed / step_duration)
            if current_step < len(steps):
                status, color, response = steps[current_step]
                self.system_status.set(status)
                self.ai_response.set(response)
                # Update status label color
                if hasattr(self, 'status_label'):
                    self.status_label.config(fg=color)
            else:
                self.defense_active = False
                self.system_status.set("SAFE")
                self.ai_response.set("Monitoring\nActive")
                self.attack_type.set("None")
                self.threat_level.set("LOW")
                if hasattr(self, 'status_label'):
                    self.status_label.config(fg='green')

        # Update threat level colors
        threat_colors = {'LOW': 'green', 'MEDIUM': 'yellow', 'HIGH': 'red', 'CRITICAL': 'red'}
        if hasattr(self, 'threat_label'):
            self.threat_label.config(fg=threat_colors.get(self.threat_level.get(), 'white'))

        # Update graphs
        self.update_line_graph()
        self.update_bar_graph()

        # Schedule next update
        self.root.after(2000, self.update_dashboard)

    def update_line_graph(self):
        """Update the attack activity line graph"""
        self.line_ax.clear()
        if self.attack_times:
            times = mdates.date2num(self.attack_times[-30:])  # Last 30 points for smoother view
            counts = self.attack_counts[-30:]
            self.line_ax.plot(times, counts, color='red', linewidth=3, marker='o', markersize=4, markerfacecolor='red', markeredgecolor='white')
            self.line_ax.set_title('Attack Activity Over Time', color='white', fontsize=14, pad=10)
            self.line_ax.set_xlabel('Time', color='white', fontsize=12, labelpad=5)
            self.line_ax.set_ylabel('Attacks', color='white', fontsize=12, labelpad=5)
            self.line_ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
            self.line_ax.tick_params(axis='x', rotation=45, labelsize=10)
            self.line_ax.tick_params(axis='y', labelsize=10)
            self.line_ax.grid(True, alpha=0.3, color='white', linestyle='--')
            self.line_ax.set_xlim(min(times), max(times))
        else:
            self.line_ax.text(0.5, 0.5, 'No attack data yet', ha='center', va='center',
                            color='white', fontsize=12, transform=self.line_ax.transAxes)
        self.line_fig.tight_layout(pad=2.0)
        self.line_canvas.draw()

    def update_bar_graph(self):
        """Update the attack distribution bar chart"""
        self.bar_ax.clear()
        attacks = ['Brute Force', 'SQL Injection', 'DoS']
        counts = [self.brute_count.get(), self.sql_count.get(), self.dos_count.get()]
        colors = ['#ff4444', '#ff8844', '#ffaa44']  # Red, orange, yellow-orange

        bars = self.bar_ax.bar(attacks, counts, color=colors, width=0.6, edgecolor='white', linewidth=1)

        self.bar_ax.set_title('Attack Distribution', color='white', fontsize=14, pad=10)
        self.bar_ax.set_ylabel('Count', color='white', fontsize=12, labelpad=5)
        self.bar_ax.tick_params(axis='x', labelsize=11, rotation=0)
        self.bar_ax.tick_params(axis='y', labelsize=10)

        # Add value labels above bars
        for bar, count in zip(bars, counts):
            height = bar.get_height()
            self.bar_ax.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                           f'{count}', ha='center', va='bottom', color='white', fontsize=12, fontweight='bold')

        # Set y-axis to start from 0 and add some padding
        max_count = max(counts) if counts else 1
        self.bar_ax.set_ylim(0, max_count * 1.2)

        self.bar_fig.tight_layout(pad=2.0)
        self.bar_canvas.draw()

    def monitor_logs(self):
        """Background thread to monitor logs (kept for compatibility)"""
        pass  # Logic moved to update_dashboard

if __name__ == '__main__':
    root = tk.Tk()
    app = SecurityMonitor(root)
    root.mainloop()
