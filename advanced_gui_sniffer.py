#!/usr/bin/env python3
"""
Pinaka - Advanced Packet Analyzer
A sophisticated network packet sniffer with AI-powered analysis and modern GUI
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from threading import Thread, Event, Lock
import queue
import time
import json
import sqlite3
import logging
from datetime import datetime
from scapy.all import *
from ipwhois import IPWhois
from ipwhois.exceptions import ASNRegistryError
import requests
import os
import sys
import traceback

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(\'pinaka_debug.log\'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configuration
CONFIG = {
    \'log_file\': \'pinaka_packets.log\',
    \'pcap_file\': \'pinaka_capture.pcap\',
    \'db_file\': \'pinaka_analysis.db\',
    \'suspicious_keywords\': [\'password=\', \'username=\', \'login=\', \'admin\', \'root\'],
    \'threat_intelligence_api\': \'https://api.abuseipdb.com/api/v2/check\',
    \'max_packets_display\': 1000,
    \'capture_interface\': None
}

class ThreatAnalyzer:
    """AI-powered threat detection and analysis"""
    
    def __init__(self):
        self.threat_patterns = {
            \'port_scan\': {\'ports\': set(), \'threshold\': 10},
            \'dos_attack\': {\'packet_count\': 0, \'time_window\': 60},
            \'suspicious_payload\': {\'keywords\': CONFIG[\'suspicious_keywords\']}
        }
        self.lock = Lock()
    
    def analyze_packet(self, packet):
        """Analyze packet for threats and anomalies"""
        threats = []
        try:
            with self.lock:
                # Check for port scanning
                if packet.haslayer(TCP):
                    dst_port = packet[TCP].dport
                    self.threat_patterns[\'port_scan\'][\'ports\'].add(dst_port)
                    if len(self.threat_patterns[\'port_scan\'][\'ports\']) > self.threat_patterns[\'port_scan\'][\'threshold\']:
                        threats.append(\'Port Scan Detected\')
                
                # Check for suspicious payload
                if packet.haslayer(Raw):
                    payload = str(packet[Raw].load).lower()
                    for keyword in self.threat_patterns[\'suspicious_payload\'][\'keywords\']:
                        if keyword in payload:
                            threats.append(f\'Suspicious Content: {keyword}\')
                
                # Check for DDoS patterns
                self.threat_patterns[\'dos_attack\'][\'packet_count\'] += 1
        except Exception as e:
            logger.error(f"Error analyzing packet: {e}")
        
        return threats
    
    def get_geo_location(self, ip):
        """Get geographical location of IP address"""
        try:
            if not ip.startswith((\'192.168.\', \'10.\', \'172.16.\', \'127.\')):
                obj = IPWhois(ip)
                results = obj.lookup_rdap(depth=1)
                return {
                    \'country\': results.get(\'asn_country_code\', \'Unknown\'),
                    \'asn\': results.get(\'asn\', \'Unknown\'),
                    \'description\': results.get(\'asn_description\', \'Unknown\')
                }
        except Exception as e:
            logger.debug(f"Geo-location lookup failed for {ip}: {e}")
        return {\'country\': \'Private/Local\', \'asn\': \'N/A\', \'description\': \'Private Network\'}

class PacketDatabase:
    """SQLite database for packet storage and analysis"""
    
    def __init__(self, db_file):
        self.db_file = db_file
        self.lock = Lock()
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute(\'\'\'
                CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    protocol TEXT,
                    length INTEGER,
                    info TEXT,
                    threats TEXT,
                    geo_info TEXT
                )
            \'\'\')
            
            cursor.execute(\'\'\'
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    start_time REAL,
                    end_time REAL,
                    packet_count INTEGER,
                    threats_detected INTEGER
                )
            \'\'\')
            
            conn.commit()
            conn.close()
            logger.info("Database initialized successfully")
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
    
    def store_packet(self, packet_data):
        """Store packet data in database"""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_file)
                cursor = conn.cursor()
                
                cursor.execute(\'\'\'
                    INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, length, info, threats, geo_info)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                \'\'\', packet_data)
                
                conn.commit()
                conn.close()
        except Exception as e:
            logger.error(f"Error storing packet data: {e}")

class PinakaGUI:
    """Main GUI application for Pinaka packet analyzer"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Pinaka - Advanced Packet Analyzer")
        self.root.geometry("1400x900")
        self.root.configure(bg=\'#0a0e1a\')
        
        # Set window icon
        try:
            icon_path = os.path.join(os.path.dirname(__file__), \'pinaka_icon.ico\')
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
        except Exception as e:
            logger.warning(f"Could not set window icon: {e}")
        
        # Initialize components
        self.threat_analyzer = ThreatAnalyzer()
        self.packet_db = PacketDatabase(CONFIG[\'db_file\'])
        self.packet_queue = queue.Queue()
        self.capture_thread = None
        self.is_capturing = False
        self.stop_event = Event()
        self.packets = []
        self.stats_lock = Lock()
        
        # Statistics
        self.stats = {
            \'total_packets\': 0,
            \'tcp_packets\': 0,
            \'udp_packets\': 0,
            \'dns_packets\': 0,
            \'http_packets\': 0,
            \'threats_detected\': 0
        }
        
        logger.info("Initializing GUI components")
        self.setup_styles()
        self.create_widgets()
        self.start_packet_processor()
        logger.info("GUI initialization complete")
    
    def setup_styles(self):
        """Configure custom styles for the application"""
        try:
            style = ttk.Style()
            style.theme_use(\'clam\')
            
            # Configure colors for dark theme
            style.configure(\'Dark.TFrame\', background=\'#1a1d29\')
            style.configure(\'Dark.TLabel\', background=\'#1a1d29\', foreground=\'#f7fafc\')
            style.configure(\'Dark.TButton\', background=\'#2d3748\', foreground=\'#f7fafc\')
            style.configure(\'Accent.TButton\', background=\'#00d4ff\', foreground=\'#0a0e1a\')
            style.configure(\'Danger.TButton\', background=\'#ef4444\', foreground=\'#f7fafc\')
            logger.debug("Styles configured successfully")
        except Exception as e:
            logger.error(f"Error setting up styles: {e}")
    
    def create_widgets(self):
        """Create and layout all GUI widgets"""
        try:
            # Main container
            main_frame = ttk.Frame(self.root, style=\'Dark.TFrame\')
            main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            # Header frame
            self.create_header(main_frame)
            
            # Stats frame
            self.create_stats_frame(main_frame)
            
            # Filter frame
            self.create_filter_frame(main_frame)
            
            # Main content frame
            content_frame = ttk.Frame(main_frame, style=\'Dark.TFrame\')
            content_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
            
            # Create paned window for resizable panels
            paned_window = ttk.PanedWindow(content_frame, orient=tk.HORIZONTAL)
            paned_window.pack(fill=tk.BOTH, expand=True)
            
            # Left panel - Packet list and details
            left_panel = ttk.Frame(paned_window, style=\'Dark.TFrame\')
            paned_window.add(left_panel, weight=3)
            
            # Right panel - AI insights and tools
            right_panel = ttk.Frame(paned_window, style=\'Dark.TFrame\')
            paned_window.add(right_panel, weight=1)
            
            self.create_packet_list(left_panel)
            self.create_packet_details(left_panel)
            self.create_ai_panel(right_panel)
            logger.debug("Widgets created successfully")
        except Exception as e:
            logger.error(f"Error creating widgets: {e}")
            messagebox.showerror("GUI Error", f"Failed to create interface: {e}")
    
    def create_header(self, parent):
        """Create header with logo and controls"""
        header_frame = ttk.Frame(parent, style=\'Dark.TFrame\')
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Logo and title
        title_frame = ttk.Frame(header_frame, style=\'Dark.TFrame\')
        title_frame.pack(side=tk.LEFT)
        
        title_label = ttk.Label(title_frame, text="🏹 Pinaka", font=(\'Inter\', 24, \'bold\'), 
                               style=\'Dark.TLabel\')
        title_label.pack(side=tk.LEFT)
        
        subtitle_label = ttk.Label(title_frame, text="Advanced Packet Analyzer", 
                                  font=(\'Inter\', 12), style=\'Dark.TLabel\')
        subtitle_label.pack(side=tk.LEFT, padx=(10, 0))
        
        # Control buttons
        controls_frame = ttk.Frame(header_frame, style=\'Dark.TFrame\')
        controls_frame.pack(side=tk.RIGHT)
        
        self.start_button = ttk.Button(controls_frame, text="▶ Start Capture", 
                                      command=self.toggle_capture_safe, style=\'Accent.TButton\')
        self.start_button.pack(side=tk.LEFT, padx=(0, 5))
        
        ttk.Button(controls_frame, text="📁 Open", command=self.open_file,
                  style=\'Dark.TButton\').pack(side=tk.LEFT, padx=(0, 5))
        
        ttk.Button(controls_frame, text="💾 Save", command=self.save_file,
                  style=\'Dark.TButton\').pack(side=tk.LEFT, padx=(0, 5))
        
        ttk.Button(controls_frame, text="⚙ Settings", command=self.show_settings,
                  style=\'Dark.TButton\').pack(side=tk.LEFT)
    
    def create_stats_frame(self, parent):
        """Create statistics display frame"""
        stats_frame = ttk.LabelFrame(parent, text="📊 Statistics", style=\'Dark.TFrame\')
        stats_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Stats labels
        self.stats_labels = {}
        stats_container = ttk.Frame(stats_frame, style=\'Dark.TFrame\')
        stats_container.pack(fill=tk.X, padx=10, pady=5)
        
        stats_items = [
            (\'Total\', \'total_packets\'),
            (\'TCP\', \'tcp_packets\'),
            (\'UDP\', \'udp_packets\'),
            (\'DNS\', \'dns_packets\'),
            (\'HTTP\', \'http_packets\'),
            (\'🛡 Threats\', \'threats_detected\')
        ]
        
        for i, (label, key) in enumerate(stats_items):
            frame = ttk.Frame(stats_container, style=\'Dark.TFrame\')
            frame.pack(side=tk.LEFT, padx=(0, 20))
            
            ttk.Label(frame, text=f"{label}:", style=\'Dark.TLabel\').pack()
            self.stats_labels[key] = ttk.Label(frame, text="0", font=(\'JetBrains Mono\', 12, \'bold\'),
                                              style=\'Dark.TLabel\')
            self.stats_labels[key].pack()
    
    def create_filter_frame(self, parent):
        """Create filter and search controls"""
        filter_frame = ttk.LabelFrame(parent, text="🔍 Filters & Search", style=\'Dark.TFrame\')
        filter_frame.pack(fill=tk.X, pady=(0, 10))
        
        filter_container = ttk.Frame(filter_frame, style=\'Dark.TFrame\')
        filter_container.pack(fill=tk.X, padx=10, pady=5)
        
        # Filter entry
        ttk.Label(filter_container, text="Filter:", style=\'Dark.TLabel\').pack(side=tk.LEFT)
        self.filter_var = tk.StringVar()
        self.filter_entry = ttk.Entry(filter_container, textvariable=self.filter_var, width=50)
        self.filter_entry.pack(side=tk.LEFT, padx=(5, 10))
        self.filter_entry.bind(\'<KeyRelease>\', self.apply_filter)
        
        # Quick filter buttons
        quick_filters = [
            ("TCP", "tcp"),
            ("UDP", "udp"),
            ("DNS", "dns"),
            ("HTTP", "http"),
            ("🚨 Threats", "threat")
        ]
        
        for text, filter_type in quick_filters:
            btn = ttk.Button(filter_container, text=text, 
                           command=lambda f=filter_type: self.apply_quick_filter(f),
                           style=\'Dark.TButton\')
            btn.pack(side=tk.LEFT, padx=(0, 5))
    
    def create_packet_list(self, parent):
        """Create packet list with treeview"""
        list_frame = ttk.LabelFrame(parent, text="📦 Packet List", style=\'Dark.TFrame\')
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        
        # Treeview for packet list
        columns = (\'No\', \'Time\', \'Source\', \'Destination\', \'Protocol\', \'Length\', \'Info\', \'Threats\')
        self.packet_tree = ttk.Treeview(list_frame, columns=columns, show=\'headings\', height=15)
        
        # Configure columns
        column_widths = {\'No\': 50, \'Time\': 100, \'Source\': 120, \'Destination\': 120, 
                        \'Protocol\': 80, \'Length\': 80, \'Info\': 300, \'Threats\': 100}
        
        for col in columns:
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=column_widths.get(col, 100))
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        h_scrollbar = ttk.Scrollbar(list_frame, orient=tk.HORIZONTAL, command=self.packet_tree.xview)
        self.packet_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Pack treeview and scrollbars
        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Bind selection event
        self.packet_tree.bind(\'<<TreeviewSelect>>\', self.on_packet_select)
    
    def create_packet_details(self, parent):
        """Create packet details panel"""
        details_frame = ttk.LabelFrame(parent, text="🔍 Packet Details", style=\'Dark.TFrame\')
        details_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
        
        # Notebook for different views
        notebook = ttk.Notebook(details_frame)
        notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Protocol details tab
        protocol_frame = ttk.Frame(notebook, style=\'Dark.TFrame\')
        notebook.add(protocol_frame, text="Protocol Details")
        
        self.protocol_text = scrolledtext.ScrolledText(protocol_frame, height=8, 
                                                      bg=\'#2d3748\', fg=\'#f7fafc\',
                                                      font=(\'JetBrains Mono\', 10))
        self.protocol_text.pack(fill=tk.BOTH, expand=True)
        
        # Hex dump tab
        hex_frame = ttk.Frame(notebook, style=\'Dark.TFrame\')
        notebook.add(hex_frame, text="Hex Dump")
        
        self.hex_text = scrolledtext.ScrolledText(hex_frame, height=8,
                                                 bg=\'#2d3748\', fg=\'#f7fafc\',
                                                 font=(\'JetBrains Mono\', 10))
        self.hex_text.pack(fill=tk.BOTH, expand=True)
    
    def create_ai_panel(self, parent):
        """Create AI insights and tools panel"""
        ai_frame = ttk.LabelFrame(parent, text="🧠 AI Insights", style=\'Dark.TFrame\')
        ai_frame.pack(fill=tk.BOTH, expand=True)
        
        # AI insights text area
        self.ai_text = scrolledtext.ScrolledText(ai_frame, height=10,
                                                bg=\'#1a1d29\', fg=\'#00d4ff\',
                                                font=(\'Inter\', 10))
        self.ai_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add initial AI message
        self.ai_text.insert(tk.END, "🧠 Pinaka AI Assistant Ready\n")
        self.ai_text.insert(tk.END, "━" * 30 + "\n\n")
        self.ai_text.insert(tk.END, "🛡 Monitoring network for threats...\n")
        self.ai_text.insert(tk.END, "📊 Real-time analysis active\n")
        self.ai_text.insert(tk.END, "🌍 Geo-location tracking enabled\n\n")
        
        # AI controls
        ai_controls = ttk.Frame(ai_frame, style=\'Dark.TFrame\')
        ai_controls.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        ttk.Button(ai_controls, text="🔮 Generate Report", 
                  command=lambda: Thread(target=self.generate_ai_report, daemon=True).start(), style=\'Accent.TButton\').pack(fill=tk.X, pady=(0, 2))
        
        ttk.Button(ai_controls, text="🌐 3D Network View", 
                  command=self.show_3d_view, style=\'Dark.TButton\').pack(fill=tk.X, pady=(0, 2))
        
        ttk.Button(ai_controls, text="👥 Collaboration Mode", 
                  command=self.enable_collaboration, style=\'Dark.TButton\').pack(fill=tk.X)
    
    def toggle_capture_safe(self):
        """Safely start or stop packet capture with error handling"""
        try:
            logger.info(f"Toggle capture called, current state: {self.is_capturing}")
            if not self.is_capturing:
                self.start_capture()
            else:
                self.stop_capture()
        except Exception as e:
            logger.error(f"Error in toggle_capture: {e}")
            logger.error(traceback.format_exc())
            messagebox.showerror("Capture Error", f"Failed to toggle capture: {e}")
    
    def start_capture(self):
        """Start packet capture in separate thread"""
        try:
            logger.info("Starting packet capture")
            self.is_capturing = True
            self.stop_event.clear()
            
            # Update button immediately
            self.start_button.configure(text="⏹ Stop Capture", style=\'Danger.TButton\')
            self.root.update_idletasks()
            
            # Start capture thread
            self.capture_thread = Thread(target=self.capture_packets_safe, daemon=True)
            self.capture_thread.start()
            
            # Update AI text
            self.ai_text.insert(tk.END, f"🚀 Capture started at {datetime.now().strftime(\'%H:%M:%S\')}\n")
            self.ai_text.see(tk.END)
            
            logger.info("Packet capture started successfully")
        except Exception as e:
            logger.error(f"Error starting capture: {e}")
            logger.error(traceback.format_exc())
            self.is_capturing = False
            self.start_button.configure(text="▶ Start Capture", style=\'Accent.TButton\')
            messagebox.showerror("Capture Error", f"Failed to start capture: {e}")
    
    def stop_capture(self):
        """Stop packet capture"""
        try:
            logger.info("Stopping packet capture")
            self.is_capturing = False
            self.stop_event.set()
            self.start_button.configure(text="▶ Start Capture", style=\'Accent.TButton\')
            
            self.ai_text.insert(tk.END, f"⏹ Capture stopped at {datetime.now().strftime(\'%H:%M:%S\')}\n")
            self.ai_text.see(tk.END)
            
            logger.info("Packet capture stopped successfully")
        except Exception as e:
            logger.error(f"Error stopping capture: {e}")
            messagebox.showerror("Stop Error", f"Failed to stop capture: {e}")
    
    def capture_packets_safe(self):
        """Safely capture packets using Scapy with comprehensive error handling"""
        def packet_handler(packet):
            try:
                if self.stop_event.is_set():
                    return
                self.packet_queue.put(packet)
                logger.debug(f"Packet queued: {packet.summary()}")
            except Exception as e:
                logger.error(f"Error in packet handler: {e}")
        
        try:
            logger.info("Starting packet sniffing")
            # Continuously sniff packets until stop_event is set
            # Using a small timeout to allow stop_filter to be checked regularly
            sniff(prn=packet_handler, stop_filter=lambda x: self.stop_event.is_set(), store=0, timeout=0.1)
            logger.info("Packet sniffing stopped")
        except Exception as e:
            logger.error(f"Critical error in capture_packets: {e}")
            logger.error(traceback.format_exc())
            self.packet_queue.put((\'error\', str(e)))
    
    def start_packet_processor(self):
        """Start packet processing in main thread"""
        try:
            self.process_packet_queue()
        except Exception as e:
            logger.error(f"Error starting packet processor: {e}")
    
    def process_packet_queue(self):
        """Process packets from queue with error handling"""
        try:
            processed_count = 0
            while processed_count < 10:  # Limit processing per cycle to avoid blocking
                try:
                    packet_data = self.packet_queue.get_nowait()
                    if isinstance(packet_data, tuple) and packet_data[0] == \'error\':
                        logger.error(f"Capture error received: {packet_data[1]}")
                        messagebox.showerror("Capture Error", packet_data[1])
                        self.stop_capture()
                        break
                    
                    # Process packet in a separate thread to avoid blocking GUI
                    Thread(target=self._process_single_packet, args=(packet_data,), daemon=True).start()
                    processed_count += 1
                    
                except queue.Empty:
                    break
                except Exception as e:
                    logger.error(f"Error processing packet from queue: {e}")
        except Exception as e:
            logger.error(f"Critical error in process_packet_queue: {e}")
        
        # Schedule next processing
        self.root.after(100, self.process_packet_queue)
    
    def _process_single_packet(self, packet):
        """Process individual packet (run in a separate thread)"""
        try:
            # Extract packet information
            packet_info = self.extract_packet_info(packet)
            
            # Analyze for threats
            threats = self.threat_analyzer.analyze_packet(packet)
            packet_info[\'threats\'] = threats
            
            # Store in database (blocking operation)
            self.store_packet_data(packet_info)

            # Update GUI elements in the main thread
            self.root.after(0, self.update_gui_with_packet, packet_info)
            
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            logger.debug(traceback.format_exc())

    def update_gui_with_packet(self, packet_info):
        """Update GUI elements with processed packet info (run in main thread)"""
        try:
            self.update_statistics(packet_info)
            self.add_packet_to_list(packet_info)
            if packet_info.get(\'threats\'):
                self.ai_text.insert(tk.END, f"🚨 THREAT DETECTED: {\', \'.join(packet_info[\'threats\'])}\n")
                self.ai_text.insert(tk.END, f"   Source: {packet_info[\'src\']} → {packet_info[\'dst\]}\n")
                self.ai_text.see(tk.END)
        except Exception as e:
            logger.error(f"Error updating GUI with packet: {e}")
    
    def extract_packet_info(self, packet):
        """Extract relevant information from packet"""
        info = {
            \'timestamp\': time.time(),
            \'src\': \'Unknown\',
            \'dst\': \'Unknown\',
            \'protocol\': \'Unknown\',
            \'length\': len(packet),
            \'info\': packet.summary(),
            \'raw_packet\': packet
        }
        
        try:
            if packet.haslayer(IP):
                info[\'src\'] = packet[IP].src
                info[\'dst\'] = packet[IP].dst
                
                if packet.haslayer(TCP):
                    info[\'protocol\'] = \'TCP\'
                    info[\'info\'] = f"TCP {packet[TCP].sport} → {packet[TCP].dport}"
                elif packet.haslayer(UDP):
                    info[\'protocol\'] = \'UDP\'
                    info[\'info\'] = f"UDP {packet[UDP].sport} → {packet[UDP].dport}"
                elif packet.haslayer(ICMP):
                    info[\'protocol\'] = \'ICMP\'
            
            if packet.haslayer(DNS):
                info[\'protocol\'] = \'DNS\'
                if packet.haslayer(DNSQR):
                    info[\'info\'] = f"DNS Query: {packet[DNSQR].qname.decode()}"
        except Exception as e:
            logger.error(f"Error extracting packet info: {e}")
        
        return info
    
    def update_statistics(self, packet_info):
        """Update packet statistics"""
        try:
            with self.stats_lock:
                self.stats[\'total_packets\'] += 1
                
                protocol = packet_info[\'protocol\'].lower()
                if protocol == \'tcp\':
                    self.stats[\'tcp_packets\'] += 1
                elif protocol == \'udp\':
                    self.stats[\'udp_packets\'] += 1
                elif protocol == \'dns\':
                    self.stats[\'dns_packets\'] += 1
                elif \'http\' in packet_info[\'info\'].lower():
                    self.stats[\'http_packets\'] += 1
                
                if packet_info.get(\'threats\'):
                    self.stats[\'threats_detected\'] += 1
                
                # Update GUI labels
                for key, label in self.stats_labels.items():
                    label.configure(text=str(self.stats[key]))
        except Exception as e:
            logger.error(f"Error updating statistics: {e}")
    
    def add_packet_to_list(self, packet_info):
        """Add packet to the treeview list"""
        try:
            # Limit displayed packets for performance
            if len(self.packets) >= CONFIG[\'max_packets_display\']:
                # Remove oldest packet
                oldest_item = self.packet_tree.get_children()[0]
                self.packet_tree.delete(oldest_item)
                self.packets.pop(0)
            
            self.packets.append(packet_info)
            
            # Format time
            time_str = datetime.fromtimestamp(packet_info[\'timestamp\']).strftime(\'%H:%M:%S.%f\')[:-3]
            
            # Format threats
            threats_str = \', \'.join(packet_info.get(\'threats\', [])) if packet_info.get(\'threats\') else \'\'
            
            # Insert into treeview
            item = self.packet_tree.insert(\'\', \'end\', values=(
                len(self.packets),
                time_str,
                packet_info[\'src\'],
                packet_info[\'dst\'],
                packet_info[\'protocol\'],
                packet_info[\'length\'],
                packet_info[\'info\'][:50] + \'...\' if len(packet_info[\'info\']) > 50 else packet_info[\'info\'],
                threats_str
            ))
            
            # Color code based on protocol and threats
            if packet_info.get(\'threats\'):
                self.packet_tree.set(item, \'Threats\', \'🚨 \' + threats_str)
            
            # Auto-scroll to latest packet
            self.packet_tree.see(item)
        except Exception as e:
            logger.error(f"Error adding packet to list: {e}")
    
    def store_packet_data(self, packet_info):
        """Store packet data in database"""
        try:
            # Get geo location for external IPs (can be blocking)
            geo_info = {}
            if not packet_info[\'dst\'].startswith((\'192.168.\', \'10.\', \'172.16.\', \'127.\')):
                geo_info = self.threat_analyzer.get_geo_location(packet_info[\'dst\'])
            
            packet_data = (
                packet_info[\'timestamp\'],
                packet_info[\'src\'],
                packet_info[\'dst\'],
                packet_info[\'protocol\'],
                packet_info[\'length\'],
                packet_info[\'info\'],
                json.dumps(packet_info.get(\'threats\', [])),
                json.dumps(geo_info)
            )
            
            self.packet_db.store_packet(packet_data)
        except Exception as e:
            logger.error(f"Error storing packet data: {e}")
    
    def on_packet_select(self, event):
        """Handle packet selection in treeview"""
        try:
            selection = self.packet_tree.selection()
            if not selection:
                return
            
            item = selection[0]
            packet_index = int(self.packet_tree.item(item, \'values\')[0]) - 1
            
            if 0 <= packet_index < len(self.packets):
                packet_info = self.packets[packet_index]
                # Display packet details in a separate thread
                Thread(target=self._display_packet_details_threaded, args=(packet_info,), daemon=True).start()
        except Exception as e:
            logger.error(f"Error in packet selection: {e}")
    
    def _display_packet_details_threaded(self, packet_info):
        """Display detailed packet information (run in a separate thread)"""
        try:
            # Prepare data for GUI update
            protocol_text_content = self._format_protocol_details(packet_info[\'raw_packet\'])
            hex_text_content = self.format_hex_dump(bytes(packet_info[\'raw_packet\']))
            
            # Update GUI in the main thread
            self.root.after(0, self._update_packet_details_gui, protocol_text_content, hex_text_content)
        except Exception as e:
            logger.error(f"Error displaying packet details: {e}")

    def _format_protocol_details(self, packet):
        """Format protocol details for display"""
        try:
            details = f"Packet #{len(self.packets)}\n" \
                      f"=" * 50 + "\n\n"
            
            layer_count = 0
            current_layer = packet
            
            while current_layer:
                layer_count += 1
                layer_name = current_layer.__class__.__name__
                details += f"Layer {layer_count}: {layer_name}\n"
                details += "-" * 30 + "\n"
                
                for field_name, field_value in current_layer.fields.items():
                    details += f"  {field_name}: {field_value}\n"
                
                details += "\n"
                current_layer = current_layer.payload if hasattr(current_layer, \'payload\') else None
            return details
        except Exception as e:
            logger.error(f"Error formatting protocol details: {e}")
            return f"Error formatting packet details: {e}"

    def _update_packet_details_gui(self, protocol_text_content, hex_text_content):
        """Update packet details GUI elements (run in main thread)"""
        try:
            self.protocol_text.delete(1.0, tk.END)
            self.protocol_text.insert(tk.END, protocol_text_content)
            
            self.hex_text.delete(1.0, tk.END)
            self.hex_text.insert(tk.END, hex_text_content)
        except Exception as e:
            logger.error(f"Error updating packet details GUI: {e}")
    
    def format_hex_dump(self, data):
        """Format binary data as hex dump"""
        try:
            lines = []
            for i in range(0, len(data), 16):
                chunk = data[i:i+16]
                hex_part = \' \'.join(f\'{b:02x}\' for b in chunk)
                ascii_part = \'\'.join(chr(b) if 32 <= b <= 126 else \'.\' for b in chunk)
                lines.append(f\'{i:04x}: {hex_part:<48} {ascii_part}\')
            return \'\n\'.join(lines)
        except Exception as e:
            logger.error(f"Error formatting hex dump: {e}")
            return f"Error formatting hex dump: {e}"
    
    def apply_filter(self, event=None):
        """Apply filter to packet list"""
        try:
            filter_text = self.filter_var.get().lower()
            
            # Clear current display
            for item in self.packet_tree.get_children():
                self.packet_tree.delete(item)
            
            # Re-populate with filtered packets
            for i, packet_info in enumerate(self.packets):
                if self.packet_matches_filter(packet_info, filter_text):
                    time_str = datetime.fromtimestamp(packet_info[\'timestamp\']).strftime(\'%H:%M:%S.%f\')[:-3]
                    threats_str = \', \'.join(packet_info.get(\'threats\', [])) if packet_info.get(\'threats\') else \'\'
                    
                    self.packet_tree.insert(\'\', \'end\', values=(
                        i + 1,
                        time_str,
                        packet_info[\'src\'],
                        packet_info[\'dst\'],
                        packet_info[\'protocol\'],
                        packet_info[\'length\'],
                        packet_info[\'info\'][:50] + \'...\' if len(packet_info[\'info\']) > 50 else packet_info[\'info\'],
                        threats_str
                    ))
        except Exception as e:
            logger.error(f"Error applying filter: {e}")
    
    def packet_matches_filter(self, packet_info, filter_text):
        """Check if packet matches filter criteria"""
        try:
            if not filter_text:
                return True
            
            searchable_text = \' \'.join([
                packet_info[\'src\'],
                packet_info[\'dst\'],
                packet_info[\'protocol\'],
                packet_info[\'info\'],
                \' \'.join(packet_info.get(\'threats\', []))
            ]).lower()
            
            return filter_text in searchable_text
        except Exception as e:
            logger.error(f"Error matching filter: {e}")
            return False
    
    def apply_quick_filter(self, filter_type):
        """Apply predefined quick filters"""
        try:
            filter_map = {
                \'tcp\': \'tcp\',
                \'udp\': \'udp\',
                \'dns\': \'dns\',
                \'http\': \'http\',
                \'threat\': \'🚨\'
            }
            
            self.filter_var.set(filter_map.get(filter_type, \'\'))
            self.apply_filter()
        except Exception as e:
            logger.error(f"Error applying quick filter: {e}")
    
    def open_file(self):
        """Open PCAP file"""
        try:
            file_path = filedialog.askopenfilename(
                title="Open PCAP File",
                filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")]
            )
            
            if file_path:
                # Open file in a separate thread
                Thread(target=self._open_file_threaded, args=(file_path,), daemon=True).start()
        except Exception as e:
            logger.error(f"Error opening file dialog: {e}")
            messagebox.showerror("File Error", f"Failed to open file dialog: {e}")

    def _open_file_threaded(self, file_path):
        """Open PCAP file and process packets (run in a separate thread)"""
        try:
            packets = rdpcap(file_path)
            self.root.after(0, self.ai_text.insert, tk.END, f"📁 Loaded {len(packets)} packets from {os.path.basename(file_path)}\n")
            self.root.after(0, self.ai_text.see, tk.END)
            
            for packet in packets:
                self._process_single_packet(packet)
            
        except Exception as e:
            logger.error(f"Error opening file {file_path}: {e}")
            self.root.after(0, messagebox.showerror, "Error", f"Failed to open file: {e}")
    
    def save_file(self):
        """Save captured packets to PCAP file"""
        try:
            if not self.packets:
                messagebox.showwarning("Warning", "No packets to save")
                return
            
            file_path = filedialog.asksaveasfilename(
                title="Save PCAP File",
                defaultextension=".pcap",
                filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
            )
            
            if file_path:
                # Save file in a separate thread
                Thread(target=self._save_file_threaded, args=(file_path,), daemon=True).start()
        except Exception as e:
            logger.error(f"Error in save file dialog: {e}")
            messagebox.showerror("Save Error", f"Failed to open save dialog: {e}")

    def _save_file_threaded(self, file_path):
        """Save captured packets to PCAP file (run in a separate thread)"""
        try:
            raw_packets = [p[\'raw_packet\'] for p in self.packets]
            wrpcap(file_path, raw_packets)
            self.root.after(0, messagebox.showinfo, "Success", f"Saved {len(raw_packets)} packets to {os.path.basename(file_path)}")
        except Exception as e:
            logger.error(f"Error saving file {file_path}: {e}")
            self.root.after(0, messagebox.showerror, "Error", f"Failed to save file: {e}")
    
    def show_settings(self):
        """Show settings dialog"""
        try:
            settings_window = tk.Toplevel(self.root)
            settings_window.title("Pinaka Settings")
            settings_window.geometry("400x300")
            settings_window.configure(bg=\'#1a1d29\')
            
            # Settings content
            ttk.Label(settings_window, text="Settings", font=(\'Inter\', 16, \'bold\'),
                     style=\'Dark.TLabel\').pack(pady=10)
            
            # Interface selection
            interface_frame = ttk.Frame(settings_window, style=\'Dark.TFrame\')
            interface_frame.pack(fill=tk.X, padx=20, pady=10)
            
            ttk.Label(interface_frame, text="Capture Interface:", style=\'Dark.TLabel\').pack(anchor=tk.W)
            interface_var = tk.StringVar(value=CONFIG.get(\'capture_interface\', \'auto\'))
            interface_combo = ttk.Combobox(interface_frame, textvariable=interface_var,
                                          values=[\'auto\', \'eth0\', \'wlan0\', \'any\'])
            interface_combo.pack(fill=tk.X, pady=(5, 0))
            
            # Buttons
            button_frame = ttk.Frame(settings_window, style=\'Dark.TFrame\')
            button_frame.pack(fill=tk.X, padx=20, pady=20)
            
            ttk.Button(button_frame, text="Save", style=\'Accent.TButton\').pack(side=tk.RIGHT, padx=(0, 5))
            ttk.Button(button_frame, text="Cancel", command=settings_window.destroy,
                      style=\'Dark.TButton\').pack(side=tk.RIGHT)
        except Exception as e:
            logger.error(f"Error showing settings: {e}")
            messagebox.showerror("Settings Error", f"Failed to open settings: {e}")
    
    def generate_ai_report(self):
        """Generate AI-powered analysis report"""
        try:
            self.ai_text.insert(tk.END, "\n🔮 Generating AI Report...\n")
            self.ai_text.insert(tk.END, "━" * 30 + "\n")
            
            # Analyze current session
            with self.stats_lock:
                total_packets = self.stats[\'total_packets\']
                threats = self.stats[\'threats_detected\']
            
            self.ai_text.insert(tk.END, f"📊 Session Analysis:\n")
            self.ai_text.insert(tk.END, f"   • Total Packets: {total_packets}\n")
            self.ai_text.insert(tk.END, f"   • Threats Detected: {threats}\n")
            self.ai_text.insert(tk.END, f"   • Risk Level: {\'HIGH\' if threats > 5 else \'MEDIUM\' if threats > 0 else \'LOW\'}\n")
            
            if threats > 0:
                self.ai_text.insert(tk.END, f"\n🚨 Security Recommendations:\n")
                self.ai_text.insert(tk.END, f"   • Review suspicious connections\n")
                self.ai_text.insert(tk.END, f"   • Consider firewall rules\n")
                self.ai_text.insert(tk.END, f"   • Monitor affected systems\n")
            
            self.ai_text.insert(tk.END, f"\n✅ Report generated at {datetime.now().strftime(\'%H:%M:%S\')}\n\n")
            self.ai_text.see(tk.END)
        except Exception as e:
            logger.error(f"Error generating AI report: {e}")
    
    def show_3d_view(self):
        """Show 3D network visualization (placeholder)"""
        try:
            messagebox.showinfo("3D Network View", 
                               "🌐 3D Network Visualization\n\n"
                               "This feature would show an interactive 3D representation "
                               "of your network topology with real-time traffic flows.\n\n"
                               "Coming in future updates!")
        except Exception as e:
            logger.error(f"Error showing 3D view: {e}")
    
    def enable_collaboration(self):
        """Enable collaboration mode (placeholder)"""
        try:
            messagebox.showinfo("Collaboration Mode",
                               "👥 Collaboration Mode\n\n"
                               "This feature would enable real-time collaboration "
                               "with team members for joint network analysis.\n\n"
                               "Coming in future updates!")
        except Exception as e:
            logger.error(f"Error enabling collaboration: {e}")

def main():
    """Main application entry point"""
    try:
        logger.info("Starting Pinaka application")
        
        # Check for admin privileges on Windows
        if sys.platform == "win32":
            try:
                import ctypes
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    messagebox.showwarning("Admin Required", 
                                         "Pinaka requires administrator privileges for packet capture.\n"
                                         "Please run as administrator.")
            except Exception as e:
                logger.warning(f"Could not check admin privileges: {e}")
        
        # Create and run GUI
        root = tk.Tk()
        app = PinakaGUI(root)
        
        logger.info("Starting main event loop")
        root.mainloop()
        
    except KeyboardInterrupt:
        logger.info("Application interrupted by user")
        print("\nShutting down Pinaka...")
    except Exception as e:
        logger.error(f"Critical error in main: {e}")
        logger.error(traceback.format_exc())
        print(f"Critical Error: {e}")

if __name__ == "__main__":
    main()

