#!/usr/bin/env python3
"""
Network Monitor GUI - Integrated Application

A comprehensive GUI application that combines all network monitoring functionality:
- Real-time device monitoring
- Network discovery
- Device management
- History viewing
- Settings configuration

Author: Exill18
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import threading
import time
import csv
import json
import ipaddress
import subprocess
import concurrent.futures
from datetime import datetime
from typing import List, Dict, Optional, Tuple
import os
import sys
import socket
import struct

# Import networking libraries
try:
    from ping3 import ping
except ImportError:
    messagebox.showerror("Error", "ping3 library not installed. Run: pip install ping3")
    sys.exit(1)

class NetworkMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Monitor - Integrated Application")
        self.root.geometry("1200x800")
        self.root.minsize(800, 600)
        
        # Initialize variables
        self.devices = []
        self.monitoring = False
        self.monitor_thread = None
        self.settings = {
            'monitor_interval': 10,
            'ping_timeout': 3,
            'max_retries': 2,
            'log_file': 'network_log.csv',
            'theme': 'azure',  # 'azure' or 'azure-dark'
            'auto_save': True
        }
        self.device_status = {}
        self.device_history = {}  # Track device status history for notifications
        self.notification_enabled = True
        
        # Load theme
        self.setup_theme()
        
        # Load saved data
        self.load_settings()
        self.load_devices()
        
        # Setup GUI
        self.setup_menu()
        self.setup_status_bar()
        self.setup_main_interface()
        
        # Bind close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
    def setup_theme(self):
        """Setup Azure theme"""
        try:
            # Load the theme
            theme_path = os.path.join(os.path.dirname(__file__), "theme", "azure.tcl")
            if os.path.exists(theme_path):
                self.root.tk.call("source", theme_path)
                
                # Set initial theme
                if self.settings.get('theme', 'azure') == 'azure-dark':
                    ttk.Style().theme_use('azure-dark')
                else:
                    ttk.Style().theme_use('azure')
            else:
                # Fallback to default theme
                ttk.Style().theme_use('clam')
        except Exception as e:
            print(f"Warning: Could not load Azure theme: {e}")
            ttk.Style().theme_use('clam')
    
    def setup_menu(self):
        """Create menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Save Configuration", command=self.save_config)
        file_menu.add_command(label="Load Configuration", command=self.load_config)
        file_menu.add_separator()
        file_menu.add_command(label="Export Log", command=self.export_log)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_closing)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Network Discovery", command=self.open_discovery_window)
        tools_menu.add_command(label="Ping Test", command=self.open_ping_test)
        tools_menu.add_separator()
        tools_menu.add_command(label="Settings", command=self.open_settings_window)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Light Theme", command=lambda: self.change_theme('azure'))
        view_menu.add_command(label="Dark Theme", command=lambda: self.change_theme('azure-dark'))
        view_menu.add_separator()
        view_menu.add_command(label="Refresh", command=self.refresh_display)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
    
    def setup_main_interface(self):
        """Create main interface with tabs"""
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Monitoring tab
        self.setup_monitoring_tab()
        
        # Device Management tab
        self.setup_device_management_tab()
        
        # Discovery tab
        self.setup_discovery_tab()
        
        # History tab
        self.setup_history_tab()
        
        # Statistics tab
        self.setup_statistics_tab()
    
    def setup_monitoring_tab(self):
        """Setup the real-time monitoring tab"""
        monitor_frame = ttk.Frame(self.notebook)
        self.notebook.add(monitor_frame, text="🔍 Live Monitoring")
        
        # Control buttons
        control_frame = ttk.Frame(monitor_frame)
        control_frame.pack(fill='x', padx=5, pady=5)
        
        self.start_btn = ttk.Button(control_frame, text="▶ Start Monitoring", 
                                   command=self.toggle_monitoring)
        self.start_btn.pack(side='left', padx=(0, 5))
        
        self.refresh_btn = ttk.Button(control_frame, text="🔄 Refresh", 
                                     command=self.manual_refresh)
        self.refresh_btn.pack(side='left', padx=(0, 5))
        
        # Status info
        info_frame = ttk.Frame(control_frame)
        info_frame.pack(side='right')
        
        self.status_label = ttk.Label(info_frame, text="Stopped")
        self.status_label.pack(side='right', padx=(5, 0))
        
        ttk.Label(info_frame, text="Status:").pack(side='right')
        
        # Device status treeview
        tree_frame = ttk.Frame(monitor_frame)
        tree_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Create treeview with scrollbars
        self.tree = ttk.Treeview(tree_frame, columns=('IP', 'Name', 'Status', 'Latency', 'Last Check'), 
                                show='headings', height=15)
        
        # Configure columns
        self.tree.heading('IP', text='IP Address')
        self.tree.heading('Name', text='Device Name')
        self.tree.heading('Status', text='Status')
        self.tree.heading('Latency', text='Latency')
        self.tree.heading('Last Check', text='Last Check')
        
        self.tree.column('IP', width=120)
        self.tree.column('Name', width=200)
        self.tree.column('Status', width=80)
        self.tree.column('Latency', width=80)
        self.tree.column('Last Check', width=150)
        
        # Add scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient='vertical', command=self.tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Pack treeview and scrollbars
        self.tree.grid(row=0, column=0, sticky='nsew')
        v_scrollbar.grid(row=0, column=1, sticky='ns')
        h_scrollbar.grid(row=1, column=0, sticky='ew')
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        # Summary frame
        summary_frame = ttk.LabelFrame(monitor_frame, text="Summary")
        summary_frame.pack(fill='x', padx=5, pady=5)
        
        self.summary_label = ttk.Label(summary_frame, text="No devices configured")
        self.summary_label.pack(pady=5)
    
    def setup_device_management_tab(self):
        """Setup the device management tab"""
        device_frame = ttk.Frame(self.notebook)
        self.notebook.add(device_frame, text="⚙️ Device Management")
        
        # Left frame for device list
        left_frame = ttk.Frame(device_frame)
        left_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        ttk.Label(left_frame, text="Configured Devices", font=('Segoe UI', 12, 'bold')).pack(anchor='w')
        
        # Device listbox with scrollbar
        list_frame = ttk.Frame(left_frame)
        list_frame.pack(fill='both', expand=True, pady=(5, 0))
        
        self.device_listbox = tk.Listbox(list_frame, font=('Consolas', 10))
        device_scrollbar = ttk.Scrollbar(list_frame, orient='vertical', command=self.device_listbox.yview)
        self.device_listbox.configure(yscrollcommand=device_scrollbar.set)
        
        self.device_listbox.pack(side='left', fill='both', expand=True)
        device_scrollbar.pack(side='right', fill='y')
        
        # Bind selection event
        self.device_listbox.bind('<<ListboxSelect>>', self.on_device_select)
        
        # Right frame for device details and controls
        right_frame = ttk.Frame(device_frame)
        right_frame.pack(side='right', fill='y', padx=5, pady=5)
        
        # Device form
        form_frame = ttk.LabelFrame(right_frame, text="Device Details")
        form_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Label(form_frame, text="IP Address:").grid(row=0, column=0, sticky='w', padx=5, pady=2)
        self.ip_entry = ttk.Entry(form_frame, width=20)
        self.ip_entry.grid(row=0, column=1, padx=5, pady=2)
        
        ttk.Label(form_frame, text="Device Name:").grid(row=1, column=0, sticky='w', padx=5, pady=2)
        self.name_entry = ttk.Entry(form_frame, width=20)
        self.name_entry.grid(row=1, column=1, padx=5, pady=2)
        
        # Buttons
        button_frame = ttk.Frame(right_frame)
        button_frame.pack(fill='x')
        
        ttk.Button(button_frame, text="➕ Add Device", 
                  command=self.add_device).pack(fill='x', pady=2)
        ttk.Button(button_frame, text="✏️ Update Device", 
                  command=self.update_device).pack(fill='x', pady=2)
        ttk.Button(button_frame, text="❌ Remove Device", 
                  command=self.remove_device).pack(fill='x', pady=2)
        ttk.Button(button_frame, text="🧪 Test Device", 
                  command=self.test_device).pack(fill='x', pady=2)
        
        self.refresh_device_list()
    
    def setup_discovery_tab(self):
        """Setup the network discovery tab"""
        discovery_frame = ttk.Frame(self.notebook)
        self.notebook.add(discovery_frame, text="🔍 Network Discovery")
        
        # Discovery controls
        control_frame = ttk.LabelFrame(discovery_frame, text="Network Scan Settings")
        control_frame.pack(fill='x', padx=5, pady=5)
        
        # Network selection row
        ttk.Label(control_frame, text="Network Range:").grid(row=0, column=0, sticky='w', padx=5, pady=2)
        self.network_combo = ttk.Combobox(control_frame, width=25)
        self.network_combo.grid(row=0, column=1, padx=5, pady=2, sticky='ew')
        
        ttk.Button(control_frame, text="🔄 Detect Networks", 
                  command=self.refresh_network_list).grid(row=0, column=2, padx=5, pady=2)
        
        ttk.Button(control_frame, text="🔍 Scan Network", 
                  command=self.start_network_scan).grid(row=0, column=3, padx=5, pady=2)
        
        # Network interface info row
        ttk.Label(control_frame, text="Interface Info:").grid(row=1, column=0, sticky='w', padx=5, pady=2)
        self.interface_label = ttk.Label(control_frame, text="No interface selected", foreground="gray")
        self.interface_label.grid(row=1, column=1, columnspan=3, sticky='w', padx=5, pady=2)
        
        # Hostname resolution option
        self.resolve_hostnames_var = tk.BooleanVar(value=True)
        hostname_check = ttk.Checkbutton(control_frame, text="Resolve hostnames (slower but detailed)", 
                                       variable=self.resolve_hostnames_var)
        hostname_check.grid(row=2, column=0, columnspan=2, sticky='w', padx=5, pady=2)
        
        # Progress bar
        self.scan_progress = ttk.Progressbar(control_frame, mode='indeterminate')
        self.scan_progress.grid(row=3, column=0, columnspan=4, sticky='ew', padx=5, pady=5)
        
        # Configure grid weights
        control_frame.grid_columnconfigure(1, weight=1)
        
        # Populate initial networks
        self.refresh_network_list()
        
        # Bind network selection change
        self.network_combo.bind('<<ComboboxSelected>>', self.on_network_selection_change)
        
        # Results
        results_frame = ttk.LabelFrame(discovery_frame, text="Discovered Devices")
        results_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Results treeview with enhanced columns
        self.discovery_tree = ttk.Treeview(results_frame, 
                                          columns=('IP', 'Response Time', 'Hostname', 'Device Type'), 
                                          show='headings', height=15)
        
        self.discovery_tree.heading('IP', text='IP Address')
        self.discovery_tree.heading('Response Time', text='Response Time')
        self.discovery_tree.heading('Hostname', text='Hostname')
        self.discovery_tree.heading('Device Type', text='Device Type')
        
        self.discovery_tree.column('IP', width=120)
        self.discovery_tree.column('Response Time', width=100)
        self.discovery_tree.column('Hostname', width=150)
        self.discovery_tree.column('Device Type', width=120)
        
        # Scrollbar for discovery results
        discovery_scrollbar = ttk.Scrollbar(results_frame, orient='vertical', 
                                           command=self.discovery_tree.yview)
        self.discovery_tree.configure(yscrollcommand=discovery_scrollbar.set)
        
        self.discovery_tree.pack(side='left', fill='both', expand=True)
        discovery_scrollbar.pack(side='right', fill='y')
        
        # Add selected devices button
        add_frame = ttk.Frame(discovery_frame)
        add_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(add_frame, text="➕ Add Selected Devices to Monitoring", 
                  command=self.add_discovered_devices).pack(side='right')
    
    def setup_history_tab(self):
        """Setup the history viewing tab"""
        history_frame = ttk.Frame(self.notebook)
        self.notebook.add(history_frame, text="📊 History")
        
        # Controls
        control_frame = ttk.Frame(history_frame)
        control_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(control_frame, text="🔄 Refresh Log", 
                  command=self.refresh_history).pack(side='left', padx=(0, 5))
        ttk.Button(control_frame, text="💾 Export Log", 
                  command=self.export_log).pack(side='left', padx=(0, 5))
        ttk.Button(control_frame, text="🗑️ Clear Log", 
                  command=self.clear_log).pack(side='left')
        
        # Log entries filter
        filter_frame = ttk.Frame(control_frame)
        filter_frame.pack(side='right')
        
        ttk.Label(filter_frame, text="Show last:").pack(side='left')
        self.history_limit = ttk.Combobox(filter_frame, values=['100', '500', '1000', 'All'], 
                                         state='readonly', width=10)
        self.history_limit.set('100')
        self.history_limit.pack(side='left', padx=(5, 0))
        self.history_limit.bind('<<ComboboxSelected>>', lambda e: self.refresh_history())
        
        # History treeview
        history_tree_frame = ttk.Frame(history_frame)
        history_tree_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.history_tree = ttk.Treeview(history_tree_frame, 
                                        columns=('Timestamp', 'IP', 'Name', 'Status', 'Latency'), 
                                        show='headings', height=20)
        
        # Configure columns
        self.history_tree.heading('Timestamp', text='Timestamp')
        self.history_tree.heading('IP', text='IP Address')
        self.history_tree.heading('Name', text='Device Name')
        self.history_tree.heading('Status', text='Status')
        self.history_tree.heading('Latency', text='Latency (ms)')
        
        self.history_tree.column('Timestamp', width=150)
        self.history_tree.column('IP', width=120)
        self.history_tree.column('Name', width=150)
        self.history_tree.column('Status', width=80)
        self.history_tree.column('Latency', width=100)
        
        # Scrollbars for history
        h_v_scrollbar = ttk.Scrollbar(history_tree_frame, orient='vertical', 
                                     command=self.history_tree.yview)
        h_h_scrollbar = ttk.Scrollbar(history_tree_frame, orient='horizontal', 
                                     command=self.history_tree.xview)
        self.history_tree.configure(yscrollcommand=h_v_scrollbar.set, 
                                   xscrollcommand=h_h_scrollbar.set)
        
        # Pack history tree and scrollbars
        self.history_tree.grid(row=0, column=0, sticky='nsew')
        h_v_scrollbar.grid(row=0, column=1, sticky='ns')
        h_h_scrollbar.grid(row=1, column=0, sticky='ew')
        
        history_tree_frame.grid_rowconfigure(0, weight=1)
        history_tree_frame.grid_columnconfigure(0, weight=1)
        
        # Load initial history
        self.refresh_history()
    
    def setup_statistics_tab(self):
        """Setup the statistics and analytics tab"""
        stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(stats_frame, text="📈 Statistics")
        
        # Controls
        control_frame = ttk.Frame(stats_frame)
        control_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(control_frame, text="🔄 Refresh Stats", 
                  command=self.refresh_statistics).pack(side='left', padx=(0, 5))
        ttk.Button(control_frame, text="📊 Generate Report", 
                  command=self.generate_report).pack(side='left', padx=(0, 5))
        
        # Toggle notifications
        self.notifications_var = tk.BooleanVar(value=self.notification_enabled)
        ttk.Checkbutton(control_frame, text="Enable Notifications", 
                       variable=self.notifications_var,
                       command=self.toggle_notifications).pack(side='right')
        
        # Create main content area with scrollable frame
        canvas = tk.Canvas(stats_frame)
        scrollbar = ttk.Scrollbar(stats_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Device uptime statistics
        uptime_frame = ttk.LabelFrame(scrollable_frame, text="Device Uptime Statistics")
        uptime_frame.pack(fill='x', padx=5, pady=5)
        
        self.uptime_tree = ttk.Treeview(uptime_frame, 
                                       columns=('Device', 'Current Status', 'Uptime %', 'Last Seen'), 
                                       show='headings', height=8)
        
        self.uptime_tree.heading('Device', text='Device Name')
        self.uptime_tree.heading('Current Status', text='Status')
        self.uptime_tree.heading('Uptime %', text='Uptime %')
        self.uptime_tree.heading('Last Seen', text='Last Seen')
        
        self.uptime_tree.column('Device', width=150)
        self.uptime_tree.column('Current Status', width=100)
        self.uptime_tree.column('Uptime %', width=100)
        self.uptime_tree.column('Last Seen', width=150)
        
        self.uptime_tree.pack(fill='x', padx=5, pady=5)
        
        # Network performance metrics
        performance_frame = ttk.LabelFrame(scrollable_frame, text="Network Performance Metrics")
        performance_frame.pack(fill='x', padx=5, pady=5)
        
        self.perf_tree = ttk.Treeview(performance_frame, 
                                     columns=('Device', 'Avg Latency', 'Min Latency', 'Max Latency', 'Packet Loss'), 
                                     show='headings', height=8)
        
        self.perf_tree.heading('Device', text='Device Name')
        self.perf_tree.heading('Avg Latency', text='Avg Latency')
        self.perf_tree.heading('Min Latency', text='Min Latency')
        self.perf_tree.heading('Max Latency', text='Max Latency')
        self.perf_tree.heading('Packet Loss', text='Packet Loss %')
        
        for col in ['Device', 'Avg Latency', 'Min Latency', 'Max Latency', 'Packet Loss']:
            self.perf_tree.column(col, width=120)
        
        self.perf_tree.pack(fill='x', padx=5, pady=5)
        
        # System summary
        summary_frame = ttk.LabelFrame(scrollable_frame, text="System Summary")
        summary_frame.pack(fill='x', padx=5, pady=5)
        
        self.summary_text = tk.Text(summary_frame, height=8, wrap=tk.WORD, 
                                   font=('Consolas', 9))
        summary_scroll = ttk.Scrollbar(summary_frame, orient='vertical', 
                                      command=self.summary_text.yview)
        self.summary_text.configure(yscrollcommand=summary_scroll.set)
        
        self.summary_text.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        summary_scroll.pack(side='right', fill='y', pady=5)
        
        # Pack canvas and scrollbar
        canvas.pack(side="left", fill="both", expand=True, padx=(5, 0), pady=5)
        scrollbar.pack(side="right", fill="y", pady=5)
        
        # Load initial statistics
        self.refresh_statistics()
    
    def setup_status_bar(self):
        """Setup status bar"""
        self.status_bar = ttk.Frame(self.root)
        self.status_bar.pack(side='bottom', fill='x')
        
        self.status_text = ttk.Label(self.status_bar, text="Ready")
        self.status_text.pack(side='left', padx=5)
        
        # Add device count on the right
        self.device_count_label = ttk.Label(self.status_bar, text="")
        self.device_count_label.pack(side='right', padx=5)
        
        self.update_device_count()
    
    def get_local_network(self):
        """Get the primary local network subnet (simplified for backward compatibility)"""
        networks = self.detect_all_networks()
        if networks:
            return networks[0]['network']  # Return primary network
        return '192.168.1.0/24'
    
    def detect_all_networks(self):
        """Detect all available network interfaces and their configurations"""
        networks = []
        
        try:
            # Method 1: Parse ipconfig output (Windows)
            if os.name == 'nt':
                networks.extend(self._parse_ipconfig())
            
            # Method 2: Use route table for additional networks
            networks.extend(self._parse_route_table())
            
            # Method 3: Common network ranges as fallback
            if not networks:
                networks.extend(self._get_common_networks())
            
            # Remove duplicates and sort by priority
            seen = set()
            unique_networks = []
            for net in networks:
                net_key = net['network']
                if net_key not in seen:
                    seen.add(net_key)
                    unique_networks.append(net)
            
            return sorted(unique_networks, key=lambda x: x['priority'])
            
        except Exception as e:
            print(f"Error detecting networks: {e}")
            return self._get_common_networks()
    
    def _parse_ipconfig(self):
        """Parse Windows ipconfig output for network interfaces"""
        networks = []
        
        try:
            result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True, shell=True)
            lines = result.stdout.split('\n')
            
            current_adapter = None
            current_ip = None
            current_subnet = None
            current_gateway = None
            
            for line in lines:
                line = line.strip()
                
                # Detect adapter
                if 'adapter' in line.lower() and ':' in line:
                    # Save previous adapter info
                    if current_adapter and current_ip and current_gateway:
                        network = self._calculate_network(current_ip, current_subnet or '255.255.255.0')
                        if network:
                            networks.append({
                                'network': network,
                                'interface': current_adapter,
                                'ip': current_ip,
                                'gateway': current_gateway,
                                'priority': self._get_interface_priority(current_adapter)
                            })
                    
                    current_adapter = line.replace(':', '').strip()
                    current_ip = None
                    current_subnet = None
                    current_gateway = None
                
                elif 'IPv4 Address' in line or 'IP Address' in line:
                    parts = line.split(':')
                    if len(parts) > 1:
                        ip = parts[-1].strip().replace('(Preferred)', '').strip()
                        if self._is_valid_ip(ip) and not ip.startswith('169.254'):
                            current_ip = ip
                
                elif 'Subnet Mask' in line:
                    parts = line.split(':')
                    if len(parts) > 1:
                        current_subnet = parts[-1].strip()
                
                elif 'Default Gateway' in line:
                    parts = line.split(':')
                    if len(parts) > 1:
                        gateway = parts[-1].strip()
                        if self._is_valid_ip(gateway):
                            current_gateway = gateway
            
            # Save last adapter
            if current_adapter and current_ip and current_gateway:
                network = self._calculate_network(current_ip, current_subnet or '255.255.255.0')
                if network:
                    networks.append({
                        'network': network,
                        'interface': current_adapter,
                        'ip': current_ip,
                        'gateway': current_gateway,
                        'priority': self._get_interface_priority(current_adapter)
                    })
        
        except Exception as e:
            print(f"Error parsing ipconfig: {e}")
        
        return networks
    
    def _parse_route_table(self):
        """Parse routing table for additional network information"""
        networks = []
        
        try:
            if os.name == 'nt':
                result = subprocess.run(['route', 'print'], capture_output=True, text=True, shell=True)
            else:
                result = subprocess.run(['route', '-n'], capture_output=True, text=True, shell=True)
            
            lines = result.stdout.split('\n')
            
            for line in lines:
                if os.name == 'nt':
                    # Windows route format
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] != '0.0.0.0':
                        if self._is_valid_ip(parts[0]) and self._is_valid_ip(parts[1]):
                            network = self._calculate_network(parts[0], parts[1])
                            if network and not network.startswith('127.') and not network.startswith('169.254'):
                                networks.append({
                                    'network': network,
                                    'interface': 'Route Table',
                                    'ip': parts[0],
                                    'gateway': parts[2] if len(parts) > 2 else '',
                                    'priority': 3
                                })
                else:
                    # Linux route format
                    parts = line.split()
                    if len(parts) >= 8 and parts[0] != '0.0.0.0':
                        if '/' in parts[0]:
                            networks.append({
                                'network': parts[0],
                                'interface': parts[-1] if len(parts) > 0 else 'Unknown',
                                'ip': '',
                                'gateway': parts[1] if len(parts) > 1 else '',
                                'priority': 3
                            })
        
        except Exception as e:
            print(f"Error parsing route table: {e}")
        
        return networks
    
    def _get_common_networks(self):
        """Return common network ranges as fallback"""
        return [
            {'network': '192.168.1.0/24', 'interface': 'Common Range', 'ip': '', 'gateway': '', 'priority': 4},
            {'network': '192.168.0.0/24', 'interface': 'Common Range', 'ip': '', 'gateway': '', 'priority': 4},
            {'network': '10.0.0.0/24', 'interface': 'Common Range', 'ip': '', 'gateway': '', 'priority': 4},
            {'network': '172.16.0.0/24', 'interface': 'Common Range', 'ip': '', 'gateway': '', 'priority': 4},
            {'network': '192.168.2.0/24', 'interface': 'Common Range', 'ip': '', 'gateway': '', 'priority': 5},
            {'network': '10.0.1.0/24', 'interface': 'Common Range', 'ip': '', 'gateway': '', 'priority': 5},
        ]
    
    def _calculate_network(self, ip, subnet_mask):
        """Calculate network address from IP and subnet mask"""
        try:
            if not self._is_valid_ip(ip):
                return None
            
            # Convert subnet mask to CIDR
            if '.' in subnet_mask:
                cidr = self._mask_to_cidr(subnet_mask)
            else:
                cidr = int(subnet_mask)
            
            # Calculate network
            network = ipaddress.IPv4Network(f"{ip}/{cidr}", strict=False)
            return str(network)
        
        except Exception:
            # Fallback: assume /24
            try:
                parts = ip.split('.')
                if len(parts) == 4:
                    return f"{'.'.join(parts[:3])}.0/24"
            except Exception:
                pass
        
        return None
    
    def _mask_to_cidr(self, mask):
        """Convert subnet mask to CIDR notation"""
        try:
            mask_int = struct.unpack("!I", socket.inet_aton(mask))[0]
            return bin(mask_int).count('1')
        except:
            # Common subnet mask mappings
            mask_map = {
                '255.255.255.0': 24,
                '255.255.0.0': 16,
                '255.0.0.0': 8,
                '255.255.255.128': 25,
                '255.255.255.192': 26,
                '255.255.255.224': 27,
                '255.255.255.240': 28,
                '255.255.255.248': 29,
                '255.255.255.252': 30
            }
            return mask_map.get(mask, 24)
    
    def _is_valid_ip(self, ip):
        """Check if IP address is valid"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def _get_interface_priority(self, interface_name):
        """Assign priority based on interface type"""
        interface_name = interface_name.lower()
        
        if 'ethernet' in interface_name or 'local area connection' in interface_name:
            return 1  # Highest priority
        elif 'wi-fi' in interface_name or 'wireless' in interface_name:
            return 2
        elif 'vpn' in interface_name or 'virtual' in interface_name:
            return 3
        else:
            return 4
    
    def change_theme(self, theme_name):
        """Change the application theme"""
        try:
            if theme_name in ['azure', 'azure-dark']:
                ttk.Style().theme_use(theme_name)
                self.settings['theme'] = theme_name
                self.save_settings()
                self.update_status("Theme changed to " + theme_name.replace('-', ' ').title())
            else:
                messagebox.showerror("Error", "Invalid theme name")
        except Exception as e:
            messagebox.showerror("Error", f"Could not change theme: {e}")
    
    def toggle_monitoring(self):
        """Start or stop monitoring"""
        if not self.devices:
            messagebox.showwarning("Warning", "No devices configured for monitoring!")
            return
        
        if self.monitoring:
            self.stop_monitoring()
        else:
            self.start_monitoring()
    
    def start_monitoring(self):
        """Start monitoring in a separate thread"""
        self.monitoring = True
        self.start_btn.config(text="⏹ Stop Monitoring")
        self.status_label.config(text="Running")
        
        self.monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        self.update_status("Monitoring started")
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring = False
        self.start_btn.config(text="▶ Start Monitoring")
        self.status_label.config(text="Stopped")
        self.update_status("Monitoring stopped")
    
    def monitor_loop(self):
        """Main monitoring loop (runs in separate thread)"""
        while self.monitoring:
            try:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                results = []
                
                for device in self.devices:
                    ip = device['ip']
                    name = device['name']
                    
                    # Ping device
                    latency = self.ping_device(ip)
                    
                    if latency is not None:
                        status = "ONLINE"
                        latency_str = f"{latency:.0f}ms"
                        latency_num = latency
                    else:
                        status = "OFFLINE"
                        latency_str = "-"
                        latency_num = None
                    
                    # Check for status changes for notifications
                    previous_status = self.device_history.get(ip, {}).get('status')
                    if previous_status and previous_status != status:
                        self._show_notification(name, status, previous_status)
                    
                    # Store current status
                    self.device_status[ip] = {
                        'name': name,
                        'status': status,
                        'latency': latency_str,
                        'last_check': timestamp
                    }
                    
                    # Update history
                    self.device_history[ip] = {
                        'name': name,
                        'status': status,
                        'timestamp': timestamp
                    }
                    
                    results.append((ip, name, status, latency_num))
                
                # Update GUI in main thread
                self.root.after(0, self.update_monitoring_display)
                
                # Log to CSV
                self.log_to_csv(timestamp, results)
                
                # Wait for next cycle
                time.sleep(self.settings['monitor_interval'])
                
            except Exception as e:
                print(f"Error in monitor loop: {e}")
                time.sleep(1)
    
    def ping_device(self, ip: str) -> Optional[float]:
        """Ping a device and return latency in ms"""
        for attempt in range(self.settings['max_retries'] + 1):
            try:
                response_time = ping(ip, timeout=self.settings['ping_timeout'])
                if response_time is not None:
                    return response_time * 1000  # Convert to milliseconds
            except Exception:
                continue
        return None
    
    def update_monitoring_display(self):
        """Update the monitoring display (called from main thread)"""
        # Clear tree
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Add current status
        online_count = 0
        for ip, status_info in self.device_status.items():
            status = status_info['status']
            if status == "ONLINE":
                online_count += 1
            
            # Insert with color coding
            item = self.tree.insert('', 'end', values=(
                ip,
                status_info['name'],
                status,
                status_info['latency'],
                status_info['last_check']
            ))
            
            # Color coding
            if status == "ONLINE":
                self.tree.set(item, 'Status', '🟢 ONLINE')
            else:
                self.tree.set(item, 'Status', '🔴 OFFLINE')
        
        # Update summary
        total_count = len(self.devices)
        self.summary_label.config(text=f"Devices Online: {online_count}/{total_count}")
    
    def manual_refresh(self):
        """Manually refresh device status"""
        if not self.devices:
            messagebox.showinfo("Info", "No devices configured!")
            return
        
        def refresh_thread():
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            for device in self.devices:
                ip = device['ip']
                name = device['name']
                
                latency = self.ping_device(ip)
                
                if latency is not None:
                    status = "ONLINE"
                    latency_str = f"{latency:.0f}ms"
                else:
                    status = "OFFLINE"
                    latency_str = "-"
                
                self.device_status[ip] = {
                    'name': name,
                    'status': status,
                    'latency': latency_str,
                    'last_check': timestamp
                }
            
            # Update display
            self.root.after(0, self.update_monitoring_display)
            self.root.after(0, lambda: self.update_status("Manual refresh completed"))
        
        threading.Thread(target=refresh_thread, daemon=True).start()
        self.update_status("Refreshing device status...")
    
    def log_to_csv(self, timestamp: str, results: List[Tuple[str, str, str, Optional[float]]]):
        """Log results to CSV file"""
        try:
            file_exists = os.path.exists(self.settings['log_file'])
            
            with open(self.settings['log_file'], 'a', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                
                if not file_exists:
                    writer.writerow(['Timestamp', 'IP', 'Name', 'Status', 'Latency_ms'])
                
                for ip, name, status, latency in results:
                    writer.writerow([timestamp, ip, name, status, latency if latency is not None else ''])
        
        except Exception as e:
            print(f"Error writing to log file: {e}")
    
    def refresh_device_list(self):
        """Refresh the device list display"""
        self.device_listbox.delete(0, tk.END)
        for i, device in enumerate(self.devices):
            display_text = f"{device['ip']:15} - {device['name']}"
            self.device_listbox.insert(tk.END, display_text)
        
        self.update_device_count()
    
    def on_device_select(self, event):
        """Handle device selection"""
        selection = self.device_listbox.curselection()
        if selection:
            index = selection[0]
            device = self.devices[index]
            
            # Clear and populate entries
            self.ip_entry.delete(0, tk.END)
            self.name_entry.delete(0, tk.END)
            
            self.ip_entry.insert(0, device['ip'])
            self.name_entry.insert(0, device['name'])
    
    def add_device(self):
        """Add a new device"""
        ip = self.ip_entry.get().strip()
        name = self.name_entry.get().strip()
        
        if not ip or not name:
            messagebox.showerror("Error", "Please enter both IP address and device name!")
            return
        
        # Validate IP
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            messagebox.showerror("Error", "Invalid IP address format!")
            return
        
        # Check for duplicates
        for device in self.devices:
            if device['ip'] == ip:
                messagebox.showerror("Error", "Device with this IP already exists!")
                return
        
        # Add device
        self.devices.append({'ip': ip, 'name': name})
        self.refresh_device_list()
        self.save_devices()
        
        # Clear entries
        self.ip_entry.delete(0, tk.END)
        self.name_entry.delete(0, tk.END)
        
        self.update_status(f"Added device: {name} ({ip})")
    
    def update_device(self):
        """Update selected device"""
        selection = self.device_listbox.curselection()
        if not selection:
            messagebox.showerror("Error", "Please select a device to update!")
            return
        
        index = selection[0]
        ip = self.ip_entry.get().strip()
        name = self.name_entry.get().strip()
        
        if not ip or not name:
            messagebox.showerror("Error", "Please enter both IP address and device name!")
            return
        
        # Validate IP
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            messagebox.showerror("Error", "Invalid IP address format!")
            return
        
        # Update device
        self.devices[index] = {'ip': ip, 'name': name}
        self.refresh_device_list()
        self.save_devices()
        
        self.update_status(f"Updated device: {name} ({ip})")
    
    def remove_device(self):
        """Remove selected device"""
        selection = self.device_listbox.curselection()
        if not selection:
            messagebox.showerror("Error", "Please select a device to remove!")
            return
        
        index = selection[0]
        device = self.devices[index]
        
        if messagebox.askyesno("Confirm", f"Remove device '{device['name']}' ({device['ip']})?"):
            self.devices.pop(index)
            self.refresh_device_list()
            self.save_devices()
            
            # Clear entries
            self.ip_entry.delete(0, tk.END)
            self.name_entry.delete(0, tk.END)
            
            self.update_status(f"Removed device: {device['name']} ({device['ip']})")
    
    def test_device(self):
        """Test connectivity to selected device"""
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showerror("Error", "Please enter an IP address!")
            return
        
        def test_thread():
            try:
                latency = self.ping_device(ip)
                if latency is not None:
                    message = f"Device {ip} is ONLINE\\nResponse time: {latency:.1f}ms"
                    self.root.after(0, lambda: messagebox.showinfo("Ping Test", message))
                else:
                    message = f"Device {ip} is OFFLINE or not responding"
                    self.root.after(0, lambda: messagebox.showwarning("Ping Test", message))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Ping test failed: {e}"))
        
        threading.Thread(target=test_thread, daemon=True).start()
    
    def refresh_network_list(self):
        """Refresh the network list in the combobox"""
        try:
            networks = self.detect_all_networks()
            self.available_networks = networks  # Store for later reference
            
            # Update combobox values
            network_options = []
            for net in networks:
                if net['interface'] != 'Common Range':
                    network_options.append(f"{net['network']} ({net['interface']})")
                else:
                    network_options.append(net['network'])
            
            self.network_combo['values'] = network_options
            
            # Select first network by default
            if network_options:
                self.network_combo.set(network_options[0])
                self.on_network_selection_change(None)
            
            self.update_status(f"Detected {len(networks)} network interfaces")
            
        except Exception as e:
            self.update_status(f"Error detecting networks: {e}")
            messagebox.showerror("Error", f"Could not detect networks: {e}")
    
    def on_network_selection_change(self, event):
        """Handle network selection change"""
        try:
            selected = self.network_combo.get()
            if not selected:
                return
            
            # Find the selected network info
            selected_network = None
            for net in self.available_networks:
                if selected.startswith(net['network']):
                    selected_network = net
                    break
            
            if selected_network:
                info_text = f"Interface: {selected_network['interface']}"
                if selected_network.get('ip'):
                    info_text += f", Local IP: {selected_network['ip']}"
                if selected_network.get('gateway'):
                    info_text += f", Gateway: {selected_network['gateway']}"
                
                self.interface_label.config(text=info_text, foreground="black")
            else:
                self.interface_label.config(text="No interface information", foreground="gray")
                
        except Exception as e:
            print(f"Error updating interface info: {e}")
    
    def start_network_scan(self):
        """Start network discovery scan"""
        selected = self.network_combo.get()
        if not selected:
            messagebox.showerror("Error", "Please select a network range!")
            return
        
        # Extract network from selection
        network = selected.split(' (')[0]  # Remove interface name part
        
        try:
            ipaddress.IPv4Network(network)
        except ValueError:
            messagebox.showerror("Error", "Invalid network format! Use CIDR notation (e.g., 192.168.1.0/24)")
            return
        
        # Clear previous results
        for item in self.discovery_tree.get_children():
            self.discovery_tree.delete(item)
        
        # Reset discovery items dictionary
        self._discovery_items = {}
        
        # Start progress bar
        self.scan_progress.start()
        
        def scan_thread():
            try:
                network_obj = ipaddress.IPv4Network(network)
                alive_hosts = []
                
                # Use ThreadPoolExecutor for concurrent pings
                with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                    future_to_ip = {executor.submit(self.ping_host_discovery, ip): ip 
                                  for ip in network_obj.hosts()}
                    
                    for future in concurrent.futures.as_completed(future_to_ip):
                        result = future.result()
                        if result:
                            ip, response_time = result
                            alive_hosts.append((str(ip), response_time))
                            
                            # Add device with basic info immediately (no blocking operations)
                            self.root.after(0, lambda i=str(ip), rt=response_time: 
                                          self._add_discovered_device_basic(i, rt))
                
                # Resolve hostnames only if enabled
                if alive_hosts and self.resolve_hostnames_var.get():
                    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as hostname_executor:
                        hostname_futures = {hostname_executor.submit(self._get_device_info_background, ip): ip 
                                          for ip, _ in alive_hosts}
                        
                        for future in concurrent.futures.as_completed(hostname_futures):
                            try:
                                result = future.result()
                                if result:
                                    ip, hostname, device_type = result
                                    # Update GUI with enhanced info (non-blocking) - check if GUI still exists
                                    try:
                                        self.root.after(0, lambda i=ip, h=hostname, dt=device_type: 
                                                      self._update_discovered_device_info(i, h, dt))
                                    except tk.TclError:
                                        # GUI has been closed, stop processing
                                        break
                            except Exception as e:
                                print(f"Error getting device info for {hostname_futures[future]}: {e}")
                elif alive_hosts and not self.resolve_hostnames_var.get():
                    # If hostname resolution is disabled, update devices with basic device type only
                    for ip, _ in alive_hosts:
                        try:
                            device_type = self._detect_device_type_fast(ip)
                            self.root.after(0, lambda i=ip, dt=device_type: 
                                          self._update_discovered_device_info(i, "Skip", dt))
                        except tk.TclError:
                            break
                
                # Stop progress bar
                self.root.after(0, self.scan_progress.stop)
                self.root.after(0, lambda: self.update_status(f"Network scan completed. Found {len(alive_hosts)} devices."))
                
            except Exception as e:
                self.root.after(0, self.scan_progress.stop)
                self.root.after(0, lambda: messagebox.showerror("Error", f"Network scan failed: {e}"))
        
        threading.Thread(target=scan_thread, daemon=True).start()
        self.update_status(f"Scanning network {network}...")
    
    def ping_host_discovery(self, ip) -> Optional[Tuple[str, float]]:
        """Ping a host for discovery (faster timeout)"""
        try:
            response_time = ping(str(ip), timeout=1)
            if response_time is not None:
                return str(ip), response_time * 1000
        except Exception:
            pass
        return None
    
    def _add_discovered_device_basic(self, ip, response_time):
        """Add discovered device with basic information (non-blocking)"""
        try:
            # Insert into tree with basic info - hostname will be updated later
            item_id = self.discovery_tree.insert('', 'end', values=(
                ip, 
                f"{response_time:.1f}ms", 
                "Resolving...",
                "Detecting..."
            ))
            # Store the item ID for later updates
            if not hasattr(self, '_discovery_items'):
                self._discovery_items = {}
            self._discovery_items[ip] = item_id
        except Exception as e:
            print(f"Error adding basic device info for {ip}: {e}")
    
    def _get_device_info_background(self, ip):
        """Get hostname and device type in background thread (blocking operations allowed here)"""
        try:
            # Get hostname (this is the slow part - now safely in background thread)
            hostname = self._resolve_hostname(ip)
            
            # Detect device type
            device_type = self._detect_device_type(ip, hostname)
            
            return ip, hostname, device_type
        except Exception as e:
            print(f"Error getting device info for {ip}: {e}")
            return ip, None, "Unknown"
    
    def _update_discovered_device_info(self, ip, hostname, device_type):
        """Update discovered device with hostname and device type (GUI thread)"""
        try:
            if hasattr(self, '_discovery_items') and ip in self._discovery_items:
                item_id = self._discovery_items[ip]
                # Update the existing item with hostname and device type
                current_values = list(self.discovery_tree.item(item_id, 'values'))
                if len(current_values) >= 4:
                    current_values[2] = hostname or "Unknown"
                    current_values[3] = device_type or "Unknown"
                    self.discovery_tree.item(item_id, values=current_values)
        except Exception as e:
            print(f"Error updating device info for {ip}: {e}")
    
    def _resolve_hostname(self, ip):
        """Try to resolve hostname for an IP address with optimized timeouts"""
        try:
            # Try reverse DNS lookup with socket timeout
            import socket
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(1.0)  # 1 second timeout
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                return hostname
            finally:
                socket.setdefaulttimeout(old_timeout)
        except:
            try:
                # Try NetBIOS name resolution with reduced timeout (Windows)
                import subprocess
                result = subprocess.run(
                    ['nbtstat', '-A', ip], 
                    capture_output=True, 
                    text=True, 
                    timeout=1.5,  # Reduced from 3 to 1.5 seconds
                    shell=True,
                    creationflags=subprocess.CREATE_NO_WINDOW  # Don't show cmd window
                )
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if '<00>' in line and 'UNIQUE' in line:
                            parts = line.split()
                            if parts:
                                return parts[0].strip()
            except:
                pass
        return None
    
    def _detect_device_type(self, ip, hostname):
        """Detect device type based on IP, hostname, and basic port scanning"""
        try:
            # Check common patterns in hostname
            if hostname:
                hostname_lower = hostname.lower()
                if any(pattern in hostname_lower for pattern in ['router', 'gateway', 'gw']):
                    return "Router/Gateway"
                elif any(pattern in hostname_lower for pattern in ['printer', 'hp', 'canon', 'epson']):
                    return "Printer"
                elif any(pattern in hostname_lower for pattern in ['camera', 'cam', 'nvr']):
                    return "Camera/NVR"
                elif any(pattern in hostname_lower for pattern in ['nas', 'storage', 'synology', 'qnap']):
                    return "NAS/Storage"
                elif any(pattern in hostname_lower for pattern in ['ap', 'wifi', 'wireless']):
                    return "Access Point"
            
            # Check based on IP range patterns
            last_octet = int(ip.split('.')[-1])
            if last_octet == 1:
                return "Router/Gateway"
            elif 2 <= last_octet <= 10:
                return "Network Device"
            elif 11 <= last_octet <= 50:
                return "Computer"
            elif 51 <= last_octet <= 100:
                return "Mobile Device"
            elif 101 <= last_octet <= 150:
                return "IoT Device"
            elif 200 <= last_octet <= 254:
                return "Server/Printer"
            else:
                return "Unknown Device"
                
        except Exception:
            return "Unknown Device"
    
    def _detect_device_type_fast(self, ip):
        """Fast device type detection based only on IP patterns"""
        try:
            last_octet = int(ip.split('.')[-1])
            if last_octet == 1:
                return "Router/Gateway"
            elif 2 <= last_octet <= 10:
                return "Network Device"
            elif 11 <= last_octet <= 50:
                return "Computer"
            elif 51 <= last_octet <= 100:
                return "Mobile Device"
            elif 101 <= last_octet <= 150:
                return "IoT Device"
            elif 200 <= last_octet <= 254:
                return "Server/Printer"
            else:
                return "Unknown Device"
        except Exception:
            return "Unknown Device"
    
    def _show_notification(self, device_name, current_status, previous_status):
        """Show notification for device status changes"""
        if not self.notification_enabled:
            return
        
        try:
            if current_status == "ONLINE" and previous_status == "OFFLINE":
                title = "Device Online"
                message = f"{device_name} is now online"
                self._show_toast_notification(title, message, "success")
            elif current_status == "OFFLINE" and previous_status == "ONLINE":
                title = "Device Offline"
                message = f"{device_name} went offline"
                self._show_toast_notification(title, message, "warning")
        except Exception as e:
            print(f"Error showing notification: {e}")
    
    def _show_toast_notification(self, title, message, notification_type="info"):
        """Show toast notification (Windows-style)"""
        try:
            # Create a simple toast notification window
            toast = tk.Toplevel(self.root)
            toast.title(title)
            toast.geometry("300x100")
            
            # Position in bottom right corner
            x = self.root.winfo_screenwidth() - 320
            y = self.root.winfo_screenheight() - 150
            toast.geometry(f"300x100+{x}+{y}")
            
            # Configure toast window
            toast.attributes("-topmost", True)
            toast.overrideredirect(True)
            
            # Color scheme based on type
            colors = {
                "success": {"bg": "#d4edda", "fg": "#155724", "border": "#c3e6cb"},
                "warning": {"bg": "#fff3cd", "fg": "#856404", "border": "#ffeaa7"},
                "error": {"bg": "#f8d7da", "fg": "#721c24", "border": "#f5c6cb"},
                "info": {"bg": "#d1ecf1", "fg": "#0c5460", "border": "#bee5eb"}
            }
            
            color = colors.get(notification_type, colors["info"])
            
            # Create frame with border
            frame = tk.Frame(toast, bg=color["border"], padx=2, pady=2)
            frame.pack(fill="both", expand=True)
            
            inner_frame = tk.Frame(frame, bg=color["bg"])
            inner_frame.pack(fill="both", expand=True, padx=1, pady=1)
            
            # Title label
            title_label = tk.Label(inner_frame, text=title, font=("Segoe UI", 10, "bold"), 
                                 bg=color["bg"], fg=color["fg"])
            title_label.pack(pady=(5, 0))
            
            # Message label
            msg_label = tk.Label(inner_frame, text=message, font=("Segoe UI", 9), 
                               bg=color["bg"], fg=color["fg"])
            msg_label.pack(pady=(2, 5))
            
            # Auto-close after 3 seconds
            toast.after(3000, toast.destroy)
            
            # Click to close
            def close_toast(event=None):
                toast.destroy()
            
            toast.bind("<Button-1>", close_toast)
            frame.bind("<Button-1>", close_toast)
            inner_frame.bind("<Button-1>", close_toast)
            title_label.bind("<Button-1>", close_toast)
            msg_label.bind("<Button-1>", close_toast)
            
        except Exception as e:
            print(f"Error creating toast notification: {e}")
    
    def toggle_notifications(self):
        """Toggle notification system on/off"""
        self.notification_enabled = self.notifications_var.get()
        status = "enabled" if self.notification_enabled else "disabled"
        self.update_status(f"Notifications {status}")
    
    def refresh_statistics(self):
        """Refresh all statistics displays"""
        self._update_uptime_statistics()
        self._update_performance_metrics()
        self._update_system_summary()
    
    def _update_uptime_statistics(self):
        """Update device uptime statistics"""
        try:
            # Clear existing items
            for item in self.uptime_tree.get_children():
                self.uptime_tree.delete(item)
            
            if not os.path.exists(self.settings['log_file']):
                return
            
            # Calculate uptime from log data
            device_stats = {}
            
            with open(self.settings['log_file'], 'r', encoding='utf-8') as csvfile:
                reader = csv.reader(csvfile)
                headers = next(reader)  # Skip headers
                
                for row in reader:
                    if len(row) >= 4:
                        timestamp, ip, name, status = row[:4]
                        
                        if name not in device_stats:
                            device_stats[name] = {
                                'ip': ip,
                                'total_checks': 0,
                                'online_checks': 0,
                                'last_seen': timestamp,
                                'current_status': status
                            }
                        
                        device_stats[name]['total_checks'] += 1
                        if status == 'ONLINE':
                            device_stats[name]['online_checks'] += 1
                            device_stats[name]['last_seen'] = timestamp
                        device_stats[name]['current_status'] = status
            
            # Populate tree
            for name, stats in device_stats.items():
                uptime_percent = (stats['online_checks'] / max(stats['total_checks'], 1)) * 100
                status_display = "🟢 Online" if stats['current_status'] == 'ONLINE' else "🔴 Offline"
                
                self.uptime_tree.insert('', 'end', values=(
                    name,
                    status_display,
                    f"{uptime_percent:.1f}%",
                    stats['last_seen']
                ))
        
        except Exception as e:
            print(f"Error updating uptime statistics: {e}")
    
    def _update_performance_metrics(self):
        """Update network performance metrics"""
        try:
            # Clear existing items
            for item in self.perf_tree.get_children():
                self.perf_tree.delete(item)
            
            if not os.path.exists(self.settings['log_file']):
                return
            
            # Calculate performance metrics
            device_metrics = {}
            
            with open(self.settings['log_file'], 'r', encoding='utf-8') as csvfile:
                reader = csv.reader(csvfile)
                headers = next(reader)  # Skip headers
                
                for row in reader:
                    if len(row) >= 5:
                        timestamp, ip, name, status, latency = row[:5]
                        
                        if name not in device_metrics:
                            device_metrics[name] = {
                                'latencies': [],
                                'total_pings': 0,
                                'failed_pings': 0
                            }
                        
                        device_metrics[name]['total_pings'] += 1
                        
                        if status == 'ONLINE' and latency:
                            try:
                                lat_value = float(latency)
                                device_metrics[name]['latencies'].append(lat_value)
                            except ValueError:
                                pass
                        else:
                            device_metrics[name]['failed_pings'] += 1
            
            # Populate performance tree
            for name, metrics in device_metrics.items():
                if metrics['latencies']:
                    avg_lat = sum(metrics['latencies']) / len(metrics['latencies'])
                    min_lat = min(metrics['latencies'])
                    max_lat = max(metrics['latencies'])
                    avg_display = f"{avg_lat:.1f}ms"
                    min_display = f"{min_lat:.1f}ms"
                    max_display = f"{max_lat:.1f}ms"
                else:
                    avg_display = min_display = max_display = "N/A"
                
                packet_loss = (metrics['failed_pings'] / max(metrics['total_pings'], 1)) * 100
                
                self.perf_tree.insert('', 'end', values=(
                    name,
                    avg_display,
                    min_display,
                    max_display,
                    f"{packet_loss:.1f}%"
                ))
        
        except Exception as e:
            print(f"Error updating performance metrics: {e}")
    
    def _update_system_summary(self):
        """Update system summary text"""
        try:
            self.summary_text.delete(1.0, tk.END)
            
            summary_lines = []
            summary_lines.append(f"Network Monitor Statistics Report")
            summary_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            summary_lines.append(f"="*50)
            
            # Device count
            total_devices = len(self.devices)
            online_devices = sum(1 for status in self.device_status.values() if status['status'] == 'ONLINE')
            summary_lines.append(f"Total Devices Configured: {total_devices}")
            summary_lines.append(f"Currently Online: {online_devices}")
            summary_lines.append(f"Currently Offline: {total_devices - online_devices}")
            summary_lines.append("")
            
            # Network interfaces
            networks = self.detect_all_networks()
            active_networks = [n for n in networks if n['priority'] <= 2]
            summary_lines.append(f"Active Network Interfaces: {len(active_networks)}")
            for net in active_networks[:3]:  # Show top 3
                summary_lines.append(f"  - {net['interface']}: {net['network']}")
            summary_lines.append("")
            
            # Monitoring status
            monitoring_status = "Running" if self.monitoring else "Stopped"
            summary_lines.append(f"Monitoring Status: {monitoring_status}")
            if self.monitoring:
                summary_lines.append(f"Check Interval: {self.settings['monitor_interval']} seconds")
                summary_lines.append(f"Ping Timeout: {self.settings['ping_timeout']} seconds")
            summary_lines.append("")
            
            # Log file info
            if os.path.exists(self.settings['log_file']):
                file_size = os.path.getsize(self.settings['log_file'])
                size_mb = file_size / (1024 * 1024)
                summary_lines.append(f"Log File: {self.settings['log_file']}")
                summary_lines.append(f"Log File Size: {size_mb:.2f} MB")
                
                # Count log entries
                with open(self.settings['log_file'], 'r', encoding='utf-8') as f:
                    line_count = sum(1 for line in f) - 1  # Exclude header
                summary_lines.append(f"Total Log Entries: {line_count:,}")
            else:
                summary_lines.append("Log File: Not created yet")
            
            # Add notification status
            summary_lines.append("")
            notif_status = "Enabled" if self.notification_enabled else "Disabled"
            summary_lines.append(f"Notifications: {notif_status}")
            
            # Insert all text
            self.summary_text.insert(1.0, "\n".join(summary_lines))
            
        except Exception as e:
            self.summary_text.delete(1.0, tk.END)
            self.summary_text.insert(1.0, f"Error generating summary: {e}")
    
    def generate_report(self):
        """Generate and export a detailed report"""
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                title="Save Network Monitor Report"
            )
            
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    # Write comprehensive report
                    f.write("NETWORK MONITOR DETAILED REPORT\n")
                    f.write("="*50 + "\n\n")
                    f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                    
                    # Device configurations
                    f.write("CONFIGURED DEVICES:\n")
                    f.write("-" * 20 + "\n")
                    for device in self.devices:
                        f.write(f"  {device['name']}: {device['ip']}\n")
                    f.write("\n")
                    
                    # Current status
                    f.write("CURRENT STATUS:\n")
                    f.write("-" * 15 + "\n")
                    for ip, status in self.device_status.items():
                        f.write(f"  {status['name']} ({ip}): {status['status']} - {status['latency']}\n")
                    f.write("\n")
                    
                    # Network interfaces
                    f.write("NETWORK INTERFACES:\n")
                    f.write("-" * 19 + "\n")
                    networks = self.detect_all_networks()
                    for net in networks[:5]:  # Top 5 interfaces
                        f.write(f"  {net['interface']}: {net['network']}")
                        if net.get('ip'):
                            f.write(f" (Local IP: {net['ip']})")
                        f.write("\n")
                    f.write("\n")
                    
                    # Performance summary (if log exists)
                    if os.path.exists(self.settings['log_file']):
                        f.write("PERFORMANCE SUMMARY:\n")
                        f.write("-" * 20 + "\n")
                        # Add basic log analysis here
                        with open(self.settings['log_file'], 'r', encoding='utf-8') as logfile:
                            lines = logfile.readlines()
                            f.write(f"Total log entries: {len(lines) - 1}\n")  # Exclude header
                        f.write("\n")
                
                messagebox.showinfo("Success", f"Report saved to: {filename}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Could not generate report: {e}")
    
    def add_discovered_devices(self):
        """Add selected discovered devices to monitoring list with enhanced naming"""
        selection = self.discovery_tree.selection()
        if not selection:
            messagebox.showinfo("Info", "Please select devices to add!")
            return
        
        added_count = 0
        for item in selection:
            values = self.discovery_tree.item(item, 'values')
            if len(values) >= 4:
                ip, response_time, hostname, device_type = values[:4]
                
                # Check if device already exists
                exists = any(device['ip'] == ip for device in self.devices)
                if not exists:
                    # Generate intelligent name based on available info
                    if hostname and hostname != "Unknown":
                        name = hostname
                    elif device_type and device_type != "Unknown Device":
                        name = f"{device_type} ({ip.split('.')[-1]})"
                    else:
                        name = f"Device {ip.split('.')[-1]}"
                    
                    self.devices.append({'ip': ip, 'name': name})
                    added_count += 1
        
        if added_count > 0:
            self.refresh_device_list()
            self.save_devices()
            self.update_status(f"Added {added_count} devices to monitoring list")
        else:
            messagebox.showinfo("Info", "No new devices were added (already exist)")
    
    def refresh_history(self):
        """Refresh the history display"""
        # Clear tree
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        
        if not os.path.exists(self.settings['log_file']):
            return
        
        try:
            limit = self.history_limit.get()
            
            with open(self.settings['log_file'], 'r', encoding='utf-8') as csvfile:
                reader = csv.reader(csvfile)
                headers = next(reader)  # Skip headers
                
                rows = list(reader)
                
                # Apply limit
                if limit != 'All':
                    rows = rows[-int(limit):]
                
                # Insert rows (newest first)
                for row in reversed(rows):
                    if len(row) >= 5:
                        timestamp, ip, name, status, latency = row[:5]
                        latency_display = f"{latency}" if latency else "-"
                        
                        self.history_tree.insert('', 'end', values=(
                            timestamp, ip, name, status, latency_display
                        ))
        
        except Exception as e:
            messagebox.showerror("Error", f"Could not load history: {e}")
    
    def export_log(self):
        """Export log to a file"""
        if not os.path.exists(self.settings['log_file']):
            messagebox.showinfo("Info", "No log file exists yet!")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Export Log File"
        )
        
        if filename:
            try:
                import shutil
                shutil.copy2(self.settings['log_file'], filename)
                messagebox.showinfo("Success", f"Log exported to: {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not export log: {e}")
    
    def clear_log(self):
        """Clear the log file"""
        if messagebox.askyesno("Confirm", "This will permanently delete all log history. Continue?"):
            try:
                if os.path.exists(self.settings['log_file']):
                    os.remove(self.settings['log_file'])
                self.refresh_history()
                messagebox.showinfo("Success", "Log history cleared!")
            except Exception as e:
                messagebox.showerror("Error", f"Could not clear log: {e}")
    
    def open_discovery_window(self):
        """Open network discovery in a popup window"""
        self.notebook.select(2)  # Switch to discovery tab
    
    def open_ping_test(self):
        """Open ping test dialog"""
        ip = simpledialog.askstring("Ping Test", "Enter IP address to ping:")
        if ip:
            def test_thread():
                try:
                    latency = self.ping_device(ip)
                    if latency is not None:
                        message = f"Device {ip} is ONLINE\\nResponse time: {latency:.1f}ms"
                        self.root.after(0, lambda: messagebox.showinfo("Ping Test", message))
                    else:
                        message = f"Device {ip} is OFFLINE or not responding"
                        self.root.after(0, lambda: messagebox.showwarning("Ping Test", message))
                except Exception as e:
                    self.root.after(0, lambda: messagebox.showerror("Error", f"Ping test failed: {e}"))
            
            threading.Thread(target=test_thread, daemon=True).start()
    
    def open_settings_window(self):
        """Open settings configuration window"""
        settings_window = tk.Toplevel(self.root)
        settings_window.title("Settings")
        settings_window.geometry("400x300")
        settings_window.transient(self.root)
        settings_window.grab_set()
        
        # Settings form
        form_frame = ttk.LabelFrame(settings_window, text="Monitoring Settings")
        form_frame.pack(fill='x', padx=10, pady=10)
        
        # Monitor interval
        ttk.Label(form_frame, text="Monitor Interval (seconds):").grid(row=0, column=0, sticky='w', padx=5, pady=2)
        interval_var = tk.StringVar(value=str(self.settings['monitor_interval']))
        ttk.Entry(form_frame, textvariable=interval_var, width=10).grid(row=0, column=1, padx=5, pady=2)
        
        # Ping timeout
        ttk.Label(form_frame, text="Ping Timeout (seconds):").grid(row=1, column=0, sticky='w', padx=5, pady=2)
        timeout_var = tk.StringVar(value=str(self.settings['ping_timeout']))
        ttk.Entry(form_frame, textvariable=timeout_var, width=10).grid(row=1, column=1, padx=5, pady=2)
        
        # Max retries
        ttk.Label(form_frame, text="Max Retries:").grid(row=2, column=0, sticky='w', padx=5, pady=2)
        retries_var = tk.StringVar(value=str(self.settings['max_retries']))
        ttk.Entry(form_frame, textvariable=retries_var, width=10).grid(row=2, column=1, padx=5, pady=2)
        
        # Log file
        ttk.Label(form_frame, text="Log File:").grid(row=3, column=0, sticky='w', padx=5, pady=2)
        log_var = tk.StringVar(value=self.settings['log_file'])
        ttk.Entry(form_frame, textvariable=log_var, width=20).grid(row=3, column=1, padx=5, pady=2)
        
        # Auto save
        auto_save_var = tk.BooleanVar(value=self.settings['auto_save'])
        ttk.Checkbutton(form_frame, text="Auto-save configuration", 
                       variable=auto_save_var).grid(row=4, column=0, columnspan=2, sticky='w', padx=5, pady=2)
        
        # Advanced settings
        advanced_frame = ttk.LabelFrame(settings_window, text="Advanced Settings")
        advanced_frame.pack(fill='x', padx=10, pady=5)
        
        # Notification settings
        notification_var = tk.BooleanVar(value=self.notification_enabled)
        ttk.Checkbutton(advanced_frame, text="Enable status change notifications", 
                       variable=notification_var).grid(row=0, column=0, columnspan=2, sticky='w', padx=5, pady=2)
        
        # Theme setting
        ttk.Label(advanced_frame, text="Theme:").grid(row=1, column=0, sticky='w', padx=5, pady=2)
        theme_var = tk.StringVar(value=self.settings.get('theme', 'azure'))
        theme_combo = ttk.Combobox(advanced_frame, textvariable=theme_var, 
                                  values=['azure', 'azure-dark'], state='readonly', width=15)
        theme_combo.grid(row=1, column=1, padx=5, pady=2)
        
        # Buttons
        button_frame = ttk.Frame(settings_window)
        button_frame.pack(fill='x', padx=10, pady=10)
        
        def save_settings():
            try:
                self.settings['monitor_interval'] = int(interval_var.get())
                self.settings['ping_timeout'] = int(timeout_var.get())
                self.settings['max_retries'] = int(retries_var.get())
                self.settings['log_file'] = log_var.get()
                self.settings['auto_save'] = auto_save_var.get()
                
                # Advanced settings
                self.notification_enabled = notification_var.get()
                if hasattr(self, 'notifications_var'):
                    self.notifications_var.set(self.notification_enabled)
                
                # Apply theme change
                new_theme = theme_var.get()
                if new_theme != self.settings.get('theme'):
                    self.change_theme(new_theme)
                
                self.save_settings()
                messagebox.showinfo("Success", "Settings saved!")
                settings_window.destroy()
            except ValueError:
                messagebox.showerror("Error", "Please enter valid numeric values!")
        
        ttk.Button(button_frame, text="Save", command=save_settings).pack(side='right', padx=(5, 0))
        ttk.Button(button_frame, text="Cancel", command=settings_window.destroy).pack(side='right')
    
    def save_config(self):
        """Save configuration to file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Save Configuration"
        )
        
        if filename:
            try:
                config = {
                    'devices': self.devices,
                    'settings': self.settings
                }
                with open(filename, 'w') as f:
                    json.dump(config, f, indent=2)
                messagebox.showinfo("Success", f"Configuration saved to: {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not save configuration: {e}")
    
    def load_config(self):
        """Load configuration from file"""
        filename = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Load Configuration"
        )
        
        if filename:
            try:
                with open(filename, 'r') as f:
                    config = json.load(f)
                
                self.devices = config.get('devices', [])
                self.settings.update(config.get('settings', {}))
                
                self.refresh_device_list()
                self.save_devices()
                self.save_settings()
                
                messagebox.showinfo("Success", f"Configuration loaded from: {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not load configuration: {e}")
    
    def show_about(self):
        """Show about dialog"""
        about_text = """
Network Monitor GUI v2.0.0

An integrated network monitoring application with:
• Real-time device monitoring
• Network discovery
• Device management
• History viewing
• Modern Azure UI theme

Built with Python and Tkinter
        """
        messagebox.showinfo("About Network Monitor", about_text.strip())
    
    def refresh_display(self):
        """Refresh all displays"""
        self.refresh_device_list()
        self.refresh_history()
        self.update_status("Display refreshed")
    
    def update_status(self, message):
        """Update status bar"""
        self.status_text.config(text=message)
        # Auto-clear status after 5 seconds
        self.root.after(5000, lambda: self.status_text.config(text="Ready"))
    
    def update_device_count(self):
        """Update device count in status bar"""
        count = len(self.devices)
        self.device_count_label.config(text=f"Devices: {count}")
    
    def load_settings(self):
        """Load settings from file"""
        settings_file = "gui_settings.json"
        try:
            if os.path.exists(settings_file):
                with open(settings_file, 'r') as f:
                    saved_settings = json.load(f)
                self.settings.update(saved_settings)
        except Exception as e:
            print(f"Could not load settings: {e}")
    
    def save_settings(self):
        """Save settings to file"""
        if self.settings.get('auto_save', True):
            settings_file = "gui_settings.json"
            try:
                with open(settings_file, 'w') as f:
                    json.dump(self.settings, f, indent=2)
            except Exception as e:
                print(f"Could not save settings: {e}")
    
    def load_devices(self):
        """Load devices from file"""
        devices_file = "devices.json"
        try:
            if os.path.exists(devices_file):
                with open(devices_file, 'r') as f:
                    self.devices = json.load(f)
        except Exception as e:
            print(f"Could not load devices: {e}")
            # Fallback to default devices
            self.devices = [
                {"ip": "8.8.8.8", "name": "Google DNS"},
                {"ip": "1.1.1.1", "name": "Cloudflare DNS"},
                {"ip": "192.168.1.1", "name": "Router"}
            ]
    
    def save_devices(self):
        """Save devices to file"""
        if self.settings.get('auto_save', True):
            devices_file = "devices.json"
            try:
                with open(devices_file, 'w') as f:
                    json.dump(self.devices, f, indent=2)
            except Exception as e:
                print(f"Could not save devices: {e}")
    
    def on_closing(self):
        """Handle application closing"""
        if self.monitoring:
            if messagebox.askokcancel("Quit", "Monitoring is still running. Do you want to quit?"):
                self.stop_monitoring()
                self.root.after(100, self.root.destroy)
        else:
            self.root.destroy()

def main():
    """Main function"""
    root = tk.Tk()
    app = NetworkMonitorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()