# Network Monitor

A network monitoring application with a modern GUI with a device discovery, real-time monitoring, and analytics. Built with Python and Tkinter, featuring multi-interface network detection, intelligent hostname resolution, and a responsive user interface.

## 🌟 Features

### 🖥️ Modern Interface
- **Azure Theme**: Professional light/dark theme with modern styling
- **Multi-tab Layout**: Organized workflow across specialized tabs
- **Real-time Updates**: Live device status with color-coded indicators
- **Progress Tracking**: Visual progress bars for long-running operations
- **Toast Notifications**: Windows-style notifications for status changes

### 🔍 Advanced Network Discovery
- **Multi-Interface Detection**: Automatically discovers all network interfaces
- **Intelligent Scanning**: Fast concurrent ping scanning with optimized timeouts  
- **Hostname Resolution**: Multi-threaded DNS and NetBIOS name resolution
- **Device Classification**: Smart device type detection based on hostnames and IP patterns
- **Flexible Targeting**: Support for CIDR notation and custom network ranges
- **Performance Optimized**: Non-blocking UI with background thread pools

### 📊 Comprehensive Monitoring
- **Real-time Status**: Live ping monitoring with latency measurements
- **Historical Analytics**: Device uptime statistics and performance trends
- **Smart Notifications**: Configurable alerts for device status changes
- **CSV Data Logging**: Automatic recording of all monitoring data
- **Batch Operations**: Efficient multi-device monitoring cycles

## 🚀 Quick Start

### Prerequisites
- Python 3.8+ (tkinter included)
- Administrator privileges recommended for network operations
- Windows, macOS, or Linux support

### Installation
1. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Launch Application:**
   ```bash
   python network_monitor_gui.py
   ```

The application will automatically:
- Detect available network interfaces
- Load Azure theme with fallback support  
- Initialize configuration files
- Apply saved settings and device lists

## 📱 Application Interface

### 🔍 Live Monitoring Tab
- **Start/Stop Controls**: Toggle real-time monitoring with visual feedback
- **Device Status Grid**: IP, name, status, latency, and last check time
- **Status Indicators**: Color-coded 🟬 online/🔴 offline with icons indicators  
- **Manual Refresh**: Instant status updates with progress indication
- **Device Summary**: Real-time online/total device counts

### ⚙️ Device Management Tab
- **Device List**: Scrollable list with IP and name display
- **Form Controls**: Add, update, remove, and test individual devices
- **IP Validation**: Real-time validation with error handling
- **Duplicate Prevention**: Automatic duplicate IP detection
- **Bulk Selection**: Multi-device operations support

### 🔍 Network Discovery Tab
- **Multi-Interface Detection**: Automatic network interface discovery
- **Network Selection**: Dropdown with interface details and gateway info
- **Intelligent Scanning**: Concurrent ping with hostname resolution toggle
- **Real-time Results**: Progressive device discovery with live updates
- **Device Classification**: Automatic device type detection (router, printer, etc.)
- **Hostname Resolution**: DNS and NetBIOS name lookup with performance controls
- **Batch Import**: Select and add multiple discovered devices at once

### 📊 History & Analytics Tab
- **Log Viewer**: Filterable historical monitoring data
- **Uptime Statistics**: Device availability percentages and trends
- **Performance Metrics**: Response time analytics and charts
- **Export Options**: CSV and JSON data export capabilities
- **Data Management**: Log rotation and cleanup tools

### 🎨 Menu System
- **File Menu**: Configuration import/export, log management, application exit
- **Tools Menu**: Network discovery access, ping testing, comprehensive settings
- **View Menu**: Light/dark theme switching, manual display refresh
- **Help Menu**: Application information and version details

## ⚙️ Configuration

### Monitoring Settings
- **Monitor Interval**: Ping cycle frequency (1-300 seconds)
- **Ping Timeout**: Individual ping timeout (1-10 seconds)  
- **Max Retries**: Failed ping attempts before offline status (0-5)
- **Log File Path**: CSV file location for historical data
- **Auto-save**: Automatic configuration and device list persistence

### Advanced Settings
- **Notifications**: Toast notification system with status change alerts
- **Hostname Resolution**: Toggle DNS/NetBIOS lookups for performance control
- **Theme Selection**: Azure light/dark theme with instant switching
- **Thread Pool Size**: Concurrent operation limits for optimal performance

### Configuration Files
- `gui_settings.json`: Application settings and preferences
- `devices.json`: Device list and configurations
- `network_log.csv`: Historical monitoring data

## 🔧 Advanced Usage

### Smart Network Discovery
1. **Auto-Detection**: Application automatically detects all network interfaces
2. **Network Selection**: Choose from available networks with interface details
3. **Scan Configuration**: Toggle hostname resolution for speed vs. detail trade-off
4. **Progressive Results**: Watch devices appear in real-time during scan
5. **Batch Import**: Select multiple devices and add them to monitoring list

### Performance Optimization
- **Hostname Resolution Toggle**: Disable for faster scanning (IP-only results)
- **Concurrent Operations**: Utilizes thread pools for non-blocking operations
- **Optimized Timeouts**: Smart timeout management (1s DNS, 1.5s NetBIOS)
- **Progressive UI Updates**: Real-time result display without UI freezing

### Data Management
- **Configuration Backup**: Full JSON export of devices and settings
- **Log Analytics**: Historical data analysis with uptime calculations
- **Selective Export**: Choose data ranges and formats for external analysis
- **Auto-cleanup**: Built-in log rotation and management tools

## 🔍 Troubleshooting

### Common Issues

**Application Startup Problems:**
```bash
# Verify Python and dependencies
python -c "import tkinter, ping3, concurrent.futures"

# Install requirements
pip install -r requirements.txt

# Run with admin privileges (recommended)
```

**Theme Loading Issues:**
- Azure theme auto-fallback to system theme if files missing
- Check for `theme/azure.tcl` in application directory
- Theme switching available in View menu regardless

**Network Discovery Problems:**
- **Slow Scanning**: Disable hostname resolution for faster results
- **No Devices Found**: Check ICMP/ping permissions and firewall settings
- **Interface Detection**: Requires admin privileges on some systems
- **Hostname Failures**: NetBIOS resolution requires Windows networking

**Performance Issues:**
- **UI Freezing**: Ensure hostname resolution is working properly in background
- **Memory Usage**: Large networks benefit from smaller concurrent thread pools
- **Timeout Errors**: Adjust ping timeouts in settings for slow networks

## 📁 File Structure

```
Local-Network-Monitor/
├── network_monitor_gui.py      # Main application (2000+ lines)
├── theme/
│   └── azure.tcl              # Modern theme with light/dark modes
├── requirements.txt           # Python dependencies (ping3, colorama, tabulate)
├── gui_settings.json         # Application settings (auto-generated)
├── devices.json              # Device configurations (auto-generated)
├── network_log.csv           # Historical monitoring data (auto-generated)
└── README.md                # This documentation
```

## 🎯 Key Benefits

### Technical Excellence
- **Multi-threaded Architecture**: Non-blocking UI with concurrent background operations
- **Smart Performance**: Optimized scanning with configurable timeout and thread management
- **Cross-platform**: Native Python/Tkinter with Windows, macOS, and Linux support
- **Resource Efficient**: Minimal memory footprint with intelligent caching

### User Experience
- **Professional Interface**: Modern Azure theme with intuitive workflow design
- **Real-time Feedback**: Progressive updates, toast notifications, and visual progress indicators
- **Flexible Configuration**: Extensive customization options for different network environments
- **Data Persistence**: Automatic saving of configurations, settings, and monitoring history

## 📊 Performance Notes

### Optimizations Implemented
- **Thread Pool Management**: Separate pools for ping scanning (50 workers) and hostname resolution (30 workers)
- **Progressive UI Updates**: Results appear in real-time without blocking the interface
- **Smart Timeouts**: 1-second ping, 1-second DNS, 1.5-second NetBIOS resolution
- **Background Processing**: All network operations run in background threads
- **Memory Efficiency**: Optimized data structures and automatic cleanup

### Network Discovery Speed
- **Fast Mode** (hostname resolution disabled): ~50-100 IPs/second
- **Full Mode** (with hostname resolution): ~10-30 IPs/second
- **Large Networks**: /16 subnets scan in 5-15 minutes depending on mode

## 🆘 Support

### Getting Help
1. **Check Troubleshooting**: Review the troubleshooting section for common issues
2. **Verify Setup**: Ensure Python 3.8+ and all dependencies are properly installed
3. **Admin Privileges**: Run with administrator privileges for full network access
4. **System Compatibility**: Tkinter is included with standard Python installations

