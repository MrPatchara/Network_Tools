# 🌐 Network Management Suite v3.1 - Professional Edition

<div align="center">

![Version](https://img.shields.io/badge/version-3.1-blue.svg)
![Python](https://img.shields.io/badge/python-3.7+-green.svg)
![License](https://img.shields.io/badge/license-MIT-yellow.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)

**A comprehensive, professional-grade network diagnostic and management tool built with PyQt5**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Screenshots](#-screenshots) • [Contributing](#-contributing) • [License](#-license)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage](#-usage)
- [Features in Detail](#-features-in-detail)
- [Building from Source](#-building-from-source)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)
- [Author](#-author)

---

## 🎯 Overview

**Network Management Suite** is a powerful, all-in-one network diagnostic tool designed for network administrators, IT professionals, and developers. It provides a modern, intuitive graphical interface for performing comprehensive network analysis, troubleshooting, and monitoring tasks.

Whether you need to scan your local network, diagnose connectivity issues, analyze port availability, or perform DNS lookups, this tool provides everything you need in a single, elegant application.

### Key Highlights

- 🚀 **High-Performance Scanning**: Multi-threaded network scanning with configurable speed profiles
- 🎨 **Modern UI**: Beautiful, dark-themed interface built with PyQt5
- 📊 **Real-Time Monitoring**: Live network statistics and activity logging
- 🔍 **Comprehensive Tools**: Network scanner, ping, port scanner, DNS lookup, traceroute, and more
- 💾 **Export Capabilities**: Save scan results in CSV, JSON, or TXT formats
- 🔧 **Cross-Platform**: Works on Windows, Linux, and macOS

---

## ✨ Features

### Core Functionality

- **📡 Network Scanner**
  - Automatic network interface detection
  - Multi-subnet scanning support
  - Configurable scan speed (Eco, Balanced, Turbo)
  - Real-time progress tracking
  - Hostname resolution
  - Export results to multiple formats

- **📡 Ping & Connectivity**
  - Multi-round ping testing
  - Configurable ping rounds and counts
  - Real-time ping statistics
  - Connectivity health checks
  - Color-coded results (green/orange/red)

- **🚪 Port Scanner**
  - Custom port range scanning
  - Preset port ranges (Common, Well-known, All)
  - Multi-threaded port scanning
  - Open port detection and reporting

- **🌐 DNS & Traceroute**
  - Forward DNS lookup (Hostname → IP)
  - Reverse DNS lookup (IP → Hostname)
  - Traceroute with configurable max hops
  - Real-time route visualization

- **📋 Network Information**
  - Network interface details
  - ARP table viewer
  - Interface status monitoring
  - Network statistics dashboard

- **📊 Dashboard**
  - Quick action buttons
  - Live network statistics
  - Health check functionality
  - One-click diagnostics

### Advanced Features

- **Multi-Threading**: Efficient concurrent operations for fast scanning
- **Smart Limits**: Automatic host count limits to maintain UI responsiveness
- **Activity Logging**: Comprehensive logging of all operations
- **Progress Tracking**: Real-time progress bars and statistics
- **Export Options**: CSV, JSON, and TXT export formats
- **Network Monitoring**: Live network statistics with psutil integration
- **Professional UI**: Modern dark theme with intuitive navigation

---

## 📦 Requirements

### System Requirements

- **Operating System**: Windows 7+, Linux, or macOS
- **Python**: 3.7 or higher
- **RAM**: 512 MB minimum (2 GB recommended for large scans)
- **Network**: Active network connection

### Python Dependencies

- `PyQt5` >= 5.15.0
- `psutil` >= 5.8.0 (optional, for enhanced network statistics)

---

## 🚀 Installation

### Method 1: Using Pre-built Executable (Windows)

1. Download the latest release from the [Releases](https://github.com/yourusername/Network_Tools/releases) page
2. Extract the ZIP file
3. Run `Network Scanner v1.0.exe` from the extracted folder
4. No installation required!

### Method 2: Install from Source

#### Step 1: Clone the Repository

```bash
git clone https://github.com/yourusername/Network_Tools.git
cd Network_Tools
```

#### Step 2: Install Dependencies

**Using pip:**

```bash
pip install PyQt5 psutil
```

**Using requirements.txt (if available):**

```bash
pip install -r requirements.txt
```

#### Step 3: Run the Application

```bash
python "Network Scanner v1.0.py"
```

### Method 3: Build Your Own Executable

1. Install PyInstaller:
   ```bash
   pip install pyinstaller
   ```

2. Build the executable:
   ```bash
   pyinstaller "Network Scanner v1.0.spec"
   ```

3. The executable will be in the `dist` folder

---

## 💻 Usage

### Getting Started

1. **Launch the Application**
   - Double-click the executable or run the Python script
   - The application will automatically detect your network interfaces

2. **Quick Network Scan**
   - Go to the **Network Scanner** tab
   - Select a network from the dropdown (or choose "All detected networks")
   - Choose a speed profile (Eco/Balanced/Turbo)
   - Click **▶ Start Scan**
   - View results in the table below

3. **Ping a Target**
   - Enter an IP address or hostname in the target field
   - Go to the **Ping & Connectivity** tab
   - Configure rounds and pings per round
   - Click **▶ Start Ping**

4. **Port Scanning**
   - Enter a target IP address
   - Go to the **Port Scanner** tab
   - Set port range or choose a preset
   - Click **▶ Start Port Scan**

5. **DNS Lookup**
   - Go to the **DNS & Traceroute** tab
   - Enter a hostname or IP address
   - Select lookup type (Forward/Reverse)
   - Click **🔍 Lookup**

### Tips & Best Practices

- **Large Networks**: Use "Eco" mode for large networks to reduce system load
- **Quick Scans**: Use "Turbo" mode for smaller networks (< 1000 hosts)
- **Export Results**: Always export important scan results for documentation
- **Health Checks**: Run health checks regularly to monitor network status
- **ARP Table**: Refresh ARP table to see recently connected devices

---

## 🔍 Features in Detail

### Network Scanner

The network scanner automatically detects all active network interfaces and allows you to:

- Scan individual subnets or all detected networks
- Choose from three speed profiles:
  - **Eco**: 80 concurrent workers (gentle on system)
  - **Balanced**: 200 concurrent workers (recommended)
  - **Turbo**: 400 concurrent workers (fast, resource-intensive)
- View results in a sortable table with IP addresses and hostnames
- Export results to CSV, JSON, or TXT formats
- Double-click any result to use it as a target for other tools

### Ping & Connectivity

Advanced ping functionality with:

- **Multi-round Testing**: Test connectivity over multiple rounds
- **Configurable Parameters**: Adjust rounds (1-10) and pings per round (1-20)
- **Color-coded Results**: 
  - 🟢 Green: 0% packet loss
  - 🟠 Orange: Partial packet loss
  - 🔴 Red: 100% packet loss
- **Real-time Output**: See ping responses as they happen

### Port Scanner

Comprehensive port scanning with:

- **Custom Ranges**: Scan any port range from 1-65535
- **Preset Options**:
  - Common ports (1-1000)
  - Well-known ports (1-1023)
  - All ports (1-65535)
- **Progress Tracking**: Real-time progress bar and status updates
- **Open Port Detection**: Identifies all open ports on the target

### Network Information

Monitor your network with:

- **Interface Details**: View all network interfaces with IP addresses, netmasks, and status
- **ARP Table**: See all devices in your ARP cache with IP and MAC addresses
- **Live Statistics**: Real-time network traffic statistics (requires psutil)
- **Auto-refresh**: Automatic updates every 5 seconds

### Dashboard

Quick access to common tasks:

- **Quick Actions**: One-click access to all major functions
- **Live Statistics**: Real-time network statistics display
- **Health Check**: Comprehensive connectivity test
- **Network Info Refresh**: Update all network information

---

## 🔨 Building from Source

### Prerequisites

- Python 3.7+
- PyInstaller (for building executables)
- All Python dependencies installed

### Build Steps

1. **Install Build Tools**
   ```bash
   pip install pyinstaller
   ```

2. **Prepare Assets**
   - Ensure `icon.ico` and `icon.png` are in the project root
   - Verify `logo.png` exists if used

3. **Build Executable**
   ```bash
   pyinstaller "Network Scanner v1.0.spec"
   ```

4. **Output Location**
   - Windows: `dist/Network Scanner v1.0/Network Scanner v1.0.exe`
   - The executable and required files will be in the dist folder

### Customization

Edit `Network Scanner v1.0.spec` to:
- Change the executable name
- Modify icon settings
- Add additional data files
- Configure UPX compression

---

## 🐛 Troubleshooting

### Common Issues

**Issue: Application won't start**
- **Solution**: Ensure Python 3.7+ is installed and all dependencies are installed correctly
- **Check**: Run `python --version` and `pip list | grep PyQt5`

**Issue: Network scan finds no hosts**
- **Solution**: 
  - Check that you have an active network connection
  - Refresh network information using the "🔄 Detect" button
  - Verify your network interface is up and has an IP address

**Issue: Port scan is slow**
- **Solution**: 
  - Reduce the port range
  - Check your network connection speed
  - Ensure the target is reachable

**Issue: psutil statistics not showing**
- **Solution**: Install psutil: `pip install psutil`
- **Note**: The application works without psutil, but statistics will be limited

**Issue: Permission denied errors (Linux/macOS)**
- **Solution**: Some operations may require elevated privileges
- **Try**: Running with `sudo` (not recommended for GUI apps) or configure proper permissions

### Performance Tips

- Use "Eco" mode for large network scans (> 5000 hosts)
- Close other network-intensive applications during scanning
- Limit port scan ranges to commonly used ports when possible
- Use "Balanced" mode as the default for best performance/resource balance

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Contribution Guidelines

- Follow the existing code style
- Add comments for complex logic
- Test your changes thoroughly
- Update documentation as needed
- Ensure compatibility with Windows, Linux, and macOS

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**Mr. Patchara Al-umaree**

- **Email**: [Patcharaalumaree@gmail.com](mailto:Patcharaalumaree@gmail.com)
- **Role**: Network Operations & Solutions Architect

### Mission & Vision

- Deliver enterprise-grade troubleshooting tools that remain lightweight and portable
- Provide one-click diagnostics so teams can resolve incidents faster
- Keep interfaces focused on clarity, accuracy, and actionable insights
- Continuously expand capabilities to cover the entire network lifecycle

### Current Focus Areas

- ✔ Unified network scanning across all adapters
- ✔ Rapid health checks and smart logging
- ✔ Modular design for future automations

---

## 🙏 Acknowledgments

- **PyQt5** team for the excellent GUI framework
- **psutil** developers for comprehensive system and network utilities
- All contributors and users who have provided feedback

---

## 📞 Support

If you encounter any issues or have questions:

1. Check the [Troubleshooting](#-troubleshooting) section
2. Search existing [Issues](https://github.com/yourusername/Network_Tools/issues)
3. Create a new issue with detailed information
4. Contact the author via email

---

<div align="center">

**Made with ❤️ for network administrators and IT professionals**

⭐ Star this repo if you find it useful!

</div>
