# 🔍 Secure Automated Volatile Data Triage And Acquisition


## 📋 Overview

This project implements an advanced forensic evidence collection and verification system that addresses critical gaps in modern incident response workflows. The system automatically collects volatile data from compromised Windows endpoints, applies immediate cryptographic hashing and digital signing at the point of collection, and validates evidence integrity in real-time on a central server.

Unlike traditional manual forensic tools, this system eliminates the time gap between evidence collection and integrity verification, provides automatic Chain-of-Custody documentation, and detects tampering attempts instantly.

## ✨ Key Features

✅ **Real-Time Evidence Collection** - Rapid triage of volatile artifacts without full disk imaging  
🔐 **Cryptographic Integrity** - SHA-256 hashing immediately upon collection  
✍️ **Digital Signatures** - RSA signing for non-repudiation and collector authentication  
📋 **Interactive Chain-of-Custody** - Dynamic case documentation with investigator details  
🛡️ **Tamper Detection** - Real-time hash validation with automatic rejection of modified evidence  
⛓️ **Immutable Ledger** - Cryptographically linked audit trail for legal admissibility  
⚡ **One-Click Automation** - Batch file automation for simplified workflow  
📊 **Professional Web Dashboard** - Complete evidence viewing with legal compliance  

## 🏗️ System Architecture

### 🔹 Windows VM (Client Agent)
- **Interactive CoC Input**
- **Multi-Artifact Collection**
- **Immediate Hashing/Signing**
- **Automatic Dashboard Launch**

### 🔹 Kali VM (Verification Server)
- **Real-Time Verification**
- **MariaDB Database Storage**
- **Immutable Ledger**
- **Flask Web Dashboard**


## Collected Artifacts

The system collects critical volatile artifact types such as:

1. **Running Processes** - Active programs and malware
2. **Network Connections** - Command & Control channels
3. **Registry Run Keys** - Persistence mechanisms
4. **Startup Items** - Auto-launch programs
5. **Scheduled Tasks** - Automated malicious scripts
6. **Browser History Indicators** - User activity traces
7. **System Information** - Computer and user details

## Security Features

### Cryptographic Protection
- **SHA-256 Hashing**: Proves evidence integrity from moment of collection.
- **RSA Digital Signatures**: Provides non-repudiation and authenticates collector identity.
- **HTTPS Transfer**: Secures evidence in transit between client and server.

### Legal Compliance
- **Automatic Chain-of-Custody**: Documents Who, When, Where, Why for each collection.
- **Immutable Audit Trail**: Each database record cryptographically linked to prevent tampering.
- **Court-Admissible Evidence**: Meets legal standards for digital evidence.
---
## Installation & Setup

### Prerequisites
- **Windows 10/11 VM** (Victim/Target machine)
- **Kali Linux VM** (Forensic server)
- **VirtualBox Host-Only Network** configured between VMs
- **Static IPs**: Windows (192.168.56.10), Kali (192.168.56.20)

### *Server Setup* (Kali Linux)
```bash
# Clone repository
git clone https://github.com/rosh-0110/forensics_triage_system.git
cd forensics_triage_system/server

# Install dependencies
pip3 install flask flask-login mysql-connector-python cryptography pyopenssl

# Start server
python3 app.py
```
### *Client Setup* (Windows)
```bash
# Navigate to client folder
cd C:\forensics_project\client

# Run collection tool
run_forensics.bat
```
## 🚀Usage

1. **Start both VMs** with **Host-Only networking** properly configured.
2. **On the Kali VM**, ensure the server is running.
3. **On Windows VM**, double-click "run_forensics.bat".
4. **Enter Chain-of-Custody details when prompted:**
     - 👤**Investigator Name**
     - 🆔**Investigator ID**
     - 🏢**Department**
     - 📍**Location**
     - 📝**Case Description**
5. **Dashboard opens automatically** showing evidence status.
## Dahboard Access
- 🌐**URL**: https://192.168.56.20:5000
- 🔑**Login**: admin/admin123

## 🧪Tampering Test
### *To verify tamper detection works:*

1. Add tampering code to collector.py:
```Python

# TAMPERING TEST - Add before send_to_server()
if artifacts['processes']:
    artifacts['processes'][0]['name'] = "MALICIOUS_TAMPERED_PROCESS.exe"
```
2. **Run collection** - Evidence will be **REJECTED** with **Hash: MISMATCH**.
3. **Remove tampering code** for normal operation.

## Security Notes
### ⚠️ Academic Demonstration Only

- Private keys included for demonstration purposes.
- Not intended for production use without proper key management.
- Repository contains sample evidence for testing.
### 🔒 For Production Use:

- Generate unique keys per deployment.
- Store private keys securely on client machines only.
- Use proper SSL certificates instead of self-signed.
- Implement user authentication and access controls.

## 🛠️Technical Specifications
- **Frontend:** Python CLI with interactive input.
- **Backend:** Flask web framework with MariaDB.
- **Cryptography:** SHA-256 hashing, RSA-2048 digital signatures.
- **Database:** MariaDB with JSON support for artifact storage.
- **Network:** HTTPS with self-signed certificates.
- **Authentication:** Basic login with password hashing.

## 🎓Academic Context
  This project was developed as a cybersecurity/forensics academic project addressing real-world incident response challenges:

   - **Speed vs. Integrity:** Balances rapid triage with cryptographic proof.
   - **Legal Compliance:** Implements automatic Chain-of-Custody documentation.
   - **Scalability:** Designed for multi-endpoint incident response.
   - **Technical Depth:** Combines forensics, cryptography, and secure development.

## Web Dashboard Features
   - 📊 Evidence statistics and status indicators.
   - 📋 Complete Chain-of-Custody legal details.
   - 🔍 Expandable artifact viewing with JSON formatting.
   - ⛓️ Immutable chain integrity verification.

---
## 📸 Screenshots
## Interactive Chain-of-Custody Input

## Server Response


---
## 💡Future Enhancements
- Docker containerization
- Email alerts for tampering detection
- Mobile forensic artifact collection
  
---

## 👤 Author

**Developed by:** Roshini  
**Project Type:** Academic 

---
