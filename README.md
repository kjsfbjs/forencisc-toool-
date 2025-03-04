# forencisc-toool-
a all in one forencics tool 
# 🔍 Forensic Toolkit 2.0

## 📌 Overview

Forensic Toolkit 2.0 is a **command-line forensic analysis tool** designed for security professionals and digital forensic investigators. It provides multiple functionalities, including file hashing, EXIF metadata extraction, process analysis, network monitoring, malware scanning, and more.

## 🚀 Features

- **File Hashing** (MD5, SHA1, SHA256) ✅
- **Extract EXIF Data** from images 📸
- **List Running Processes** 🖥️
- **Analyze Network Connections** 🌐
- **Capture Live Network Packets** 📡
- **Extract Browser History** 🔍
- **USB Device History** 🔌
- **GeoIP Lookup** for IP addresses 🌍
- **YARA Malware Scanning** 🦠

## 📥 Installation

### 1️⃣ Clone the Repository

```sh
git clone https://github.com/yourusername/forensic-toolkit.git
cd forensic-toolkit
```

### 2️⃣ Install Dependencies

```sh
pip install -r requirements.txt
```

**Required Libraries:** `psutil`, `pyexifinfo`, `dpkt`, `pyshark`, `yara-python`, `pygeoip`, `scapy`

**Additional Requirement:** Download **GeoLiteCity.dat** from [MaxMind](https://www.maxmind.com/en/geoip2-databases) and place it in the same directory as the script.

## ▶️ Usage

Run the tool:

```sh
python forensic_tool.py
```

### 🛠️ CLI Menu Options:

1️⃣ **File Hashing** – Verify file integrity using cryptographic hashes.
2️⃣ **EXIF Data Extraction** – Extract metadata from images.
3️⃣ **List Processes** – View currently running system processes.
4️⃣ **List Network Connections** – Display active network connections.
5️⃣ **Capture Network Packets** – Sniff real-time network traffic.
6️⃣ **Extract Browser History** – Fetch browsing history from Chrome/Firefox.
7️⃣ **USB Device History** – List previously connected USB devices.
8️⃣ **GeoIP Lookup** – Find the location of an IP address.
9️⃣ **YARA Malware Scanning** – Scan files for malware using YARA rules.
🔟 **Exit** – Close the tool.

## 📌 Example Usage

**Example: Compute SHA256 hash of a file**

```sh
Enter file path: /path/to/file.exe  
Enter hash algorithm (md5, sha1, sha256): sha256  
Output: f2c7bb8acc97f92da089e30d9fa3f717c7a30...
```

**Example: Extract EXIF metadata from an image**

```sh
Enter image file path: /path/to/photo.jpg  
Output: { "Camera": "Canon EOS 5D", "GPS": "37.7749° N, 122.4194° W" }
```

## 🛡️ Future Improvements

- 📄 **Generate Automated Reports (PDF/HTML)**
- 🗃️ **File Carving for Deleted File Recovery**
- 🧠 **Live Memory Forensics**
- 📊 **Real-Time System Monitoring**

## 🏆 Why Use This Tool?

✅ **All-in-One Forensic Suite**\
✅ **Easy-to-Use CLI Interface**\
✅ **Cross-Platform (Windows, Linux, macOS)**\
✅ **Lightweight, No GUI Needed**

## 📜 License

This project is licensed under the **MIT License**.

## 🙌 Contributions

Contributions are welcome! Feel free to fork, improve, and submit pull requests.

---

🔗 **GitHub:** [https://github.com/yourusername/forensic-toolkit](https://github.com/yourusername/forensic-toolkit)

by sahil 
