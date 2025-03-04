import os
import hashlib
import psutil
import json
import dpkt
import socket
import datetime
import sqlite3
from shutil import copyfile
import subprocess
import pyshark
import yara
import pygeoip
from scapy.all import sniff, wrpcap
from PIL import Image
from PIL.ExifTags import TAGS

def get_file_hash(file_path, algo='sha256'):
    hash_func = getattr(hashlib, algo)()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hash_func.update(chunk)
    return hash_func.hexdigest()

def extract_exif(file_path):
    try:
        image = Image.open(file_path)
        exif_data = image._getexif()
        if not exif_data:
            return "No EXIF data found."
        exif_dict = {TAGS.get(tag, tag): value for tag, value in exif_data.items()}
        return json.dumps(exif_dict, indent=4)
    except Exception as e:
        return f"Error extracting EXIF: {e}"

def list_processes():
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username']):
        processes.append(proc.info)
    return json.dumps(processes, indent=4)

def list_network_connections():
    connections = []
    for conn in psutil.net_connections(kind='inet'):
        connections.append({
            'local_address': conn.laddr,
            'remote_address': conn.raddr,
            'status': conn.status
        })
    return json.dumps(connections, indent=4)

def capture_packets(interface='eth0', count=10):
    packets = sniff(count=count, iface=interface)
    wrpcap('/tmp/packets.pcap', packets)
    return f"Packets captured to /tmp/packets.pcap ({count} packets)"

def extract_browser_history(browser='chrome'):
    history_db = os.path.expanduser(f'~/Library/Application Support/{browser}/Default/History')
    copyfile(history_db, '/tmp/history_copy.db')
    conn = sqlite3.connect('/tmp/history_copy.db')
    cursor = conn.cursor()
    cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 10")
    history = cursor.fetchall()
    conn.close()
    return json.dumps(history, indent=4)

def get_usb_history():
    return os.popen("lsusb").read()

def get_geoip(ip):
    geo = pygeoip.GeoIP('GeoLiteCity.dat')
    return geo.record_by_addr(ip)

def yara_scan(directory, rule_file):
    rules = yara.compile(rule_file)
    matches = {}
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            matches[file_path] = rules.match(file_path)
    return json.dumps(matches, indent=4)

def cli_menu():
    while True:
        print("\nForensic Toolkit 2.0 Menu:")
        print("1. File Hashing")
        print("2. EXIF Data Extraction")
        print("3. List Processes")
        print("4. List Network Connections")
        print("5. Capture Network Packets")
        print("6. Extract Browser History")
        print("7. USB Device History")
        print("8. GeoIP Lookup")
        print("9. YARA Rule Scanning")
        print("10. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            file_path = input("Enter file path: ")
            algo = input("Enter hash algorithm (md5, sha1, sha256): ")
            print(get_file_hash(file_path, algo))
        elif choice == '2':
            file_path = input("Enter image file path: ")
            print(extract_exif(file_path))
        elif choice == '3':
            print(list_processes())
        elif choice == '4':
            print(list_network_connections())
        elif choice == '5':
            iface = input("Enter network interface (default: eth0): ") or 'eth0'
            count = int(input("Enter number of packets to capture: "))
            print(capture_packets(iface, count))
        elif choice == '6':
            browser = input("Enter browser name (chrome, firefox): ")
            print(extract_browser_history(browser))
        elif choice == '7':
            print(get_usb_history())
        elif choice == '8':
            ip = input("Enter IP address for GeoIP lookup: ")
            print(get_geoip(ip))
        elif choice == '9':
            directory = input("Enter directory to scan: ")
            rule_file = input("Enter YARA rule file path: ")
            print(yara_scan(directory, rule_file))
        elif choice == '10':
            print("Exiting...")
            break
        else:
            print("Invalid option! Please try again.")

if __name__ == "__main__":
    cli_menu()
