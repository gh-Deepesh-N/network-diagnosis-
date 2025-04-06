from flask import Flask, render_template, request, jsonify
import platform, psutil, requests, time, subprocess, json, socket
from dns import resolver
from scapy.all import ARP, Ether, srp, conf
import os
import sys
import socket
import struct

app = Flask(__name__)
speed_test_history = []

# ------------------ UTILITIES ------------------

def get_local_subnet():
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        ip_parts = local_ip.split('.')
        return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
    except:
        return "192.168.1.0/24"

def is_admin():
    try:
        return os.geteuid() == 0  # UNIX
    except AttributeError:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0  # Windows

def get_geolocation():
    try:
        data = requests.get("https://ipinfo.io").json()
        return data.get("loc", "N/A")
    except Exception as e:
        return f"Error: {e}"

# ------------------ SPEED TEST ------------------

def test_network_speed():
    try:
        result = subprocess.run(["speedtest-cli"], capture_output=True, text=True)
        if result.returncode == 0:
            output = result.stdout
            download = extract_value(output, "Download:")
            upload = extract_value(output, "Upload:")
            ping = extract_value(output, "Ping:")

            result_data = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "download": download,
                "upload": upload,
                "ping": ping,
                "geolocation": get_geolocation()
            }
            speed_test_history.append(result_data)
            return result_data
        else:
            return {"error": f"Speedtest CLI error: {result.stderr}"}
    except Exception as e:
        return {"error": str(e)}

def extract_value(output, label):
    for line in output.split('\n'):
        if label in line:
            return line.split(label)[1].strip()
    return "N/A"

# ------------------ OTHER DIAGNOSTICS ------------------

def get_system_info():
    try:
        mem = psutil.virtual_memory()
        return {
            "Operating System": f"{platform.system()} {platform.release()}",
            "System Version": platform.version(),
            "CPU": platform.processor(),
            "Memory Total": f"{mem.total / (1024**3):.2f} GB",
            "Memory Available": f"{mem.available / (1024**3):.2f} GB"
        }
    except Exception as e:
        return {"error": str(e)}

def network_device_discovery():
    try:
        subnet = get_local_subnet()
        arp = ARP(pdst=subnet)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        result = srp(packet, timeout=2, verbose=0)[0]
        devices = [{"IP": rcv.psrc, "MAC": rcv.hwsrc} for snd, rcv in result]

        if not devices:
            return {"message": "No devices found. Try again with admin privileges."}

        return devices
    except PermissionError:
        return {"error": "Permission denied. Run the app with administrator/root privileges."}
    except Exception as e:
        return {"error": str(e)}

def resolve_dns(host):
    try:
        answers = resolver.resolve(host, "A")
        return [rdata.address for rdata in answers]
    except Exception as e:
        return {"error": str(e)}

# ------------------ FLASK ROUTES ------------------

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/speedtest")
def speedtest_route():
    return jsonify(test_network_speed())

@app.route("/systeminfo")
def systeminfo_route():
    return jsonify(get_system_info())

@app.route("/devices")
def devices_route():
    return jsonify(network_device_discovery())

@app.route("/dns", methods=["POST"])
def dns_route():
    host = request.form.get("host")
    return jsonify(resolve_dns(host))

@app.route("/history")
def history_route():
    return jsonify(speed_test_history)

# ------------------ START SERVER ------------------

if __name__ == "__main__":
    conf.verb = 0  # Disable scapy verbosity
    app.run(debug=True)
