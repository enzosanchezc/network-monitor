import nmap
import sqlite3
import subprocess
import time
import os
from dotenv import load_dotenv
load_dotenv()

# specify the network to scan, 192.168.0.0/24 by default
network = os.getenv("NETWORK") or "192.168.0.0/24"

# create an nmap scanner object
nm = nmap.PortScanner()

# get the current time
timestamp = int(time.time())

# create a database connection and cursor
conn = sqlite3.connect("network_monitor_" + network.replace("/", "_") + ".db")
c = conn.cursor()

# create tables if they do not exist
c.execute("""CREATE TABLE IF NOT EXISTS active_devices (
                mac TEXT PRIMARY KEY,
                ip TEXT,
                hostname TEXT,
                last_seen INTEGER,
                first_seen INTEGER,
                FOREIGN KEY (mac) REFERENCES devices(mac)
            )""")
c.execute("""CREATE TABLE IF NOT EXISTS devices (
                mac TEXT PRIMARY KEY,
                hostname TEXT,
                first_seen INTEGER,
                last_seen INTEGER,
                last_state TEXT
            )""")
c.execute("""CREATE TABLE IF NOT EXISTS connection_log (
                mac TEXT,
                hostname TEXT,
                connection_status TEXT,
                timestamp INTEGER,
                FOREIGN KEY (mac) REFERENCES devices(mac)
            )""")

# function to get the MAC address using ARP
def get_mac_address(ip):
    try:
        output = subprocess.check_output(["arp", "-n", ip])
        output = output.decode("utf-8").strip().split("\n")[-1].split()
        mac_address = output[2]
        return mac_address
    except:
        return None

# function to update the active_devices table
def update_active_devices():
    # scan the network for active hosts using nmap ping scan
    nm.scan(hosts=network, arguments="-sn")

    # iterate through each host found by nmap
    for host in nm.all_hosts():
        # get the MAC address using ARP
        mac_address = get_mac_address(host)

        # if the MAC address is not found, skip this host
        if mac_address is None:
            continue

        # get the hostname if available
        try:
            hostname = nm[host].hostname()
        except:
            hostname = None

        # set last state to connected
        last_state = "connected"

        # check if the device is already in the devices table
        c.execute("SELECT * FROM devices WHERE mac=?", (mac_address,))
        result = c.fetchone()

        # if the device is not in the devices table, add it
        if result is None:
            c.execute("INSERT INTO devices VALUES (?, ?, ?, ?, ?)", (mac_address, hostname, timestamp, timestamp, last_state))

        # add/update the device in the active_devices table
        c.execute("SELECT * FROM active_devices WHERE mac=?", (mac_address,))
        result = c.fetchone()

        if result is None:
            c.execute("INSERT INTO active_devices VALUES (?, ?, ?, ?, ?)", (mac_address, host, hostname, timestamp, timestamp))
        else:
            c.execute("UPDATE active_devices SET ip=?, hostname=?, last_seen=? WHERE mac=?", (host, hostname, timestamp, mac_address))

    # commit changes to the database
    conn.commit()

# function to log connection changes
def log_connection_changes():    
    # query the devices table
    c.execute("SELECT * FROM devices")
    devices = c.fetchall()
    c.execute("SELECT * FROM active_devices")
    active_devices = c.fetchall()

    # iterate through each device
    for device in devices:
        # get the MAC address
        mac_address = device[0]

        # check if the device is active
        active = False
        for active_device in active_devices:
            if active_device[0] == mac_address:
                active = True
                break

        # get the last state
        last_state = device[4]

        # if the device is active and the last state was disconnected, log a connection
        if active and last_state == "disconnected":
            c.execute("INSERT INTO connection_log VALUES (?, ?, ?, ?)", (mac_address, device[1], "connected", timestamp))

        # if the device is not active and the last state was connected, log a disconnection
        if not active and last_state == "connected":
            c.execute("INSERT INTO connection_log VALUES (?, ?, ?, ?)", (mac_address, device[1], "disconnected", timestamp))

        # update the last state
        if active:
            last_state = "connected"
        else:
            last_state = "disconnected"

        # update the devices table
        c.execute("UPDATE devices SET last_seen=?, last_state=? WHERE mac=?", (timestamp, last_state, mac_address))

    # commit changes to the database
    conn.commit()

# update the active_devices table and log connection changes 
update_active_devices()
log_connection_changes()

