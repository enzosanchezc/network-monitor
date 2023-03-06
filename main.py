import datetime
import nmap
import sqlite3
import influxdb
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
            
        # set last state to connected
        last_state = "connected"
        c.execute("UPDATE devices SET last_seen=?, last_state=? WHERE mac=?", (timestamp, last_state, mac_address))

    # delete devices from the active_devices table that are no longer active
    c.execute("DELETE FROM active_devices WHERE last_seen<?", (timestamp - 60,))
    
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
            c.execute("UPDATE devices SET last_seen=?, last_state=? WHERE mac=?", (timestamp, "disconnected", mac_address))

    # commit changes to the database
    conn.commit()

# update the active_devices table and log connection changes 
update_active_devices()
log_connection_changes()

# insert active_devices into influx measument named "active_devices"
influx_host = os.getenv("INFLUX_HOST") or "localhost"
influx_port = int(os.getenv("INFLUX_PORT") or int(8086))
influx_db = os.getenv("INFLUX_DB") or "network_monitor"

influx_client = influxdb.InfluxDBClient(host=influx_host, port=influx_port, database=influx_db)
influx_client.create_database(influx_db)

# query the active_devices table
c.execute("SELECT * FROM active_devices")
active_devices = c.fetchall()

# iterate through each active device
for active_device in active_devices:
    # create a dictionary for the influxdb point
    point = {
        "measurement": "active_devices",
        "tags": {
            "mac": active_device[0],
            "ip": active_device[1],
            "hostname": active_device[2],
            "network": network
        },
        "time": active_device[3] * 1000000000,
        "fields": {
            "last_seen": datetime.datetime.fromtimestamp(active_device[3]).strftime('%Y-%m-%d %H:%M:%S'),
            "first_seen": datetime.datetime.fromtimestamp(active_device[4]).strftime('%Y-%m-%d %H:%M:%S')
        }
    }
    # write the point to influxdb
    influx_client.write_points([point])

# insert connection_log into influx measument named "connection_log"
# query the connection_log table
c.execute("SELECT * FROM connection_log")
connection_log = c.fetchall()

# iterate through each connection log entry
for log_entry in connection_log:
    # create a dictionary for the influxdb point
    point = {
        "measurement": "connection_log",
        "tags": {
            "mac": log_entry[0],
            "hostname": log_entry[1],
            "connection_status": log_entry[2],
            "network": network
        },
        "time": log_entry[3] * 1000000000,
        "fields": {
            "timestamp": datetime.datetime.fromtimestamp(log_entry[3]).strftime('%Y-%m-%d %H:%M:%S')
        }
    }

    # write the point to influxdb
    influx_client.write_points([point])

# close the database connection
conn.close()