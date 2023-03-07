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
c.execute("""CREATE TABLE IF NOT EXISTS devices (
                mac TEXT PRIMARY KEY,
                ip TEXT,
                hostname TEXT,
                first_seen INTEGER,
                last_seen INTEGER,
                status TEXT
            )""")
c.execute("""CREATE TABLE IF NOT EXISTS connection_log (
                mac TEXT,
                ip TEXT,
                hostname TEXT,
                timestamp INTEGER,
                status TEXT,
                FOREIGN KEY (mac) REFERENCES devices(mac)
            )""")

# function to get the MAC address using ARP
def get_mac_address(ip):
    output = subprocess.check_output(["arp", "-n", ip])
    output = output.decode("utf-8").strip().split("\n")[-1].split()
    mac_address = output[2]
    if mac_address != "--":
        return mac_address
    try:
        output = subprocess.check_output(["ip", "a"])
        output = output.decode("utf-8").split("\n")
        for idx, line in enumerate(output):
                if ip in line:
                    mac_address = output[idx-1].split()[1]
                    return mac_address
    except:
        return "00:00:00:00:00:00"

# function to update the active_devices table
def update_active_devices():
    # scan the network for active hosts using nmap ping scan
    nm.scan(hosts=network, arguments="-sn")

    # iterate through each host found by nmap
    for host in nm.all_hosts():
        # get the MAC address using ARP
        mac_address = get_mac_address(host)

        # get the hostname if available
        try:
            hostname = nm[host].hostname()
        except:
            hostname = None

        # set last state to online
        status = "online"

        # check if the device is already in the devices table
        c.execute("SELECT * FROM devices WHERE mac=?", (mac_address,))
        result = c.fetchone()

        # if the device is not in the devices table, add it
        if result is None:
            c.execute("INSERT INTO devices VALUES (?, ?, ?, ?, ?, ?)", (mac_address, host, hostname, timestamp, timestamp, status))
        else:
            c.execute("UPDATE devices SET ip=?, hostname=?, last_seen=?, status=? WHERE mac=?", (host, hostname, timestamp, status, mac_address))

    # set device to offline if it has not been seen in the last 60 seconds
    c.execute("UPDATE devices SET status=? WHERE last_seen<?", ("offline", timestamp - 60))
    
    # commit changes to the database
    conn.commit()

# function to log connection changes
def log_connection_changes():    
    # query the devices table
    c.execute("SELECT * FROM devices")
    devices = c.fetchall()

    # iterate through each device
    for device in devices:
        # get the MAC address
        mac_address = device[0]

        # check if the device is active
        active = False
        c.execute("SELECT * FROM devices WHERE mac=? AND status=?", (mac_address, "online"))
        result = c.fetchone()
        if result is not None:
            active = True

        # get the last state from the connection log
        c.execute("SELECT * FROM connection_log WHERE mac=? ORDER BY timestamp DESC LIMIT 1", (mac_address,))
        result = c.fetchone()
        if result is None:
            last_state = "offline"
        else:
            last_state = result[4]

        # if the device is active and the last state was offline, log a connection
        if active and last_state == "offline":
            c.execute("INSERT INTO connection_log VALUES (?, ?, ?, ?, ?)", (mac_address, device[1], device[2], timestamp, "online"))

        # if the device is not active and the last state was online, log a disconnection
        if not active and last_state == "online":
            c.execute("INSERT INTO connection_log VALUES (?, ?, ?, ?, ?)", (mac_address, device[1], device[2], timestamp, "offline"))
            c.execute("UPDATE devices SET last_seen=?, status=? WHERE mac=?", (timestamp, "offline", mac_address))

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

# query the active devices table
c.execute("SELECT * FROM devices")
devices = c.fetchall()

# iterate through each active device
for device in devices:
    # create a dictionary for the influxdb point
    point = {
        "measurement": "devices",
        "tags": {
            "mac": device[0],
            "network": network
        },
        "time": device[3] * 1000000000,
        "fields": {
            "ip": device[1],
            "hostname": device[2],
            "first_seen": datetime.datetime.fromtimestamp(device[3]).strftime('%Y-%m-%d %H:%M:%S'),
            "last_seen": datetime.datetime.fromtimestamp(device[4]).strftime('%Y-%m-%d %H:%M:%S'),
            "status": device[5]
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
            "network": network
        },
        "time": log_entry[3] * 1000000000,
        "fields": {
            "hostname": log_entry[2],
            "ip": log_entry[1],
            "connection_status": log_entry[4]
        }
    }
    # write the point to influxdb
    influx_client.write_points([point])

# close the database connection
conn.close()
