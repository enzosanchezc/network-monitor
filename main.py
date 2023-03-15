import datetime
import subprocess
import nmap
import sqlite3
import influxdb
import time
import os
from dotenv import load_dotenv
load_dotenv()

# specify the network to scan, 192.168.0.0/24 by default
NETWORK = os.getenv("NETWORK") or "192.168.0.0/24"
INFLUX_HOST = os.getenv("INFLUX_HOST") or "localhost"
INFLUX_PORT = int(os.getenv("INFLUX_PORT") or 8086)
INFLUX_DB = os.getenv("INFLUX_DB") or "network_monitor"

# create an nmap scanner object
nm = nmap.PortScanner()

# get the current time
timestamp = int(time.time())

# open influxdb connection
influx_client = influxdb.InfluxDBClient(
    host=INFLUX_HOST, port=INFLUX_PORT, database=INFLUX_DB)
influx_client.create_database(INFLUX_DB)

# create a database connection and cursor
conn = sqlite3.connect("network_monitor_" + NETWORK.replace("/", "_") + ".db")
c = conn.cursor()

# create tables if they do not exist
c.execute("""CREATE TABLE IF NOT EXISTS devices (
                mac TEXT PRIMARY KEY,
                ip TEXT,
                hostname TEXT,
                first_seen INTEGER,
                last_seen INTEGER,
                status INTEGER
            )""")


def get_self_mac():
    # get the MAC address of the device running the script
    dev = "eth0"
    routes = subprocess.check_output("ip r", shell=True).decode("utf-8").split("\n")
    for route in routes:
        if ".".join("192.168.192.0/24".split('/')[0].split('.')[:-1]) in route:
            dev = route.split('dev')[1].split()[0]
    output = subprocess.check_output("ip a show dev " + dev, shell=True).decode("utf-8").split("\n")
    for line in output:
        if "link/ether" in line:
            return line.split()[1].upper()
    return "00:00:00:00:00:00"


# function to update the devices table
def update_devices():
    # scan the network for active hosts using nmap ping scan
    nm.scan(hosts=NETWORK, arguments="-sn --privileged")

    # iterate through each host found by nmap
    for host in nm.all_hosts():
        # get the MAC address
        mac_address = nm[host]["addresses"]["mac"] if "mac" in nm[host]["addresses"] else get_self_mac()

        # check if the device is already in the devices table
        c.execute("SELECT * FROM devices WHERE mac=?", (mac_address,))
        result = c.fetchone()

        # set last state to online
        status = 1

        # get the hostname if available
        if nm[host].hostname() != "":
            hostname = nm[host].hostname()
        else:
            hostname = result[2]

        # if the device is not in the devices table, add it
        if result is None:
            c.execute("INSERT INTO devices VALUES (?, ?, ?, ?, ?, ?)",
                      (mac_address, host, hostname, timestamp, timestamp, status))
        else:
            c.execute("UPDATE devices SET ip=?, hostname=?, last_seen=?, status=? WHERE mac=?",
                      (host, hostname, timestamp, status, mac_address))

    # set device to offline if it has not been seen in the last 60 seconds
    c.execute("UPDATE devices SET status=? WHERE last_seen<?",
              (0, timestamp - 60))

    # commit changes to the database
    conn.commit()


def send_to_influx():
    # query the devices table
    c.execute("SELECT * FROM devices")
    devices = c.fetchall()

    # iterate through each device
    for device in devices:
        # create a dictionary for the influxdb point
        point = {
            "measurement": "devices",
            "tags": {
                "mac": device[0],
                "network": NETWORK
            },
            "time": device[4] * 1000000000,
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


# update the devices table
update_devices()
# send data to influxdb
send_to_influx()
# close the database connection
conn.close()
