#This script blocks any ip that appears in blocked_ips.log from making any more attempts for 10 minutes

import os
import time
from datetime import datetime, timedelta
import subprocess

#log where ips that auth fail 5 or more times show up
LOG_PATH = "blocked_ips.log"
#where lock/unlock actions are logged
LOCK_LOG = "locking.log"
#txt file that has every ip that is currently blocked from sshing in 
LOCKED_LIST = "currently_locked_ips.txt"

#dictionary of ip and unblock timestamp
BLOCKED_IPS = {}
#set of ips and their timestamp used to make sure the same ip is not blocked repeatedly
SEEN_ENTRIES = set()
#inode of file being processed. Added this to try and stop error, not sure if it is still needed
CURRENT_INODE = None

#get inode of file passed in
def get_inode(filepath):
    try:
        return os.stat(filepath).st_ino
    except FileNotFoundError:
        return None

#collect ip and timestamp from line in the blocked_ips.log
def parse_log_line(line):
    parts = line.strip().split()
    if len(parts) != 2 or not parts[1].startswith("rhost="):
        return None, None, None
    timestamp_str = parts[0]
    ip = parts[1].split("=")[1]
    try:
        timestamp = datetime.fromisoformat(timestamp_str)
    except ValueError:
        return None, None, None
    entry_id = f"{timestamp_str}:{ip}"
    return timestamp, ip, entry_id

#log every unlock/lock action taken on an ip in this script
def log_action(action, ip, time_info=None):
    timestamp = datetime.now().isoformat()
    with open(LOCK_LOG, 'a') as f:
        if time_info:
            f.write(f"{timestamp} {action} rhost={ip} until {time_info}\n")
        else:
            f.write(f"{timestamp} {action} rhost={ip}\n")

#add ip to currently_locked_ips.txt with the time that it will be unlocked
def add_to_locked_list(ip, unlock_time):
    with open(LOCKED_LIST, 'a') as f:
        f.write(f"{ip} {unlock_time.isoformat()}\n")

#remove ip from currently_locked_ips when it is unlocked.
def remove_from_locked_list(ip):
    if not os.path.exists(LOCKED_LIST):
        return
    with open(LOCKED_LIST, 'r') as f:
        lines = f.readlines()
    with open(LOCKED_LIST, 'w') as f:
        for line in lines:
            if not line.startswith(ip + " "):
                f.write(line)

#use iptables command to lock an ip from sshing in
def block_ip(ip, unlock_time):
    subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '22', '-s', ip, '-j', 'DROP'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    log_action("BLOCKED", ip, unlock_time.isoformat())
    add_to_locked_list(ip, unlock_time)

#use iptables command to unlock an ip
def unblock_ip(ip):
    subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-p', 'tcp', '--dport', '22', '-s', ip, '-j', 'DROP'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    log_action("UNBLOCKED", ip)
    remove_from_locked_list(ip)
    remove_line_from_file(LOG_PATH, f"rhost={ip}")

#use to locate specific phrase in file and delete line containing phrase
def remove_line_from_file(filepath, identifier):
    if not os.path.exists(filepath):
        return
    with open(filepath, 'r') as f:
        lines = f.readlines()
    with open(filepath, 'w') as f:
        for line in lines:
            if identifier not in line:
                f.write(line)

#check for new item in blocked_ips.log, if so, save ip and timestamp, block ip for 10 minutes, unblock ip once 10
#minutes is reached, make sure to log every lock and unlock action
def monitor_log():
    global CURRENT_INODE

    while True:
        time.sleep(2)

        if not os.path.exists(LOG_PATH):
            continue
        
        #again, i dont know if it still need this, i just didnt want to break anything
        new_inode = get_inode(LOG_PATH)
        reset_file = False

        if new_inode != CURRENT_INODE:
            CURRENT_INODE = new_inode
            reset_file = True

        try:
            with open(LOG_PATH, 'r') as f:
                lines = f.readlines()
        except Exception:
            continue

        for line in lines:
            timestamp, ip, entry_id = parse_log_line(line)
            if not timestamp or not ip or not entry_id:
                continue
            if entry_id in SEEN_ENTRIES:
                continue

            SEEN_ENTRIES.add(entry_id)
            unlock_time = timestamp + timedelta(minutes=10)
            BLOCKED_IPS[ip] = unlock_time
            block_ip(ip, unlock_time)

        now = datetime.now()
        to_unblock = [ip for ip, unlock_time in BLOCKED_IPS.items() if now >= unlock_time]
        for ip in to_unblock:
            unblock_ip(ip)
            del BLOCKED_IPS[ip]

if __name__ == "__main__":
    try:
        monitor_log()
    except KeyboardInterrupt:
        pass

