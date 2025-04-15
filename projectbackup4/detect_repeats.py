#this script looks through auth_fail.log. If same ip or same user shows up 5 or more times, they are
#logged in either blocked_users.log or blocked_ips.log.

import time
import os
from datetime import datetime

#log with authentication fails. this is the file being scanned for repeat users or ips.
AUTH_FAIL_LOG = "auth_fail.log"
#ips that show up 5 or more times in auth_fails.log are logged here.
BLOCKED_IPS_LOG = "blocked_ips.log"
#users that show up 5 or more times in auth_fails.log are logged here.
BLOCKED_USERS_LOG = "blocked_users.log"

#this function collects all the ips or users who already appear in either blocked_users.log or 
#blocked_ips.log
def load_blocked(file_path, entity_type):
    blocked = set()
    if not os.path.exists(file_path):
        return blocked

    with open(file_path, 'r') as f:
        for line in f:
            if entity_type + "=" in line:
                parts = line.strip().split()
                for part in parts:
                    if part.startswith(f"{entity_type}="):
                        value = part.split("=", 1)[1]
                        blocked.add(value)
    return blocked

#this function adds user or ip to their associated blocked log
def save_blocked(file_path, entity_type, entity_value):
    timestamp = datetime.now().isoformat()
    with open(file_path, 'a') as f:
        f.write(f"{timestamp} {entity_type}={entity_value}\n")

#this function checks for 5 or more repeats in auth_fail.log
def monitor_log():
    while True:
        user_counts = {}
        ip_counts = {}

        #figure out which ips and users are already logged
        blocked_users = load_blocked(BLOCKED_USERS_LOG, "user")
        blocked_ips = load_blocked(BLOCKED_IPS_LOG, "rhost")

        #scan through auth_fail.log
        if os.path.exists(AUTH_FAIL_LOG):
            with open(AUTH_FAIL_LOG, 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if not parts:
                        continue
                    for part in parts:
                        if part.startswith("user="):
                            user = part.split("=", 1)[1]
                            user_counts[user] = user_counts.get(user, 0) + 1
                        elif part.startswith("rhost="):
                            ip = part.split("=", 1)[1]
                            ip_counts[ip] = ip_counts.get(ip, 0) + 1

        #save user in blocked_users.log if they appear in auth_fail.log 5 or more times
        #and if not logged already.
        for user, count in user_counts.items():
            if count >= 5 and user not in blocked_users:
                save_blocked(BLOCKED_USERS_LOG, "user", user)

        #save ip in blocked_ips.log if they appear in auth_fail.log 5 or more times
        #and if not logged already.
        for ip, count in ip_counts.items():
            if count >= 5 and ip not in blocked_ips:
                save_blocked(BLOCKED_IPS_LOG, "rhost", ip)

        time.sleep(2)

if __name__ == "__main__":
    try:
        monitor_log()
    except KeyboardInterrupt:
        pass

