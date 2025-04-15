#completely wipes all data in auth_fail.log, blocked_user.log, and blocked_ips.log every 10 minutes.

#Did this to make these files neat, but also so that ips/users can be reblocked every 10 minutes
#if the attack persists.

import os
import time

#where auth fails are stores
AUTH_FAIL_LOG = "auth_fail.log"
#where users who fail password 5 times will be logged
BLOCKED_USERS_LOG = "blocked_users.log"
#where ips that fail ssh password 5 times will be logged
BLOCKED_IPS_LOG = "blocked_ips.log"

def clear_file(file_path):
    #clears file
    with open(file_path, 'w') as f:
        f.truncate(0)

def monitor_and_clear():
    #uses clear file function to clear files every 10 minutes
    while True:
        time.sleep(600)  #600 seconds = 10 minutes

        #clear the logs
        clear_file(AUTH_FAIL_LOG)
        clear_file(BLOCKED_USERS_LOG)
        clear_file(BLOCKED_IPS_LOG)

if __name__ == "__main__":
    try:
        monitor_and_clear()
    except KeyboardInterrupt:
        pass

