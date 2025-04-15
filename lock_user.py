import os
import time
from datetime import datetime, timedelta
import subprocess

#where users who have failed password 5 times will show up
LOG_PATH = "blocked_users.log"
#log containing every lock and unlock action
LOCK_LOG = "locking.log"
#txt file with each line representing a user currently locked out with a timestamp of when they will
#be unlocked.
LOCKED_LIST = "currently_locked_users.txt"

#dictionary with user and unlock timestamp
LOCKED_USERS = {}
#a set that stores the user and timestamp that we have already read in from block_users.log
SEEN_ENTRIES = set()
#inode of the file being processed.
CURRENT_INODE = None

#returns the inode of the given file
#Added this because i was having weird errors when file was being cleared. Probably not the best
#solution, but it stopped error from happening.
def get_inode(filepath):
    try:
        return os.stat(filepath).st_ino
    except FileNotFoundError:
        return None

#breaks down line from log into a timestamp and username value so that they can be processed
def parse_log_line(line):
    parts = line.strip().split()
    if len(parts) != 2 or not parts[1].startswith("user="):
        return None, None, None
    timestamp_str = parts[0]
    username = parts[1].split("=")[1]
    try:
        timestamp = datetime.fromisoformat(timestamp_str)
    except ValueError:
        return None, None, None
    entry_id = f"{timestamp_str}:{username}"
    return timestamp, username, entry_id

#log unlock or lock action into locking.log
def log_action(action, username, time_info=None):
    timestamp = datetime.now().isoformat()
    with open(LOCK_LOG, 'a') as f:
        if time_info:
            f.write(f"{timestamp} {action} user={username} until {time_info}\n")
        else:
            f.write(f"{timestamp} {action} user={username}\n")

#add user to currently_locked_users.txt with the timestamp of when they will be unlocked.
def add_to_locked_list(username, unlock_time):
    with open(LOCKED_LIST, 'a') as f:
        f.write(f"{username} {unlock_time.isoformat()}\n")

#remove the user from currently_locked_users.txt and blocked_user.log (so that they can be readded
#if more password fails happen).
def remove_from_locked_list(username):
    #remove from currently_locked_users.txt
    if os.path.exists(LOCKED_LIST):
        with open(LOCKED_LIST, 'r') as f:
            lines = f.readlines()
        with open(LOCKED_LIST, 'w') as f:
            for line in lines:
                if not line.startswith(username + " "):
                    f.write(line)

    #remove from blocked_users.log
    blocked_log = "blocked_users.log"
    if os.path.exists(blocked_log):
        with open(blocked_log, 'r') as f:
            lines = f.readlines()
        with open(blocked_log, 'w') as f:
            for line in lines:
                if f"user={username}" not in line:
                    f.write(line)

#lock user from signing in with usermod command
def lock_user(username, unlock_time):
    subprocess.run(['sudo', 'usermod', '-L', username], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    log_action("LOCKED", username, unlock_time.isoformat())
    add_to_locked_list(username, unlock_time)

#allow user to be able to sign in with usermod command
def unlock_user(username):
    subprocess.run(['sudo', 'usermod', '-U', username], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    log_action("UNLOCKED", username)
    remove_from_locked_list(username)

#basically main function. get user that shows up in blocked_user.log, make a timestamp for 10 minutes
#from now, log information, unlock users who reach their unlock timestamp.
def monitor_log():
    global CURRENT_INODE

    while True:
        time.sleep(2)

        if not os.path.exists(LOG_PATH):
            continue
        
        #inode checks to stop error from file being cleared.
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
            timestamp, username, entry_id = parse_log_line(line)
            if not timestamp or not username or not entry_id:
                continue
            if entry_id in SEEN_ENTRIES:
                continue

            SEEN_ENTRIES.add(entry_id)
            unlock_time = timestamp + timedelta(minutes=10)
            LOCKED_USERS[username] = unlock_time
            lock_user(username, unlock_time)

        now = datetime.now()
        to_unlock = [user for user, unlock_time in LOCKED_USERS.items() if now >= unlock_time]
        for user in to_unlock:
            unlock_user(user)
            del LOCKED_USERS[user]

if __name__ == "__main__":
    try:
        monitor_log()
    except KeyboardInterrupt:
        pass

