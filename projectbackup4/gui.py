#this is the user interface for the app. Shows all ips and user who are currently blocked. Currently blocked ips and user can be 
#immediately unlocked using the buttons. Also shows the last 20 items in locking.log so that system admin can check for suspicious 
#activity. System admin can choose to reblock ip or user permanently (for 100 years).

import tkinter as tk
from tkinter import ttk
from datetime import datetime
from datetime import timedelta
import subprocess
import os

#txt file of user who are locked out
USERS_FILE = "currently_locked_users.txt"
#txt files of ips prevented from sshing in
IPS_FILE = "currently_locked_ips.txt"
#log of lock/unlock actions
LOCKING_LOG = "locking.log"
#how often the script refreshes. (refreshes every second so that timers countdown properly)
REFRESH_INTERVAL = 1  # seconds
#how many lines of the locking.log are shown
MAX_LOG_LINES = 20

#app class
class LockMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Lock Monitor")

        self.setup_tables()
        self.user_data = {}
        self.ip_data = {}
        self.last_log_lines = []

        self.setup_log_view()

        self.update_loop()

    def setup_tables(self):
        #currently disabled user accounts
        user_frame = ttk.LabelFrame(self.root, text="Deactivated Accounts")
        user_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        self.user_container = tk.Frame(user_frame)
        self.user_container.pack(fill="both", expand=True)
        
        #disabled user accounts columns (User, Countdown, Action).
        ttk.Label(self.user_container, text="User", width=20).grid(row=0, column=0)
        ttk.Label(self.user_container, text="Countdown", width=20).grid(row=0, column=1)
        ttk.Label(self.user_container, text="Action", width=10).grid(row=0, column=2)
        
        
        
        
        
        
        #currently disabled ips
        ip_frame = ttk.LabelFrame(self.root, text="Blocked IPs")
        ip_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

        self.ip_container = tk.Frame(ip_frame)
        self.ip_container.pack(fill="both", expand=True)
        
        #disabled ips columsn (IP, Countdown, Action)
        ttk.Label(self.ip_container, text="IP", width=20).grid(row=0, column=0)
        ttk.Label(self.ip_container, text="Countdown", width=20).grid(row=0, column=1)
        ttk.Label(self.ip_container, text="Action", width=10).grid(row=0, column=2)

    #create the list of log entries in locking.log
    def setup_log_view(self):
        log_frame = ttk.LabelFrame(self.root, text="Recent Log Activity")
        log_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

        self.log_container = tk.Frame(log_frame)
        self.log_container.pack(fill="both", expand=True)

    #update the data
    def update_loop(self):
        self.update_users()
        self.update_ips()
        self.update_log()
        self.root.after(REFRESH_INTERVAL * 1000, self.update_loop)
    
    #checks currentlly_locked_users.txt to make sure user data is up to date
    def update_users(self):
        current_entries = {}
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE) as f:
                for line in f:
                    try:
                        user, ts = line.strip().split()
                        unlock_time = datetime.fromisoformat(ts)
                        current_entries[user] = unlock_time
                    except:
                        continue

        for user in list(self.user_data.keys()):
            if user not in current_entries:
                self.remove_user_row(user)

        for user, unlock_time in current_entries.items():
            if user not in self.user_data:
                self.add_user_row(user, unlock_time)
            else:
                self.update_user_countdown(user, unlock_time)
                
                
    #checks currently_locked_ips.txt to make sure disabled ips data is still up to date
    def update_ips(self):
        current_entries = {}
        if os.path.exists(IPS_FILE):
            with open(IPS_FILE) as f:
                for line in f:
                    try:
                        ip, ts = line.strip().split()
                        unlock_time = datetime.fromisoformat(ts)
                        current_entries[ip] = unlock_time
                    except:
                        continue

        for ip in list(self.ip_data.keys()):
            if ip not in current_entries:
                self.remove_ip_row(ip)

        for ip, unlock_time in current_entries.items():
            if ip not in self.ip_data:
                self.add_ip_row(ip, unlock_time)
            else:
                self.update_ip_countdown(ip, unlock_time)
                
    #adds a new row in disabled users table when a new user appears in currently_locked_users.txt
    def add_user_row(self, user, unlock_time):
        row = len(self.user_data) + 1
        label = ttk.Label(self.user_container, text=user, width=20)
        countdown = ttk.Label(self.user_container, text="", width=20)
        button = ttk.Button(self.user_container, text="Unlock", width=10, command=lambda: self.unlock_user(user))

        label.grid(row=row, column=0)
        countdown.grid(row=row, column=1)
        button.grid(row=row, column=2)

        self.user_data[user] = (unlock_time, (label, countdown, button))
        self.update_user_countdown(user, unlock_time)

    #updates the countdown to unlock time for disabled users. subtracts current time from unlock time to calculate this.
    def update_user_countdown(self, user, unlock_time):
        now = datetime.now()
        remaining = unlock_time - now
        display = str(remaining).split('.')[0] if remaining.total_seconds() > 0 else "00:00:00"
        self.user_data[user][1][1].config(text=display)

    #removes a user from the disabled users table (called when account is unlocked).
    def remove_user_row(self, user):
        _, widgets = self.user_data.pop(user)
        for widget in widgets:
            widget.destroy()

    #adds a row to disabled ips table with ip and countdown to unlock time.
    def add_ip_row(self, ip, unlock_time):
        row = len(self.ip_data) + 1
        label = ttk.Label(self.ip_container, text=ip, width=20)
        countdown = ttk.Label(self.ip_container, text="", width=20)
        button = ttk.Button(self.ip_container, text="Unblock", width=10, command=lambda: self.unblock_ip(ip))

        label.grid(row=row, column=0)
        countdown.grid(row=row, column=1)
        button.grid(row=row, column=2)

        self.ip_data[ip] = (unlock_time, (label, countdown, button))
        self.update_ip_countdown(ip, unlock_time)

    #updates countdown to when ip will be unlocked (calculated by subtracting current time from unlock time)
    def update_ip_countdown(self, ip, unlock_time):
        now = datetime.now()
        remaining = unlock_time - now
        display = str(remaining).split('.')[0] if remaining.total_seconds() > 0 else "00:00:00"
        self.ip_data[ip][1][1].config(text=display)

    #removes an ip from the disabled ips table (called when ip is unlocked).
    def remove_ip_row(self, ip):
        _, widgets = self.ip_data.pop(ip)
        for widget in widgets:
            widget.destroy()
    
    #unlock user using usermod command (called with unlock button)
    def unlock_user(self, user):
        subprocess.run(["sudo", "usermod", "-U", user], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.remove_line_from_file(USERS_FILE, user)
        self.remove_line_from_file("blocked_users.log", f"user={user}")
        timestamp = datetime.now().isoformat()
        with open(LOCKING_LOG, "a") as log_file:
            log_file.write(f"{timestamp} UNLOCKED user={user}\n")
        self.remove_user_row(user)

    #unblock ip using iptables commadn (called with unblock button)
    def unblock_ip(self, ip):
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-p", "tcp", "--dport", "22", "-s", ip, "-j", "DROP"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.remove_line_from_file(IPS_FILE, ip)
        self.remove_line_from_file("blocked_ips.log", f"rhost={ip}")
        timestamp = datetime.now().isoformat()
        with open(LOCKING_LOG, "a") as log_file:
            log_file.write(f"{timestamp} UNBLOCKED rhost={ip}\n")
        self.remove_ip_row(ip)

    #used to remove a line containing an identifier phrase from a file (used often to remove lines from currently_blocked txt files
    #after user or ip is unblocked).
    def remove_line_from_file(self, filepath, identifier):
        if not os.path.exists(filepath):
            return
        with open(filepath, 'r') as f:
            lines = f.readlines()
        with open(filepath, 'w') as f:
            for line in lines:
                if not line.startswith(identifier + " "):
                    f.write(line)
    
    #updates the display for locking.log in gui and also adds buttons to block an account or ip that was unlocked (can be used
    #by system admin to block any user or ip they view as suspicious).
    def update_log(self):
        if not os.path.exists(LOCKING_LOG):
            return

        with open(LOCKING_LOG, 'r') as f:
            lines = f.readlines()[-MAX_LOG_LINES:]

        #only updates if there is a change to locking.log (had to add this because otherwise, the log display flickered after constanly
        #updating).
        if lines == self.last_log_lines:
            return  # No change, skip redraw
        self.last_log_lines = lines  # Update cache

        for widget in self.log_container.winfo_children():
            widget.destroy()

        for idx, line in enumerate(lines):
            line = line.strip()
            label = ttk.Label(self.log_container, text=line, anchor="w")
            label.grid(row=idx, column=0, sticky="w")

            if "UNBLOCKED rhost=" in line:
                ip = line.split("rhost=")[-1]
                btn = ttk.Button(self.log_container, text="Block Again", width=12, command=lambda ip=ip: self.block_ip(ip))
                btn.grid(row=idx, column=1, padx=5)
            elif "UNLOCKED user=" in line:
                user = line.split("user=")[-1]
                btn = ttk.Button(self.log_container, text="Lock Again", width=12, command=lambda user=user: self.lock_user(user))
                btn.grid(row=idx, column=1, padx=5)

    
    
    #block ip from sshing using iptables (called with block again button)
    #blocks ip for 100 years
    def block_ip(self, ip):
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-s", ip, "-j", "DROP"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        now = datetime.now()
        future_time = now.replace(microsecond=0) + timedelta(days=365*100)
        now_str = now.isoformat()
        future_str = future_time.isoformat()

        with open(LOCKING_LOG, "a") as f:
            f.write(f"{now_str} BLOCKED rhost={ip} until {future_str}\n")

        self.update_or_add_entry(IPS_FILE, ip, future_str)

    #lock a user and prevent them from signing in with usermod (called with lock again button)
    #locks out user for 100 years
    def lock_user(self, user):
        subprocess.run(["sudo", "usermod", "-L", user], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        now = datetime.now()
        future_time = now.replace(microsecond=0) + timedelta(days=365*100)
        now_str = now.isoformat()
        future_str = future_time.isoformat()

        with open(LOCKING_LOG, "a") as f:
            f.write(f"{now_str} LOCKED user={user} until {future_str}\n")

        self.update_or_add_entry(USERS_FILE, user, future_str)
    
    #this function will either add a new line to the file given or will update a line that contains the identifier phrase
    #this is used to update the currently_blocked_ips.txt file and currently_blocked_users.txt file. I didnt want the same
    #user or ip to show up so it replaces lines that have the same ip or user.
    def update_or_add_entry(self, filepath, identifier, timestamp):
        lines = []
        found = False

        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                for line in f:
                    if line.strip().startswith(identifier + " "):
                        found = True
                        continue
                    lines.append(line)

        lines.append(f"{identifier} {timestamp}\n")

        with open(filepath, 'w') as f:
            f.writelines(lines)


if __name__ == "__main__":
    root = tk.Tk()
    app = LockMonitorApp(root)
    root.mainloop()

