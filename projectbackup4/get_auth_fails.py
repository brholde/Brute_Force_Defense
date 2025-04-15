#this script takes all the pam_unix authentication failures that occur in auth.log
#and organizes them into a file called auth_fail.log

import subprocess

#auth.log
AUTH_LOG_PATH = "/var/log/auth.log"
#auth_fail.log (where all authentication failures are stored/organized into).
FAIL_LOG_PATH = "auth_fail.log"

def monitor_auth_log():
    #views the last few items of auth.log with tail command
    process = subprocess.Popen(
        ['tail', '-F', AUTH_LOG_PATH],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )

    with open(FAIL_LOG_PATH, 'a') as fail_log:
        while True:
            line = process.stdout.readline()
            if not line:
                continue

            #check if line contains "authenticatin failure"
            if "authentication failure;" in line:
                #get timestamp (first word in line)
                parts = line.split()
                timestamp = parts[0]

                #get the rhost (ip of "attacker")
                rhost = None
                user = None
                for part in line.split():
                    if part.startswith("rhost="):
                        rhost = part.split("=")[1]
                    elif part.startswith("user="):
                        user = part.split("=")[1]

                #collect data into string to log in auth_fail.log
                if rhost:
                    log_entry = f"{timestamp} rhost={rhost}\n"
                elif user:
                    log_entry = f"{timestamp} user={user}\n"
                else:
                    continue

                #log auth fail in auth_fail.log
                fail_log.write(log_entry)
                fail_log.flush()

if __name__ == "__main__":
    try:
        monitor_auth_log()
    except KeyboardInterrupt:
        pass

