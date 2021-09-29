from paramiko import SSHClient, AutoAddPolicy
from os import path
import json

def pwn_ssh(user, host, port, password, command_string, sshKeyPath = None):
    # TODO implement with pwntools
    print("Logging in with pwntools")

def para_ssh(user, host, port, password, command_string, sshKeyPath = None):
    c = SSHClient()
    c.load_system_host_keys()
    print(f"\n============= {user} =============")
    try:
        if (sshKeyPath != None):
            print("Passing ssh key...")
        else:
            print(f"Logging into {user}...")
            c.set_missing_host_key_policy(AutoAddPolicy())
            c.connect(host, port, user, password, allow_agent=False, look_for_keys=False)

            print(f"Executing {user} commands...") 
            stdin, stdout, stderr = c.exec_command(command_string)

            next_password = stdout.read().decode('utf8')
            print(f"===== STDOUT =====\n{next_password}")
                        
            stdin.close()
            stdout.close()
            stderr.close()

            print(f"Logging out of {user}...")
            c.close()

            # Return password for the next level without newline
            return next_password[0:32]
    except Exception as e:
        print("paramiko failed")
        print(str(e))


def parse_cfg(filepath):
    try:
        with open(path.abspath(filepath), 'r') as f:
            data = f.read() 
            return json.loads(data)
    except Exception as e:
        print(str(e))


if __name__ == "__main__":
    config_path = path.abspath("config")
    banditLevels = [f"bandit{x}" for x in range(0,6)]

    next_password = "bandit0"
    for level in banditLevels:
        cfg = parse_cfg(f"{config_path}/{level}.cfg")
        username = cfg["user"]
        # password = cfg["pass"]
        password = next_password
        host = cfg["host"]
        port = cfg["port"]
        commands = cfg["commands"]

        command_string = "; ".join(commands)

        next_password = para_ssh(username, host, port, password, command_string)
