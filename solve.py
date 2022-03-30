from paramiko import SSHClient, AutoAddPolicy, AuthenticationException, SSHException
from os import path
import json
import sys

from paramiko.pkey import PKey

def pwn_ssh(user, host, port, password, command_string, sshKeyPath=None):
    # TODO implement with pwntools
    print("Logging in with pwntools")

def para_ssh(host, port, user, password, command_string, sshKeyPath=None):
    client = SSHClient()
    client.load_system_host_keys()
    print(f"\n============= {user} =============")
    try:
        if (sshKeyPath != None):
            print("Passing ssh key...")
        else:
            print(f"Logging into {user}...")
            client.set_missing_host_key_policy(AutoAddPolicy())
            client.connect(host, port, user, password, allow_agent=False, look_for_keys=False)

            print(f"Executing {user} commands...") 
            stdin, stdout, stderr = client.exec_command(command_string)

            next_password = stdout.read().decode('utf8')
            # print(f"===== STDOUT =====\n{next_password}")
                        
            stdin.close()
            stdout.close()
            stderr.close()

            print(f"Logging out of {user}...")
            client.close()

            # Return password for the next level without newline
            return next_password[:-1]
    except Exception as e:
        print("paramiko failed")
        print(str(e))


def test_ssh_login(host, port, user, password, key=None):
    client = SSHClient()
    client.load_system_host_keys()
    try:
        client.connect(host, port, user, password, pkey=key, allow_agent=False, look_for_keys=False)
        return True
    except AuthenticationException:
        print(f"Authentication failure. Invalid password or private key. Cannot login as {user}.")
        return None
    except SSHException:
        print(f"""SSH error. Cannot connect. The connection parameters were:\n
                \thost: {host}\n
                \tport: {port}\n
                \tusername: {user}\n
                \tpassword: {password}\n
                \tprivate key (starting with): {key[0:20]}...""")
        return None

def parse_cfg(filepath):
    try:
        with open(path.abspath(filepath), 'r') as f:
            data = f.read() 
            return json.loads(data)
    except Exception as e:
        print(str(e))

def main(config_path, bandit_levels):
    next_password = "bandit0"
    for i, level in enumerate(bandit_levels[:-1]):
        cfg = parse_cfg(f"{config_path}/{level}.cfg")
        cfg = {} if cfg is None else cfg
        try:
            username = cfg["user"]
            password = next_password
            host = cfg["host"]
            port = cfg["port"]
            commands = cfg["commands"]

            command_string = "; ".join(commands)
            next_password = para_ssh(host, port, username, password, command_string)
            print(f"Password for {bandit_levels[i+1]}: {next_password}")
            if test_ssh_login(host, port, bandit_levels[i+1], next_password):
                print(f"{level} solved! The password for the {bandit_levels[i+1]} is correct!")
        except KeyError:
            print(f"Config file not found for {level}, continuing to next level.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python solve.py <max_level>")
    else:
        config_path = path.abspath("config")
        bandit_levels = [f"bandit{x}" for x in range(0,int(sys.argv[1]) + 1)]
        main(config_path, bandit_levels)

