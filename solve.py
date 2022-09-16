import argparse
import socket
import json
import sys
from os import path
from time import sleep
from paramiko import SSHClient, AutoAddPolicy, AuthenticationException, SSHException, Channel
from pwn import ssh, context
context.log_level = 'WARNING'


# TODO: implement interface for pwn and paramiko ssh for easier implementation 
def pwn_ssh(user, host, password, commands, port=22, sshKeyPath=None):
    print(f"\n============= {user} =============")
    try:
        print(f"Logging into {user}...")
        if (sshKeyPath):
            session = ssh(user, host, port, keyfile=sshKeyPath, ignore_config=True)
        else:
            session = ssh(user, host, int(port), password=password, ignore_config=True)

        print(f"Executing {user} commands...")
        for c in commands:
            print (f"COMMAND: {c}")
            results = session.run_to_end(c)
        next_password = results[0].decode('utf8')

        session.close()
        return next_password[:-1]
    except Exception as e:
        # TODO add exception handling
        print("pwntools failed: ", e)

def para_ssh(host, port, user, password, commands, sshKeyPath=None):
    session = SSHClient()
    session.load_system_host_keys()
    next_password = " "
    print(f"\n============= {user} =============")
    try:
        if (sshKeyPath != None):
            # TODO pass ssh key
            print("Passing ssh key...")
        else:
            print(f"Logging into {user}...")
            session.set_missing_host_key_policy(AutoAddPolicy())
            session.connect(host, port, user, password, allow_agent=False, look_for_keys=False)

            print(f"Executing {user} commands...") 
            for c in commands:
                # TODO: check for ssh keyword command to initiate another ssh connection via paramiko
                #channel = session.invoke_shell()
                print (f"COMMAND: {c}")
                stdin, stdout, stderr = session.exec_command(c)
                #stdin, stdout, stderr = channel.exec_command(c)
                # if channel:
                    # stdin, stdout, stderr = client_channel.exec_command(c)
                # else:
                    # print("Channel is borked")
                #stdout.channel.recv_exit_status() # wait for each command to complete

            next_password = stdout.read().decode('utf8')
            # print(f"===== STDOUT =====\n{next_password}")
                        
            stdin.close()
            stdout.close()
            stderr.close()

            print(f"Logging out of {user}...")

            # Return password for the next level without newline
            return next_password[:-1]
    except SSHException as e:
        print(str(e))
    finally:
        session.close()
        return next_password[:-1]

def test_pwn_login(user, host, password, key=None, port=22):
    try:
        if (key):
            session = ssh(user, host, port, keyfile=key, ignore_config=True)
        else:
            session = ssh(user, host, port, password=password, ignore_config=True)
        status = session.connected()        

        print(f"Logging out of {user}...")
        session.close()

        return status
    except Exception as e:
        # TODO add exception handling
        print("pwntools test login failed: ", e)

def test_para_login(host, port, user, password, key=None):
    try:
        print(f"Testing {user} with password: {password}")

        session = SSHClient()
        session.load_system_host_keys()
        session.connect(host, port, user, password, pkey=key, allow_agent=False, look_for_keys=False)

        print(f"Logging out of {user}...")
        session.close()

        return True
    except AuthenticationException:
        print(f"Authentication failure. Invalid password or private key. Cannot login as {user}.")
        return False
    except SSHException as e:
        print(f"SSH error. Cannot connect. The connection parameters were:")
        print(f"\thost: {host}")
        print(f"\tport: {port}")
        print(f"\tusername: {user}")
        print(f"\tpassword: {password}")
        print(f"\tprivate key {key}")
        print(f"\tSSHException: {e}")
        return False

def parse_cfg(filepath):
    try:
        with open(path.abspath(filepath), 'r') as f:
            data = f.read() 
            return json.loads(data)
    except Exception as e:
        print(str(e))

def solve_level(cfg, level, password, ssh_impl):
    # TODO add type hints
    level_name = f"bandit{level}"
    next_level_name = f"bandit{level+1}"
    try:
        if ssh_impl == "pwn": # use pwntools ssh implementation
            next_password = pwn_ssh(cfg["user"], cfg["host"], password, cfg["commands"], port=cfg["port"])
            test_passed = test_pwn_login(next_level_name, cfg["host"], next_password, port=cfg["port"])
        elif ssh_impl == "para": # use paramikio ssh implementation
            next_password = para_ssh(cfg["host"], cfg["port"], cfg["user"], password, cfg["commands"])
            test_passed = test_para_login(cfg["host"], cfg["port"], next_level_name, next_password)
        else: # default to paramikio ssh implementation
            next_password = para_ssh(cfg["host"], cfg["port"], cfg["user"], password, cfg["commands"])
            test_passed = test_para_login(cfg["host"], cfg["port"], next_level_name, next_password)
            
        return (test_passed, next_password)
    except KeyError:
        print(f"Config file not found for {level_name}, continuing to next level.")
        return (False, "")

def solve_level_range(config_root, min_level, max_level, ssh_impl):
    # TODO handle failed cfg read
    # TODO implement retry count
    if max_level is None:
        max_level = min_level
    level_statuses = []
    ssh_impl = ssh_impl.lower()
    success = False
    next_password = None
    for i in range(min_level, max_level + 1):
        cfg_path = f"{config_root}/bandit{i}.json"
        cfg = parse_cfg(cfg_path)
        if cfg is None:
            continue

        if not success or next_password is None: # failed to solve previous level, so use password from cfg
            next_password = cfg["pass"]

        status = None
        try:
            (success, next_password) = solve_level(cfg, i, next_password, ssh_impl)
            status = (i, success, next_password)  
            if success:
                print(f"bandit{i} solved! The password for bandit{i+1} is correct!")
            else:
                print(f"Failed to solve bandit{i}.")
        except Exception as e:
            print(e)
        finally:
            level_statuses.append(status)
            sleep(1) # throttle to reduce server load

    return level_statuses

if __name__ == "__main__":
    MAX_BANDIT_LEVEL = 33
    parser = argparse.ArgumentParser(description="Solved specified OverTheWire Bandit levels.")
    parser.add_argument('min_level', type=int,
        help="Minimum Bandit level to solve")
    parser.add_argument('max_level', type=int, nargs="?", default=None,
        help="Maximum Bandit level to solve")
    parser.add_argument('-s, --ssh', dest="ssh", nargs="?", default="para", choices=["para", "pwn"],
        help="Specify which SSH implementation to use. (para = Paramiko, pwn = PwnTools)")
    parser.add_argument('-v', '--verbose', action="count", default=0,
        help="increase verbosity")
    parser.add_argument('-c', '--config', action="count",
        help="Directory containing JSON config files for each level")
    args = parser.parse_args()

    # TODO: more comprehensive SSH error handling check paramiko and pwn docs

    # TODO: verbose output option
    # if True:
    #     def vprint(*args, **kwargs):
    #         print(*args, **kwargs)
    # else:
    #     vprint = lambda *a, **k: None

    # Default to pwntools ssh implementation
    config_path = path.abspath("config")
    solve_statuses = solve_level_range(config_path, args.min_level, args.max_level, args.ssh)
    for x in [x[:-1] for x in solve_statuses]:
        print(x)
