from paramiko import SSHClient, AutoAddPolicy, AuthenticationException, SSHException, Channel
import socket
from os import path
import json
import sys
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
            session.close()

            # Return password for the next level without newline
            return next_password[:-1]
    except SSHException as e:
        print(str(e))
        return ""

def test_pwn_login(user, host, password, key=None, port=22):
    try:
        if (key):
            session = ssh(user, host, port, keyfile=key, ignore_config=True)
        else:
            session = ssh(user, host, port, password=password, ignore_config=True)
        status = session.connected()        
        session.close()
        return status
    except Exception as e:
        # TODO add exception handling
        print("pwntools test login failed: ", e)

def test_para_login(host, port, user, password, key=None):
    try:
        client = SSHClient()
        client.load_system_host_keys()
        client.connect(host, port, user, password, pkey=key, allow_agent=False, look_for_keys=False)
        return True
    except AuthenticationException:
        print(f"Authentication failure. Invalid password or private key. Cannot login as {user}.")
        return False
    except SSHException:
        print(f"""SSH error. Cannot connect. The connection parameters were:
        host: {host}
        port: {port}
        username: {user}
        password: {password}
        private key {key}""")
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
        if ssh_impl == "pwn":
            next_password = pwn_ssh(cfg["user"], cfg["host"], password, cfg["commands"], port=cfg["port"])
            test_passed = test_pwn_login(next_level_name, cfg["host"], next_password, port=cfg["port"])
        else: # use paramikio ssh implementation
            next_password = para_ssh(cfg["host"], cfg["port"], cfg["user"], password, cfg["commands"])
            test_passed = test_para_login(cfg["host"], cfg["port"], next_level_name, next_password)
            
        return (test_passed, next_password)
    except KeyError:
        print(f"Config file not found for {level_name}, continuing to next level.")
        return (False, "")
        # TODO handle exception and propogate message to use cfg['pass'] for next level pass

def solve_levels(config_root, min_level, max_level, ssh_impl):
    # TODO handle failed cfg read
    # TODO implement retry count
    # TODO track login/solve status for each level
    level_statuses = []
    ssh_impl = ssh_impl.lower()
    cfg = parse_cfg(f"{config_root}/bandit{min_level}.json")
    if cfg == None:
        print(f"Could not parse {config_root}/bandit{min_level}.json")
        print("Exiting...")
        return level_statuses

    # Validate login of min_level with password from config
    next_password = cfg["pass"]
    success, next_password = solve_level(cfg, min_level, next_password, ssh_impl)
    level_statuses.append((success, next_password))
    if not success:
        print(f"Failed to login to bandit{min_level+1} with the provided password: {next_password}")
        return level_statuses 
    else:
        print(f"bandit{min_level} solved! The password for bandit{min_level+1} is correct!")
        print(f"Password for bandit{min_level+1}: {next_password}")
        
        # Validate subsequent levels
        for i in range(min_level + 1, max_level + 1):
            cfg_path = f"{config_root}/bandit{i}.json"
            cfg = parse_cfg(cfg_path)
            if cfg is None:
                print(f"Failed to load {cfg_path}. Exiting...")
                return level_statuses
            try:
                status = (success, next_password) = solve_level(cfg, i, next_password, ssh_impl)
                if success:
                    print(f"bandit{i} solved! The password for bandit{i+1} is correct!")
                    print(f"Password for bandit{i+1}: {next_password}")
                    level_statuses.append(status)
                else:
                    print(f"Failed to solve bandit{i} with the given commands.")
                    level_statuses.append(status)
                    return level_statuses
            except Exception as e:
                print(e)

if __name__ == "__main__":
    if len(sys.argv) == 2:
        min_level = int(sys.argv[1])
        max_level = int(sys.argv[1])
    elif len(sys.argv) == 3 or len(sys.argv) == 4:
        min_level = int(sys.argv[1])
        max_level = int(sys.argv[2])
    else:
        print("Usage: python solve.py <min_level> <max_level> [pwn | para]")
        sys.exit(1)

    # Default to pwntools ssh implementation
    config_path = path.abspath("config")
    ssh_impl = sys.argv[3] if len(sys.argv) > 3 else "para" 
    if ssh_impl != "pwn" and ssh_impl != "para":
        print("The ssh implementation (second argument) must be either \"pwn\" or \"para\".")
        exit(1)
    solve_levels(config_path, min_level, max_level, ssh_impl)
