# OverTheWire Bandit Solver

A Python program that issues commands over SSH to complete the [OverTheWire](https://overthewire.org/wargames/) Bandit wargame. A JSON file is used for each level to specify the commands required to complete the level and retrieve the password/key for the subsequent level.

## Install Dependencies
```console
$ pip install -r requirements.txt
```

## Usage
- The program can be run using either [`pwntools`](https://github.com/Gallopsled/pwntools) or [`paramiko`](https://github.com/paramiko/paramiko) to establish SSH connections using the optional CLI parameters `pwn` or `para`. Pwntools is the default.
```console
$ python3 solve.py
Usage: python solve.py <start_level> <end_level> [pwn | para]
```

Supply only the `start_level` to solve a single level.
```console
$ python3 solve.py 5

============= bandit5 =============
Logging into bandit5...
Executing bandit5 commands...
Logging out of bandit5...
bandit5 solved! The password for bandit6 is correct!
Password for bandit6: [REDACTED]
```
Or provide a range with `start_level` and `end_level`.
```console
$ python3 solve.py 0 2

============= bandit0 =============
Logging into bandit0...
Executing bandit0 commands...
Password for bandit1: [REDACTED] 
bandit0 solved! The password for the bandit1 is correct!

============= bandit1 =============
Logging into bandit1...
Executing bandit1 commands...
Password for bandit2: [REDACTED]
bandit1 solved! The password for the bandit2 is correct!
```
