import os
import sys
import json
import uuid
import time
import socket
import threading
from datetime import datetime, timezone
import paramiko
import ollama
import hashlib
import urllib.request
import time
import os
from collections import defaultdict
import shlex
import re

IP_STRIKES = defaultdict(int)

# Generate persistent RSA host key for Paramiko SSH Server
HOST_KEY_FILE = "utgard_rsa.key"
if not os.path.exists(HOST_KEY_FILE):
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(HOST_KEY_FILE)

HOST_KEY = paramiko.RSAKey(filename=HOST_KEY_FILE)

# -------------------------------------------------------------------
# 1. DYNAMIC SYSTEM HYDRATION & OVERRIDES (Restored from Old Version)
# -------------------------------------------------------------------
def load_system_binaries():
    """Dynamically populates the binary whitelist from PATH or fallback list."""
    bin_dirs = ["/bin", "/usr/bin", "/sbin", "/usr/sbin", "/usr/local/bin"]
    binaries = set()
    
    found_local = False
    for d in bin_dirs:
        if os.path.exists(d):
            found_local = True
            try:
                binaries.update(os.listdir(d))
            except PermissionError:
                continue

    if found_local and binaries:
        return binaries

    return {
        "alias", "apt", "apt-get", "awk", "base64", "basename", "bash", "cat", 
        "cc", "cd", "chgrp", "chmod", "chown", "chroot", "clear", "cmp", "comm", 
        "cp", "cron", "curl", "cut", "date", "dd", "diff", "dir", "dirname", 
        "dmesg", "du", "echo", "egrep", "env", "exit", "expr", "false", "fdisk", 
        "fgrep", "file", "find", "free", "fg", "bg", "gcc", "gdb", "getent", 
        "git", "grep", "groupadd", "head", "history", "host", "hostname", "id", 
        "ifconfig", "ip", "iptables", "jobs", "kill", "killall", "less", "ln", 
        "locate", "login", "ls", "lsblk", "lscpu", "lsusb", "lsof", "make", 
        "man", "md5sum", "mkdir", "mkfifo", "mknod", "more", "mount", "mv", 
        "nc", "netstat", "nice", "nohup", "nslookup", "od", "passwd", "paste", 
        "pathchk", "ping", "pkill", "ps", "ptx", "pwd", "python", "python3", 
        "read", "readlink", "realpath", "rm", "rmdir", "route", "rsync", "sed", 
        "seq", "service", "sh", "sleep", "sort", "split", "ss", "ssh", "stat", 
        "su", "sudo", "systemctl", "tail", "tar", "tee", "test", "time", "top", 
        "touch", "tr", "true", "tms", "umount", "uname", "uncompress", "uniq", 
        "uptime", "useradd", "userdel", "usermod", "vi", "vim", "w", "watch", 
        "wc", "wget", "whereis", "which", "who", "whoami", "xargs", "yes", "zcat", "eval"
    }

COMMON_BINARIES = load_system_binaries()

RECON_OVERRIDES = {
    "whoami": "user",
    "id": "uid=1000(user) gid=1000(user) groups=1000(user),27(sudo),100(users)",
    "hostname": "ubuntu-srv",
    "uname -a": "Linux ubuntu-srv 5.15.0-88-generic #98-Ubuntu SMP Mon Oct 2 15:18:56 UTC 2023 x86_64 GNU/Linux",
    "who": "user     pts/0        2026-07-31 17:00 (10.0.2.15)",
    "who am i": "user     pts/0        2026-07-31 17:00 (10.0.2.15)",
    "w": " 17:00:00 up 1 day,  2:14,  1 user,  load average: 0.08, 0.03, 0.01\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\nuser     pts/0    10.0.2.15        17:00    0.00s  0.02s  0.00s w"
}

def capture_payload(url, session_id):
    quarantine_dir = "quarantine"
    os.makedirs(quarantine_dir, exist_ok=True)
    try:
        parsed_name = url.split("/")[-1].split("?")[0]
        filename = parsed_name if parsed_name else "payload.bin"
        filepath = os.path.join(quarantine_dir, f"{session_id}_{filename}")
        
        urllib.request.urlretrieve(url, filepath)
        
        with open(filepath, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
            
        return filepath, file_hash
    except Exception as e:
        return None, str(e)

def evaluate_network_defense(client_ip, risk_flag):
    if risk_flag == "HIGH":
        IP_STRIKES[client_ip] += 1
    
    if IP_STRIKES[client_ip] > 3:
        time.sleep(5.0)  # Tarpit: 5-second delay
    
    if IP_STRIKES[client_ip] > 6:
        return False
    return True
def normalize_bash_input(raw_command):
    """
    Safely normalizes and tokenizes bash input to handle subshells, 
    variable concatenations, and escapes without executing them.
    """
    raw_command = raw_command.replace('\xa0', ' ').strip()
    
    # If the user glues a subshell like $(echo ca)t, replace the subshell 
    # placeholder with its conceptual evaluated form or strip the wrapper 
    # while keeping the attached characters intact for the VFS.
    # For $(echo ca)t -> cat
    resolved_cmd = re.sub(r'\$\(echo\s+([a-zA-Z0-9_-]+)\)', r'\1', raw_command)
    
    try:
        tokens = shlex.split(resolved_cmd)
    except ValueError as e:
        return {"error": f"syntax error: {e}", "executable": None, "args": []}

    if not tokens:
        fallback_tokens = shlex.split(raw_command)
        executable = fallback_tokens[0] if fallback_tokens else ""
        return {"executable": executable, "args": fallback_tokens[1:], "raw_tokens": fallback_tokens}

    executable = tokens[0]
    args = tokens[1:]

    return {
        "executable": executable,
        "args": args,
        "raw_tokens": tokens
    }
# -------------------------------------------------------------------
# 2. STRUCTURED SIEM LOGGING SYSTEM (ECS / Splunk Ready)
# -------------------------------------------------------------------
class SIEMLogger:
    def __init__(self, log_dir="logs"):
        os.makedirs(log_dir, exist_ok=True)
        self.log_file = os.path.join(log_dir, f"utgard_events_{datetime.now(timezone.utc).strftime('%Y%m%d')}.json")

    def log(self, session_id, client_ip, command, execution_tier, output, latency_ms, risk_flag="LOW"):
        event = {
            "@timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "event": {
                "kind": "event",
                "category": ["intrusion_detection"],
                "type": ["info"],
                "module": "utgard_honeypot",
                "duration_ms": round(latency_ms, 2)
            },
            "session": {"id": session_id},
            "source": {"ip": client_ip},
            "process": {
                "command_line": command,
                "execution_tier": execution_tier
            },
            "utgard": {
                "output_response": output.strip(),
                "risk_category": risk_flag
            }
        }
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")

logger = SIEMLogger()

# -------------------------------------------------------------------
# 3. DYNAMIC STATEFUL VIRTUAL FILESYSTEM (VFS)
# -------------------------------------------------------------------
class VirtualFS:
    def __init__(self):
        self.fs = {
            "/": {"type": "dir", "owner": "root", "perm": "drwxr-xr-x", "children": ["bin", "etc", "home", "tmp", "var"]},
            "/bin": {"type": "dir", "owner": "root", "perm": "drwxr-xr-x", "children": []},
            "/etc": {"type": "dir", "owner": "root", "perm": "drwxr-xr-x", "children": ["passwd", "shadow", "hostname"]},
            "/etc/passwd": {"type": "file", "owner": "root", "perm": "-rw-r--r--", "content": "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000:user:/home/user:/bin/bash"},
            "/etc/shadow": {"type": "file", "owner": "root", "perm": "-r--------", "content": "root:$6$vU7x$fakehash123:19000:0:99999:7:::\nuser:$6$qP9z$fakehash456:19000:0:99999:7:::"},
            "/etc/hostname": {"type": "file", "owner": "root", "perm": "-rw-r--r--", "content": "ubuntu-srv"},
            "/home": {"type": "dir", "owner": "root", "perm": "drwxr-xr-x", "children": ["user"]},
            "/home/user": {"type": "dir", "owner": "user", "perm": "drwxr-x---", "children": [".bashrc", ".profile", "notes.txt"]},
            "/home/user/.bashrc": {"type": "file", "owner": "user", "perm": "-rw-r--r--", "content": "# ~/.bashrc"},
            "/home/user/.profile": {"type": "file", "owner": "user", "perm": "-rw-r--r--", "content": "# ~/.profile"},
            "/home/user/notes.txt": {"type": "file", "owner": "user", "perm": "-rw-r--r--", "content": "TODO: Rotate AWS API key AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE"},
            "/tmp": {"type": "dir", "owner": "root", "perm": "drwxrwxrwt", "children": []},
            "/var": {"type": "dir", "owner": "root", "perm": "drwxr-xr-x", "children": ["log"]},
            "/var/log": {"type": "dir", "owner": "root", "perm": "drwxr-xr-x", "children": ["auth.log", "syslog"]}
        }
        self.current_dir = "/home/user"

    def resolve_path(self, path):
        if path.startswith("~"):
            path = path.replace("~", "/home/user", 1)
        if path.startswith("/"):
            return os.path.normpath(path).replace('\\', '/')
        return os.path.normpath(os.path.join(self.current_dir, path)).replace('\\', '/')
    
    def cd(self, path):
        target = self.resolve_path(path)
        if target in self.fs and self.fs[target]["type"] == "dir":
            self.current_dir = target
            return ""
        return f"-bash: cd: {path}: No such file or directory"

    def ls(self, path=""):
        target = self.resolve_path(path) if path else self.current_dir
        if target not in self.fs:
            return f"ls: cannot access '{path}': No such file or directory"
        if self.fs[target]["type"] == "file":
            return target.split("/")[-1]
        
        entries = self.fs[target]["children"]
        output = []
        for entry in sorted(entries):
            full_path = os.path.normpath(os.path.join(target, entry))
            meta = self.fs.get(full_path, {"perm": "-rw-r--r--", "owner": "user"})
            output.append(f"{meta['perm']} 1 {meta['owner']} {meta['owner']} 4096 Jul 31 17:00 {entry}")
        return "\n".join(output) if output else "total 0"

    def touch(self, path):
        target = self.resolve_path(path)
        parent = os.path.dirname(target)
        filename = os.path.basename(target)
        if parent in self.fs and self.fs[parent]["type"] == "dir":
            if filename not in self.fs[parent]["children"]:
                self.fs[parent]["children"].append(filename)
            self.fs[target] = {"type": "file", "owner": "user", "perm": "-rw-r--r--", "content": ""}
            return ""
        return f"touch: cannot touch '{path}': No such file or directory"

    def cat(self, path):
        target = self.resolve_path(path)
        if target in self.fs:
            if self.fs[target]["type"] == "dir":
                return f"cat: {path}: Is a directory"
            return self.fs[target]["content"]
        return f"cat: {path}: No such file or directory"

    def snapshot(self):
        summary = ["Current Virtual Filesystem State:"]
        for p, data in self.fs.items():
            if data["type"] == "file" and not p.startswith("/etc"):
                summary.append(f"File: {p} | Content: {data['content'][:100]}")
        return "\n".join(summary)

# -------------------------------------------------------------------
# 4. UTGARD ENGINE PIPELINE
# -------------------------------------------------------------------
class UtgardEngine:
    def __init__(self):
        self.vfs = VirtualFS()

    def clean_and_verify(self, raw_output, first_token):
        """Restored AI Sanitization Regex Filter"""
        text = raw_output.replace("```", "").strip()
        conversational_pattern = r'\b(I am|as an AI|here is|sorry|cannot|help you|understand)\b'
        if re.search(conversational_pattern, text, re.IGNORECASE):
            return f"-bash: {first_token}: command not found"
        return text

    def process_command(self, user_input, session_id, client_ip):
        start_time = time.time()
        cmd = user_input.strip()

        if not cmd:
            return "", "TIER0_EMPTY"

        parsed = normalize_bash_input(cmd)
        if "error" in parsed and parsed["error"]:
            out = f"-bash: {parsed['error']}"
            logger.log(session_id, client_ip, cmd, "TIER1_SYNTAX_ERROR", out, (time.time() - start_time)*1000, "LOW")
            return out, "TIER1"

        first_token = parsed["executable"]
        tokens = [first_token] + parsed["args"]

        if cmd.startswith("wget ") or cmd.startswith("curl "):
            parts = cmd.split()
            if len(parts) > 1:
                target_url = parts[1]
                filepath, file_hash = capture_payload(target_url, session_id)
                out = f"--2026-07-31 17:00:00--  {target_url}\nResolving host...\nConnecting...\nHTTP request sent, awaiting response... 200 OK\nSaved to: {filepath} [Hash: {file_hash}]"
                logger.log(session_id, client_ip, cmd, "FORENSIC_CAPTURE", out, (time.time() - start_time)*1000, "HIGH")
                return out, "TIER2_PAYLOAD"

        risk = "HIGH" if any(x in cmd for x in ["/etc/shadow", "AWS_", "curl", "wget", "nc", "sudo"]) else "LOW"

        # TIER 1: Binary Whitelist Check (Dynamic Hydration)
        if not (first_token.startswith("./") or first_token.startswith("/") or first_token in COMMON_BINARIES):
            out = f"-bash: {first_token}: command not found"
            logger.log(session_id, client_ip, cmd, "TIER1_FAIL_FAST", out, (time.time() - start_time)*1000, risk)
            return out, "TIER1"

        # TIER 2: Static Overrides & Native Filesystem (Merged)
        if cmd in RECON_OVERRIDES:
            out = RECON_OVERRIDES[cmd]
            logger.log(session_id, client_ip, cmd, "TIER2_OVERRIDE", out, (time.time() - start_time)*1000, risk)
            return out, "TIER2"

        # TIER 2.1: Robust catch for invalid 'who' variants
        if first_token == "who" and cmd not in RECON_OVERRIDES:
            out = ""
            logger.log(session_id, client_ip, cmd, "TIER2_OVERRIDE", out, (time.time() - start_time)*1000, risk)
            return out, "TIER2"

        # TIER 2.2: VFS Commands
        if cmd == "pwd":
            out = self.vfs.current_dir
            logger.log(session_id, client_ip, cmd, "TIER2_VFS", out, (time.time() - start_time)*1000, risk)
            return out, "TIER2"

        if cmd.startswith("cd"):
            target = tokens[1] if len(tokens) > 1 else "~"
            out = self.vfs.cd(target)
            logger.log(session_id, client_ip, cmd, "TIER2_VFS", out, (time.time() - start_time)*1000, risk)
            return out, "TIER2"

        if first_token == "ls":
            target = tokens[-1] if len(tokens) > 1 and not tokens[-1].startswith("-") else ""
            out = self.vfs.ls(target)
            logger.log(session_id, client_ip, cmd, "TIER2_VFS", out, (time.time() - start_time)*1000, risk)
            return out, "TIER2"

        if first_token == "cat":
            target = tokens[1] if len(tokens) > 1 else ""
            out = self.vfs.cat(target)
            logger.log(session_id, client_ip, cmd, "TIER2_VFS", out, (time.time() - start_time)*1000, risk)
            return out, "TIER2"

        if first_token == "touch" and len(tokens) > 1:
            out = self.vfs.touch(tokens[1])
            logger.log(session_id, client_ip, cmd, "TIER2_VFS", out, (time.time() - start_time)*1000, risk)
            return out, "TIER2"

        # TIER 3: LLM Dynamic Fallback Execution
        system_prompt = (
            "You are an exact bash terminal on Ubuntu 22.04 LTS.\n"
            f"Current working directory: {self.vfs.current_dir}\n"
            f"{self.vfs.snapshot()}\n"
            "Rules:\n"
            "1. Output raw stdout/stderr ONLY.\n"
            "2. Never use markdown standard fences.\n"
            "3. Never explain or act as an assistant."
        )

        try:
            response = ollama.chat(
                model="llama3.2",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": cmd}
                ],
                options={"temperature": 0.0}
            )
            raw_output = response["message"]["content"]
            final_output = self.clean_and_verify(raw_output, first_token)

            logger.log(session_id, client_ip, cmd, "TIER3_LLM", final_output, (time.time() - start_time)*1000, risk)
            return final_output, "TIER3"
        except Exception as e:
            err = f"-bash: {first_token}: Input/output error"
            logger.log(session_id, client_ip, cmd, "TIER3_LLM_ERROR", str(e), (time.time() - start_time)*1000, "HIGH")
            return err, "TIER3"
# -------------------------------------------------------------------
# 5. NETWORK LAYER: PARAMIKO SSH DAEMON
# -------------------------------------------------------------------
class HoneypotSSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        logger.log("AUTH_ATTEMPT", self.client_ip, f"USER:{username} PASS:{password}", "AUTH", "GRANTED", 0, "MEDIUM")
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_pty_request(self, channel, term, modes, height, width, pixelwidth, pixelheight):
        return True

    def check_channel_shell_request(self, channel):
        return True

def handle_connection(client_sock, client_addr):
    session_id = str(uuid.uuid4())[:8]
    client_ip = client_addr[0]
    transport = paramiko.Transport(client_sock)
    
    try:
        transport.add_server_key(HOST_KEY)
        server = HoneypotSSHServer(client_ip)
        transport.start_server(server=server)
        
        chan = transport.accept(20)
        if chan is None:
            return

        engine = UtgardEngine()
        chan.send(b"Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)\r\n\r\n")

        while True:
            prompt_dir = "~" if engine.vfs.current_dir == "/home/user" else engine.vfs.current_dir
            prompt = f"user@ubuntu-srv:{prompt_dir}$ "
            chan.send(prompt.encode('utf-8'))

            buffer = ""
            while not buffer.endswith("\r") and not buffer.endswith("\n"):
                char = chan.recv(1).decode('utf-8', errors='ignore')
                if not char:
                    break
                chan.send(char.encode('utf-8'))
                buffer += char

            cmd = buffer.strip()
            chan.send(b"\r\n")

            if cmd.lower() in ["exit", "quit"]:
                chan.send(b"logout\r\n")
                break

            if cmd:
                risk_flag = "HIGH" if any(x in cmd for x in ["/etc/shadow", "AWS_", "curl", "wget", "nc", "sudo"]) else "LOW"
                keep_alive = evaluate_network_defense(client_ip, risk_flag)
                
                if not keep_alive:
                    chan.send(b"\r\nConnection reset by peer.\r\n")
                    chan.close()
                    return

                output, _ = engine.process_command(cmd, session_id, client_ip)
                if output:
                    formatted_out = output.replace("\r\n", "\n").replace("\n", "\r\n") + "\r\n"
                    chan.send(formatted_out.encode('utf-8'))

    except (socket.error, paramiko.SSHException, ConnectionResetError):
        pass
    except Exception as e:
        print(f"[*] Connection exception: {e}")
    finally:
        transport.close()

def start_ssh_server(host="0.0.0.0", port=2222):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(100)
    print(f"[*] UtgardAI SSH Honeypot listening on {host}:{port}...")

    while True:
        client_sock, client_addr = server_socket.accept()
        t = threading.Thread(target=handle_connection, args=(client_sock, client_addr))
        t.daemon = True
        t.start()

if __name__ == "__main__":
    start_ssh_server()
