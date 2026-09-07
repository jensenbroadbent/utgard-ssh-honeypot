# UtgardAI: 3-Tier Active Defense SSH Honeypot

## Overview
UtgardAI is an SSH honeypot designed to detect command evasion, maintain stateful shell interaction, and capture malware payloads. It addresses common limitations in standard static honeypots, including subshell obfuscation, stateless file systems, and uncaptured download payloads.

## Architecture
Incoming SSH session commands process through a 3-tier pipeline:

1. Tier 1: Command Normalization and Subshell Parsing
Processes input using tokenization to resolve nested subshell execution before rule evaluation.

2. Tier 2: Stateful Virtual Filesystem (VFS)
Maintains directory state across directory navigation and file creation commands. Returns responses for common reconnaissance binaries and decoy files.

3. Tier 3: LLM Fallback Engine
Handles unlisted commands via a constrained local Llama 3.2 instance via Ollama to generate raw terminal output.

4. Payload Capture and Quarantine
Intercepts file transfer commands, saves external payloads into an isolated quarantine directory, and logs SHA-256 hashes.

5. Tarpitting and Strike System
Tracks suspicious command execution per source IP. Applies a time delay when risk thresholds are met before severing the session.

## Repository Structure
```
UtgardAI/
├── UtgardAI.py
├── Dockerfile
├── utgard_rsa.key
├── logs/
└── quarantine/
```

## Log Schema
Logs are formatted in ECS-compliant JSON.

```json
{
  "@timestamp": "2026-07-31T18:13:00.124Z",
  "event": {
    "kind": "event",
    "category": ["intrusion_detection"],
    "type": ["info"],
    "module": "utgard_honeypot"
  },
  "session": {
    "id": "a1b2c3d4"
  },
  "source": {
    "ip": "192.168.1.50"
  },
  "process": {
    "command_line": "$(echo ca)t /etc/passwd",
    "execution_tier": "TIER2_VFS"
  },
  "utgard": {
    "output_response": "root:x:0:0:root:/root:/bin/bash",
    "risk_category": "HIGH"
  }
}
```

## Setup and Execution

### Docker Deployment
1. Build the image:
   `docker build -t utgard-ai .`

2. Run the container:
   `docker run -d -p 2222:2222 --name utgard-honeypot utgard-ai`

### Direct Execution
1. Install dependencies:
   `pip install paramiko ollama requests`

2. Pull the model:
   `ollama pull llama3.2`

3. Start the script:
   `python UtgardAI.py`

## Verification
Connect locally on port 2222:
`ssh user@127.0.0.1 -p 2222`

Test cases:
* Subshell evaluation: `$(echo ca)t /etc/passwd`
* VFS file state: `cd /tmp && touch test.txt && ls -la`
* Payload intercept: `wget http://example.com/test.sh`

## Author
Jensen Broadbent
