# 🔒 JWT-CrackX: Advanced JWT Vulnerability Scanner & Exploitation Toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Version 1.0.0](https://img.shields.io/static/v1?label=version&message=1.0.0&color=green)](https://github.com/Untouchable17/JWT-CrackX/releases)


<h1 align="center">
    <a href="https://github.com/Untouchable17/JWT-CrackX">
        <img src="https://i.ibb.co/LhJTnLnR/jwt-racke.png" width="700">
    </a>
</h1>


**The Swiss Army Knife for JWT Security Testing**  
A high-performance tool for identifying and exploiting vulnerabilities in JSON Web Tokens (JWT). Designed for security professionals and developers working with JWT implementations
```
python3 JWT-CrackX.py [-h] -t TOKEN [-w WORDLIST] [-p PUBKEY]
```
---
## Supported Attacks
<table><thead><tr><th>Attack Type</th><th>Description</th><th>Example Command</th></tr></thead><tbody><tr><td><strong>Secret Brute-Force</strong></td><td>Dictionary attacks against HS* algorithms</td><td><code>-w passwords.txt</code></td></tr><tr><td><strong>Algorithm Null</strong></td><td>Exploit <code>alg:none</code> misconfigurations</td><td>(automatic detection)</td></tr><tr><td><strong>Key Confusion</strong></td><td>RSA public key as HMAC secret</td><td><code>-p public.pem</code></td></tr><tr><td><strong>Header Injection</strong></td><td>Craft malicious JWT headers</td><td>(beta)</td></tr></tbody></table>

---
### 🛠️ Core Capabilities
- **Brute-Force Secrets**  
  - HS256/HS512 secret cracking with intelligent wordlist processing
  - Multi-threaded architecture for high-speed attacks
  - Smart progress tracking with dynamic status updates

### 🚨 Vulnerability Detection
- **`alg:none` Exploitation**  
  - Automatic detection of unsigned token acceptance
  - Payload extraction without secret validation

### 🔑 Advanced Attacks
- **RSA-HMAC Confusion**  
  - Public key reuse for signature forgery
  - Support for PEM/DER key formats
  - Automatic algorithm downgrade detection

### Key Features Table
<table><thead><tr><th><strong>Mode</strong></th><th><strong>Command</strong></th><th><strong>Key Functionality</strong></th><th><strong>Performance</strong></th></tr></thead><tbody><tr><td><strong>Analysis</strong></td><td><code>-t &lt;token&gt;</code></td><td>Header inspection, payload decoding</td><td>Instant (single-threaded)</td></tr><tr><td><strong>Brute-Force</strong></td><td><code>-t &lt;token&gt; -w &lt;wordlist&gt;</code></td><td>Secret cracking, multi-threaded</td><td>~15,000 attempts/sec</td></tr><tr><td><strong>Key Confusion</strong></td><td><code>-t &lt;token&gt; -p &lt;public_key&gt;</code></td><td>RSA-HMAC confusion, signature forgery</td><td>~1,000 validations/sec</td></tr></tbody></table>

---
<h3 style="text-align:center">Execution Modes</h3>

>  Analysis Mode (default)
```bash
python3 JWT-CrackX.py -t <token>
```
- **Header Inspection**
   - Parses JWT header for algorithm, key ID (kid), and other parameters.
   - Validates token structure (3-part segmentation).
- **Algorithm Validation**
   - Checks for insecure algorithms (none, weak RSA keys).
   - Detects unsupported or deprecated algorithms.
- **Basic Payload Decoding**
   - Decodes payload without signature verification.
   - Displays standard claims (iss, sub, exp, etc.).

> Brute-Force Mode
```bash
python3 JWT-CrackX.py -t <token> -w ./wordlists/secrets.txt --threads 12
```
- **Performance**
   - Throughput: ~15,000 attempts/sec (on i7-11800H)
   - Multi-threaded execution (default: 8 threads, configurable via --threads)

> Key Confusion Mode
```bash
python3 JWT-CrackX.py -t <token> -p ./keys/public.pem
```
- **Supported Key Formats**
   - PEM (PKCS#1, PKCS#8)
   - DER (automatically converted to PEM)
- **Tested Algorithms**
   - HS256, HS384, HS512
   - Automatic algorithm detection based on key size
- **Attack Mechanism**
   - Uses public RSA key as HMAC secret
   - Validates token signature with forged key

## 📦 Installation

```bash
# Clone repository
git clone https://github.com/Untouchable17/JWT-CrackX.git
cd JWT-CrackX

# Install dependencies
pip install -r requirements.txt
```

<h2 align="center">Contact Developer</h2>

    Telegram:           @secdet17
    Group:              t.me/secdet_team
    Email:              tylerblackout17@gmail.com
