# 🔒 JWT-CrackX: Advanced JWT Vulnerability Scanner & Exploitation Toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Version 2.0.0](https://img.shields.io/static/v1?label=version&message=2.0.0&color=green)](https://github.com/Untouchable17/JWT-CrackX/releases)


<h1 align="center">
    <a href="https://github.com/Untouchable17/JWT-CrackX">
        <img src="https://i.ibb.co/84x7NZ6w/2025-03-28-233019594.png" width="700">
    </a>
</h1>


**The Swiss Army Knife for JWT Security Testing**  
A high-performance tool for identifying and exploiting vulnerabilities in JSON Web Tokens (JWT). Designed for security professionals and developers working with JWT implementations. Now with advanced attack vectors and 3x faster brute-force
```
python3 JWT-CrackX.py -t <token> [--jwks URL] [-w wordlist.txt] [-p public.pem] [--threads 12]

# Run sample attack
python3 JWT-CrackX.py -t eyJhbGci... -w top100.txt
```
---
## 🚀 What's New in v2.0?
| **Feature**              | **v1.0**                 | **v2.0**                          |
|--------------------------|--------------------------|-----------------------------------|
| **JWKS Injection**       | ❌ Not supported          | ✅ Full implementation             |
| **Algorithm Support**    | `HS256`/`HS512` only     | + `RS256`/`ES256`/`ES512`         |
| **Brute-force Engine**   | Basic threading          | Chunked processing + Progress Bar |
| **Memory Usage**         | High (full file load)    | Optimized (generator-based)       |
| **Pre-checks**           | None                     | TOP_SECRETS validation            |
| **Error Handling**       | Basic                    | Advanced validation               |
| **Key Formats**          | PEM only	                | PEM + DER support                 |
 

## 🛠️ Core Capabilities

### 🔥 Brutal Brute-Force
- **HS256/HS512 Secret Cracking**
  - Multi-threaded architecture (8-32 threads)
  - Intelligent chunk processing (1000 secrets/chunk)
  - Built-in top-100 secrets pre-check
  - Real-time progress tracking with `tqdm`

```bash
python3 JWT-CrackX.py -t <token> -w secrets.txt --threads 16
```

## Supported Attacks
| Attack Type          | Description                              | Example Command       |
|----------------------|------------------------------------------|-----------------------|
| **Secret Brute-Force** | Dictionary attacks against HS* algorithms | `-w passwords.txt`    |
| **Algorithm Null**     | Exploit `alg:none` misconfigurations      | (automatic detection) |
| **Key Confusion**      | RSA public key as HMAC secret             | `-p public.pem`       |
| **JWKS Injection**     | Spoof JWKS endpoint for key validation    | `--jwks http://...`   |
| **Header Manipulation**| Craft malicious JWT headers               | (auto-generated)      |

## 🚨 Advanced Features

### Smart Vulnerability Detection
- **alg:none Exploitation**
  - Instant detection of unsigned tokens 
  - Automatic payload extraction 
  - Structure validation (3-part segmentation)

### Military-Grade Exploits
- **RSA-HMAC Confusion**
  - Public key reuse for signature forgery 
  - Support for PEM/DER key formats 
  - Automatic algorithm downgrade detection

```bash
python3 JWT-CrackX.py -t <token> -p public.pem
```

## ⚡ Performance Benchmarks

| Mode               | Command                      | Key Functionality          | Performance           |
|--------------------|------------------------------|---------------------------|-----------------------|
| **Analysis**       | `-t <token>`                 | Header inspection          | Instant               |
| **Brute-Force**    | `-t <token> -w wordlist`     | Secret cracking            | 58k attempts/sec      |
| **Key Confusion**  | `-t <token> -p public.pem`   | Signature forgery          | 1.2k validations/sec  |


---
<h3 style="text-align:center">Execution Modes</h3>

>  Analysis Mode (default)
```bash
python3 JWT-CrackX.py -t <token>
```
- **Features:**
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

    Telegram Group:     t.me/secdet_team
    Email:              tylerblackout17@gmail.com
