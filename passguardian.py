import string
import hashlib
import urllib.request
import getpass
import argparse
import sys

# ---------------------------------------------------------
# Block 1: Terminal UI Components
# ---------------------------------------------------------

class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def print_banner():
    print(f"{Colors.CYAN}{Colors.BOLD}")
    print("==================================================")
    print("   🔒  PassGuardian - PASSWORD SECURITY AUDITOR   ")
    print("==================================================")
    print(f"{Colors.RESET}")

def render_strength_bar(score):
    filled = "█" * (score * 2)
    empty = "░" * ((5 - score) * 2)
    percent = score * 20
    
    if score <= 1:
        color = Colors.RED
        status = "CRITICAL / WEAK"
    elif score <= 3:
        color = Colors.YELLOW
        status = "MODERATE"
    else:
        color = Colors.GREEN
        status = "STRONG"

    return f"{color}[{filled}{empty}] {percent}% ({status}){Colors.RESET}"

# ---------------------------------------------------------
# Block 2: Security & API Logic
# ---------------------------------------------------------

def load_wordlist_text(filepath):
    wordlist = []
    try:
        with open(filepath, "r") as f:
            for line in f:
                wordlist.append(line.strip().lower())
    except FileNotFoundError:
        print(f"{Colors.YELLOW}[!] Warning: '{filepath}' not found. Skipping local wordlist check.{Colors.RESET}")
    return wordlist

def check_hibp_api(password):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_password[:5]
    suffix = sha1_password[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'PassGuardian-Security-Tool'})
        with urllib.request.urlopen(req, timeout=5) as response:
            hashes = response.read().decode('utf-8').splitlines()

        for line in hashes:
            line_suffix, count = line.split(':')
            if line_suffix == suffix:
                return int(count)
        return 0
    except Exception:
        return -1


def check_password(password, clean_wordlist):
    score = 0
    feedback = []

    # 1. Length checks
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Password should be at least 8 characters.")
    
    if len(password) >= 12:
        score += 1

    # 2. Character variety checks
    if any(c in string.ascii_uppercase for c in password):
        score += 1
    else:
        feedback.append("Add at least one uppercase letter.")

    if any(c in string.digits for c in password):
        score += 1
    else:
        feedback.append("Add at least one digit.")

    if any(c in string.punctuation for c in password):
        score += 1
    else:
        feedback.append("Add at least one special character.")

    # 3. Local wordlist check
    if password.lower() in clean_wordlist:
        score = 0
        feedback.append(f"{Colors.RED}Found in local common-passwords list! Choose another.{Colors.RESET}")

    # 4. HIBP API check (k-Anonymity)
    breach_count = check_hibp_api(password)
    if breach_count > 0:
        score = 0
        feedback.append(f"{Colors.RED}CRITICAL: Found in {breach_count:,} public data breaches!{Colors.RESET}")
    elif breach_count == -1:
        feedback.append(f"{Colors.YELLOW}Note: Could not check online breach database (Offline/Timeout).{Colors.RESET}")

    return score, feedback

# ---------------------------------------------------------
# Block 3: Interactive Main Loop
# ---------------------------------------------------------

def main():
    print_banner()
    parser = argparse.ArgumentParser(
        description="PassGuardian: A CLI password auditor with local wordlist filtering and HIBP breach checking."
    )
    
    parser.add_argument(
        "-w", "--wordlist",
        type=str,
        help="Path to a custom common passwords text file (e.g., -w /path/to/wordlist.txt)",
        default=None
    )

    args = parser.parse_args()

    if args.wordlist:
        word_list = load_wordlist_text(args.wordlist)
    else:
        word_list = []
        print(f"{Colors.YELLOW}[!] No wordlist provided. Skipping local file check (Use -w/--wordlist).{Colors.RESET}")

    while True:
        try:
            password = getpass.getpass(f"\n{Colors.CYAN}Enter password to check (or 'quit' to exit): {Colors.RESET}")
        except Exception:
            password = input(f"\n{Colors.CYAN}Enter password to check (or 'quit' to exit): {Colors.RESET}")

        if password.lower() == "quit":
            print(f"{Colors.GREEN}\nGoodbye! Security audit session ended.{Colors.RESET}")
            break

        if len(password) == 0:
            print(f"{Colors.RED}[!] Password cannot be empty. Try again.{Colors.RESET}")
            continue

        print(f"{Colors.CYAN}[*] Analyzing strength and breach databases...{Colors.RESET}")
        score, feedback = check_password(password, word_list)

        print("\n" + "─" * 50)
        print(f"Rating: {render_strength_bar(score)}")
        
        if feedback:
            print(f"\n{Colors.BOLD}Security Findings & Recommendations:{Colors.RESET}")
            for item in feedback:
                print(f"  • {item}")
        else:
            print(f"\n{Colors.GREEN}[✓] Excellent password! Meets all policy parameters.{Colors.RESET}")
        print("─" * 50)

        # Audit log with password length masking
        with open("password_log.txt", "a") as log:
            log.write(f"Password: {'*' * len(password)} | Score: {score}/5\n")


if __name__ == "__main__":
    main()
