#!/usr/bin/env python3
"""
Password Strength Analyzer
Evaluates password strength, complexity, and suggests stronger alternatives.
"""

import re
import math
import string
import secrets
import hashlib
import json
import os
from pathlib import Path


# ─────────────────────────────────────────────
#  STRENGTH ANALYSIS
# ─────────────────────────────────────────────

def calculate_entropy(password: str) -> float:
    """Calculate Shannon entropy of a password."""
    charset_size = 0
    if re.search(r'[a-z]', password): charset_size += 26
    if re.search(r'[A-Z]', password): charset_size += 26
    if re.search(r'\d', password):    charset_size += 10
    if re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?`~]', password): charset_size += 32
    if charset_size == 0: charset_size = 1
    return len(password) * math.log2(charset_size)


def check_common_patterns(password: str) -> list[str]:
    """Detect common weak patterns."""
    issues = []
    lower = password.lower()

    common_passwords = [
        "password", "123456", "qwerty", "abc123", "letmein",
        "monkey", "dragon", "master", "sunshine", "princess",
        "welcome", "shadow", "superman", "iloveyou", "admin",
        "login", "pass", "test", "hello", "charlie"
    ]
    if lower in common_passwords:
        issues.append("This is one of the most commonly used passwords.")

    if re.match(r'^(.)\1+$', password):
        issues.append("All characters are identical (e.g., 'aaaa').")

    if re.search(r'(012|123|234|345|456|567|678|789|890|987|876|765|654|543|432|321|210)', password):
        issues.append("Contains sequential numbers (e.g., '123').")

    if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', lower):
        issues.append("Contains sequential letters (e.g., 'abc').")

    keyboard_walks = ['qwerty', 'asdf', 'zxcv', 'qazwsx', 'qweasd', '1qaz', '2wsx']
    for walk in keyboard_walks:
        if walk in lower:
            issues.append(f"Contains keyboard walk pattern ('{walk}').")
            break

    return issues


def analyze_password(password: str) -> dict:
    """Full analysis of a password."""
    result = {
        "password": password,
        "length": len(password),
        "entropy": round(calculate_entropy(password), 2),
        "checks": {},
        "issues": [],
        "score": 0,
        "strength": "",
        "color": "",
        "suggestions": []
    }

    # Character class checks
    checks = {
        "has_lowercase":  bool(re.search(r'[a-z]', password)),
        "has_uppercase":  bool(re.search(r'[A-Z]', password)),
        "has_digit":      bool(re.search(r'\d', password)),
        "has_special":    bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?`~]', password)),
        "length_ok":      len(password) >= 8,
        "length_good":    len(password) >= 12,
        "length_great":   len(password) >= 16,
    }
    result["checks"] = checks

    # Score (0–100)
    score = 0
    if checks["length_ok"]:    score += 10
    if checks["length_good"]:  score += 15
    if checks["length_great"]: score += 15
    if checks["has_lowercase"]: score += 10
    if checks["has_uppercase"]: score += 10
    if checks["has_digit"]:     score += 10
    if checks["has_special"]:   score += 15
    entropy = result["entropy"]
    if entropy >= 28:  score += 5
    if entropy >= 36:  score += 5
    if entropy >= 50:  score += 5

    # Deduct for patterns
    patterns = check_common_patterns(password)
    result["issues"] = patterns
    score -= len(patterns) * 20
    score = max(0, min(100, score))
    result["score"] = score

    # Strength label
    if score < 20:
        result["strength"] = "Very Weak"
        result["color"] = "red"
    elif score < 40:
        result["strength"] = "Weak"
        result["color"] = "orange"
    elif score < 60:
        result["strength"] = "Fair"
        result["color"] = "yellow"
    elif score < 80:
        result["strength"] = "Strong"
        result["color"] = "blue"
    else:
        result["strength"] = "Very Strong"
        result["color"] = "green"

    # Suggestions
    suggestions = []
    if not checks["length_good"]:
        suggestions.append("Use at least 12 characters.")
    if not checks["has_uppercase"]:
        suggestions.append("Add uppercase letters (A–Z).")
    if not checks["has_digit"]:
        suggestions.append("Include numbers (0–9).")
    if not checks["has_special"]:
        suggestions.append("Add special characters (!@#$%^&*).")
    if patterns:
        suggestions.append("Avoid predictable patterns and common words.")
    result["suggestions"] = suggestions

    return result


# ─────────────────────────────────────────────
#  PASSWORD GENERATOR
# ─────────────────────────────────────────────

def generate_strong_password(length: int = 16, use_symbols: bool = True) -> str:
    """Generate a cryptographically strong random password."""
    chars = string.ascii_letters + string.digits
    if use_symbols:
        chars += "!@#$%^&*()-_=+[]{}|;:,.<>?"
    while True:
        pwd = ''.join(secrets.choice(chars) for _ in range(length))
        analysis = analyze_password(pwd)
        if analysis["score"] >= 80:
            return pwd


def generate_passphrase(num_words: int = 4) -> str:
    """Generate a memorable passphrase."""
    word_list = [
        "apple", "bridge", "castle", "dragon", "ember", "falcon",
        "galaxy", "harbor", "island", "jungle", "knight", "lantern",
        "mirror", "nebula", "ocean", "puzzle", "quantum", "river",
        "silver", "tiger", "umbrella", "violet", "winter", "xenon",
        "yellow", "zenith", "anchor", "breeze", "cloud", "dagger",
        "engine", "forest", "glider", "hammer", "iron", "jade",
        "kestrel", "laser", "marble", "neon", "orbit", "phoenix",
        "quartz", "rocket", "storm", "thunder", "ultra", "vapor",
    ]
    words = [secrets.choice(word_list).capitalize() for _ in range(num_words)]
    separator = secrets.choice(['!', '@', '#', '$', '-', '_', '.'])
    number = str(secrets.randbelow(90) + 10)
    return separator.join(words) + number


# ─────────────────────────────────────────────
#  PASSWORD HISTORY (optional DB via JSON file)
# ─────────────────────────────────────────────

HISTORY_FILE = Path("password_history.json")


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def load_history() -> list[str]:
    if HISTORY_FILE.exists():
        with open(HISTORY_FILE) as f:
            return json.load(f)
    return []


def save_history(history: list[str]) -> None:
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)


def check_reuse(password: str) -> bool:
    """Return True if password was used before."""
    h = hash_password(password)
    return h in load_history()


def record_password(password: str) -> None:
    """Store hashed password in history."""
    history = load_history()
    h = hash_password(password)
    if h not in history:
        history.append(h)
        save_history(history)


# ─────────────────────────────────────────────
#  CLI INTERFACE
# ─────────────────────────────────────────────

COLORS = {
    "red":    "\033[91m",
    "orange": "\033[93m",
    "yellow": "\033[33m",
    "blue":   "\033[94m",
    "green":  "\033[92m",
    "reset":  "\033[0m",
    "bold":   "\033[1m",
    "dim":    "\033[2m",
    "cyan":   "\033[96m",
}


def colored(text: str, color: str) -> str:
    return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"


def print_bar(score: int, color: str, width: int = 40) -> None:
    filled = int(score / 100 * width)
    bar = "█" * filled + "░" * (width - filled)
    print(f"  [{colored(bar, color)}] {colored(str(score) + '%', color)}")


def print_analysis(result: dict, check_history: bool = False) -> None:
    print()
    print(colored("━" * 52, "cyan"))
    print(colored("  PASSWORD STRENGTH ANALYZER", "bold"))
    print(colored("━" * 52, "cyan"))

    strength = result["strength"]
    color = result["color"]
    print(f"\n  Strength : {colored(strength, color)} {colored('●', color)}")
    print(f"  Entropy  : {result['entropy']} bits")
    print(f"  Length   : {result['length']} characters\n")
    print_bar(result["score"], color)

    print(f"\n  {colored('Character Classes:', 'bold')}")
    checks = result["checks"]
    markers = {True: colored("✔", "green"), False: colored("✘", "red")}
    print(f"    {markers[checks['has_lowercase']]}  Lowercase letters")
    print(f"    {markers[checks['has_uppercase']]}  Uppercase letters")
    print(f"    {markers[checks['has_digit']]}  Numbers")
    print(f"    {markers[checks['has_special']]}  Special characters")
    print(f"    {markers[checks['length_ok']]}  Minimum length (8+)")
    print(f"    {markers[checks['length_good']]}  Recommended length (12+)")

    if result["issues"]:
        print(f"\n  {colored('⚠  Issues Detected:', 'orange')}")
        for issue in result["issues"]:
            print(f"    • {colored(issue, 'orange')}")

    if check_history and check_reuse(result["password"]):
        print(f"\n  {colored('⚠  This password has been used before!', 'red')}")

    if result["suggestions"]:
        print(f"\n  {colored('💡 Suggestions:', 'cyan')}")
        for s in result["suggestions"]:
            print(f"    • {s}")

    print(colored("\n━" * 52, "cyan"))


def cli_main():
    import getpass

    print(colored("\n  🔐 Password Strength Analyzer", "bold"))
    print(colored("  ─────────────────────────────", "dim"))
    print("  Options:")
    print("  [1] Analyze a password")
    print("  [2] Generate a strong password")
    print("  [3] Generate a passphrase")
    print("  [4] Quit")

    while True:
        print()
        choice = input("  Enter choice (1-4): ").strip()

        if choice == "1":
            pwd = getpass.getpass("  Enter password (hidden): ")
            if not pwd:
                print(colored("  No password entered.", "red"))
                continue
            result = analyze_password(pwd)
            print_analysis(result, check_history=True)
            record_password(pwd)

        elif choice == "2":
            try:
                length = int(input("  Password length [default 16]: ").strip() or "16")
            except ValueError:
                length = 16
            use_sym = input("  Include symbols? (y/n) [y]: ").strip().lower() != "n"
            pwd = generate_strong_password(length, use_sym)
            print(f"\n  {colored('Generated password:', 'green')}")
            print(f"  {colored(pwd, 'bold')}")
            result = analyze_password(pwd)
            print_analysis(result)

        elif choice == "3":
            pwd = generate_passphrase()
            print(f"\n  {colored('Generated passphrase:', 'green')}")
            print(f"  {colored(pwd, 'bold')}")
            result = analyze_password(pwd)
            print_analysis(result)

        elif choice == "4":
            print(colored("\n  Goodbye! Stay secure. 🔒\n", "cyan"))
            break
        else:
            print(colored("  Invalid choice. Please enter 1–4.", "red"))


if __name__ == "__main__":
    cli_main()
