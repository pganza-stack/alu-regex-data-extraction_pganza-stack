"""
ALU Regex Onboarding Assignment - Data Extraction & Secure Validation
Author: Ganza Prince

WHAT THIS SCRIPT DOES
----------------------
Reads a raw text file (as if it came back from an external API), and:
  1. Extracts four required data types using regex:
       - Email addresses (general) + 3 ALU-specific email sub-types
       - Credit card numbers
       - URLs
       - Phone numbers
  2. Validates that extracted data is well-formed (e.g. Luhn check for cards).
  3. Defends against unsafe/malicious input instead of blindly trusting the text
     (script injection, SQL injection payloads, path traversal, template
     injection, spoofed/lookalike domains).
  4. Masks sensitive data (credit card numbers, emails) before it is ever
     printed or written to a log/output file, so raw sensitive values never
     leak into logs.
  5. Writes a structured JSON summary + prints a readable console summary.

No UI/form is required per the assignment - everything is regex + validation
logic run from the command line.
"""

import re
import json
import os


# ---------------------------------------------------------------------------
# SECTION 1: REGEX PATTERNS (each pattern has a comment explaining it)
# ---------------------------------------------------------------------------

# General email pattern.
# local-part: letters, digits, ., _, %, +, - (common real-world characters)
# domain: letters/digits/hyphens, at least one dot, 2+ letter TLD
EMAIL_PATTERN = re.compile(
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
)

# ALU-SPECIFIC EMAIL SUB-TYPES
# These are checked AFTER a string already matches EMAIL_PATTERN, using
# re.search with a "domain must end exactly here" anchor ($) so that a
# spoofed domain like "alueducation.com.evil.net" or "fake-alueducation.com"
# does NOT slip through as a legitimate ALU address.
ALU_OFFICIAL_PATTERN = re.compile(r"@alueducation\.com$", re.IGNORECASE)
ALU_ALUMNI_PATTERN = re.compile(r"@alumni\.alueducation\.com$", re.IGNORECASE)
ALU_SI_PATTERN = re.compile(r"@si\.alueducation\.com$", re.IGNORECASE)

# Credit card numbers.
# Real cards are 13-19 digits, often written with spaces or dashes every
# 4 digits. We capture the "loose" shape here, then verify each candidate
# with the Luhn checksum algorithm afterward (regex alone can't validate a
# checksum, only shape).
CREDIT_CARD_PATTERN = re.compile(
    r"\b(?:\d[ -]?){13,19}\b"
)

# URLs (http/https, optional www, path/query string).
# We deliberately require a scheme (http:// or https://) OR a leading "www."
# so we don't accidentally match plain domain-looking text out of context.
URL_PATTERN = re.compile(
    r"\b(?:https?://|www\.)[A-Za-z0-9.-]+(?:\.[A-Za-z]{2,})(?:[/?#][^\s'\"<>]*)?",
    re.IGNORECASE,
)

# Phone numbers.
# Supports optional country code (+250, +256, etc.), and common separators
# (spaces, dashes, parentheses) between groups of digits. Requires 7-13
# digits total so it doesn't grab random long digit strings.
PHONE_PATTERN = re.compile(
    r"(?:\+?\d{1,3}[-.\s]?)?(?:\(\d{2,4}\)[-.\s]?)?\d{2,4}[-.\s]?\d{2,4}[-.\s]?\d{2,4}"
)

# ---------------------------------------------------------------------------
# SECTION 2: SECURITY - PATTERNS OF UNSAFE / MALICIOUS INPUT
# ---------------------------------------------------------------------------
# These patterns flag content that looks like it is trying to manipulate the
# application (script injection, SQL injection, path traversal, template
# injection) rather than being genuine data. We never execute or "clean up"
# this content - we simply detect it and exclude/flag it, matching the
# assignment's requirement to demonstrate that input is not automatically
# trusted.
UNSAFE_PATTERNS = {
    "script_injection": re.compile(r"<\s*script.*?>|on\w+\s*=", re.IGNORECASE),
    "html_event_handler": re.compile(r"<[^>]+on\w+\s*=", re.IGNORECASE),
    "sql_injection": re.compile(r"(--|;)\s*(DROP|DELETE|INSERT|UPDATE)\b", re.IGNORECASE),
    "path_traversal": re.compile(r"\.\./"),
    "template_injection": re.compile(r"\{\{.*?\}\}"),
    "embedded_credentials_url": re.compile(r"https?://[^/\s]*@"),  # e.g. http://user@host
}


def contains_unsafe_content(text: str) -> list:
    """Return a list of the names of any unsafe patterns found in `text`."""
    findings = []
    for name, pattern in UNSAFE_PATTERNS.items():
        if pattern.search(text):
            findings.append(name)
    return findings


def luhn_check(card_number: str) -> bool:
    """
    Validate a credit card number using the Luhn algorithm.
    This confirms the number is a *structurally valid* card number - it does
    NOT confirm the card is real, active, or belongs to anyone.
    """
    digits = [int(d) for d in re.sub(r"[ -]", "", card_number)]
    if not (13 <= len(digits) <= 19):
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def mask_card(card_number: str) -> str:
    """Mask all but the last 4 digits of a card number before it is ever
    stored, printed, or logged - so sensitive data is not exposed."""
    digits = re.sub(r"[ -]", "", card_number)
    return "*" * (len(digits) - 4) + digits[-4:]


def mask_email(email: str) -> str:
    """Partially mask an email's local part before logging it, e.g.
    'j.uwimana@alueducation.com' -> 'j.*******@alueducation.com'."""
    local, _, domain = email.partition("@")
    if len(local) <= 1:
        masked_local = "*" * len(local)
    else:
        masked_local = local[0] + "*" * (len(local) - 1)
    return f"{masked_local}@{domain}"


# ---------------------------------------------------------------------------
# SECTION 3: EXTRACTION LOGIC
# ---------------------------------------------------------------------------

def extract_emails(text: str) -> dict:
    """Extract all emails, then bucket the ALU-specific ones separately.
    Any candidate that also trips an unsafe pattern (e.g. it's actually part
    of a bigger malicious payload/spoofed link) is skipped rather than
    trusted."""
    raw_matches = EMAIL_PATTERN.findall(text)
    general, official, alumni, si = [], [], [], []

    for email in raw_matches:
        # Reject if this exact fragment is sitting inside something flagged
        # unsafe (defense in depth - the whole-line check happens later too).
        if contains_unsafe_content(email):
            continue

        if ALU_OFFICIAL_PATTERN.search(email):
            official.append(mask_email(email))
        elif ALU_ALUMNI_PATTERN.search(email):
            alumni.append(mask_email(email))
        elif ALU_SI_PATTERN.search(email):
            si.append(mask_email(email))
        else:
            general.append(mask_email(email))

    return {
        "general_emails": sorted(set(general)),
        "alu_official_emails": sorted(set(official)),
        "alu_alumni_emails": sorted(set(alumni)),
        "alu_si_emails": sorted(set(si)),
    }


def extract_credit_cards(text: str):
    """Extract candidate card numbers, keep only ones that pass Luhn, and
    mask them immediately - the raw number is never returned or stored.
    Also returns the character spans that were consumed, so other
    extractors (phone numbers) don't re-match the same digits."""
    valid_masked = []
    spans = []
    for match in CREDIT_CARD_PATTERN.finditer(text):
        candidate = match.group()
        if luhn_check(candidate):
            valid_masked.append(mask_card(candidate))
            spans.append(match.span())
    return sorted(set(valid_masked)), spans


def extract_urls(text: str, unsafe_line_numbers: set) -> list:
    """Extract URLs, excluding any that show signs of credential-embedding
    or other unsafe tricks (e.g. http://user@host used for phishing), and
    excluding any URL that appears on a line already flagged as malicious
    (e.g. a URL sitting inside a <script> payload) - we don't treat any
    part of an unsafe line as trustworthy data."""
    safe_urls = []
    for line_num, line in enumerate(text.splitlines(), start=1):
        if line_num in unsafe_line_numbers:
            continue
        for match in URL_PATTERN.finditer(line):
            url = match.group()
            if contains_unsafe_content(url):
                continue
            safe_urls.append(url.rstrip(".,)"))
    return sorted(set(safe_urls))


def extract_phone_numbers(text: str, exclude_spans: list) -> list:
    """Extract phone-number-shaped strings. We require 7-13 actual digits so
    we don't pick up short unrelated numbers, we drop obvious placeholder
    numbers like all-zero strings, and we skip any span already consumed by
    a validated credit card match so card digits are never double-counted
    as a phone number."""
    valid = []
    for match in PHONE_PATTERN.finditer(text):
        start, end = match.span()
        m = match.group()

        # Skip if this match overlaps a span already claimed by a credit card
        if any(start < c_end and end > c_start for c_start, c_end in exclude_spans):
            continue

        digit_count = len(re.sub(r"\D", "", m))
        if digit_count < 7 or digit_count > 13:
            continue
        if re.fullmatch(r"[0\s\-().]+", m):  # e.g. 000-000-0000
            continue
        valid.append(m.strip())
    return sorted(set(valid))


def scan_for_threats(text: str) -> list:
    """Scan the raw text line-by-line and report which lines contain
    unsafe/malicious patterns, without ever executing or reproducing the
    dangerous payload itself in a usable form."""
    threats = []
    for line_num, line in enumerate(text.splitlines(), start=1):
        findings = contains_unsafe_content(line)
        if findings:
            threats.append({"line": line_num, "flags": findings})
    return threats


# ---------------------------------------------------------------------------
# SECTION 4: MAIN
# ---------------------------------------------------------------------------

def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    input_path = os.path.join(base_dir, "input", "raw-text.txt")
    output_path = os.path.join(base_dir, "output", "sample-output.json")

    with open(input_path, "r", encoding="utf-8") as f:
        raw_text = f.read()

    security_flags = scan_for_threats(raw_text)
    unsafe_line_numbers = {flag["line"] for flag in security_flags}

    cards_masked, card_spans = extract_credit_cards(raw_text)

    results = {
        "emails": extract_emails(raw_text),
        "credit_cards_masked": cards_masked,
        "urls": extract_urls(raw_text, unsafe_line_numbers),
        "phone_numbers": extract_phone_numbers(raw_text, card_spans),
        "security_flags": security_flags,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    # Console summary (readable, no raw sensitive data printed)
    print("=" * 60)
    print("REGEX DATA EXTRACTION SUMMARY")
    print("=" * 60)
    print(f"General emails found:      {len(results['emails']['general_emails'])}")
    print(f"ALU official emails found: {len(results['emails']['alu_official_emails'])}")
    print(f"ALU alumni emails found:   {len(results['emails']['alu_alumni_emails'])}")
    print(f"ALU SI emails found:       {len(results['emails']['alu_si_emails'])}")
    print(f"Valid credit cards found:  {len(results['credit_cards_masked'])} (masked)")
    print(f"URLs found:                {len(results['urls'])}")
    print(f"Phone numbers found:       {len(results['phone_numbers'])}")
    print(f"Unsafe lines flagged:      {len(results['security_flags'])}")
    print("-" * 60)
    if results["security_flags"]:
        print("Security warnings (input NOT trusted, excluded from results):")
        for flag in results["security_flags"]:
            print(f"  Line {flag['line']}: {', '.join(flag['flags'])}")
    print("-" * 60)
    print(f"Full structured results written to: {output_path}")


if __name__ == "__main__":
    main()
