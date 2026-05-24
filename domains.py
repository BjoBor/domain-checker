import socket
import time
from pathlib import Path

# Which extensions to check
CHECK_COM = False
CHECK_NO = True

# WHOIS servers
WHOIS_SERVERS = {
    ".com": "whois.verisign-grs.com",
    ".no": "whois.norid.no",
}

REQUEST_DELAY_SECONDS = 0.1
_last_request_time = 0.0


def throttle_requests() -> None:
    """Keep WHOIS lookups spaced out to reduce rate limiting."""
    global _last_request_time

    elapsed = time.monotonic() - _last_request_time
    if elapsed < REQUEST_DELAY_SECONDS:
        time.sleep(REQUEST_DELAY_SECONDS - elapsed)

    _last_request_time = time.monotonic()


def query_whois(domain: str, whois_server: str) -> str:
    """Query a WHOIS server and return the raw response."""
    response = b""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(10)
        s.connect((whois_server, 43))
        s.sendall((domain + "\r\n").encode())

        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data

    return response.decode(errors="ignore")


def is_domain_available(domain: str, extension: str) -> bool:
    """Check if a domain is available based on WHOIS response."""
    full_domain = f"{domain}{extension}"
    whois_server = WHOIS_SERVERS.get(extension)

    if not whois_server:
        raise ValueError(f"Unsupported extension: {extension}")

    try:
        throttle_requests()
        result = query_whois(full_domain, whois_server).lower()
        
        print(f"  Checking {full_domain}...", end=" ")

        # Availability patterns
        if extension == ".com":
            available = "no match for" in result
            print(f"→ {'Available' if available else 'Taken'}")
            return available

        elif extension == ".no":
            # Available if "no match" is in response
            available = "no match" in result and "domain information" not in result
            print(f"→ {'Available' if available else 'Taken'}")
            return available

    except Exception as e:
        print(f"Error: {e}")

    return False


def main():
    domains_file = Path("domains.txt")

    if not domains_file.exists():
        print("domains.txt not found")
        return

    domains = [
        line.strip().lower()
        for line in domains_file.read_text().splitlines()
        if line.strip()
    ]

    print("Checking domains...\n")

    available_both = []
    not_available_both = []

    for domain in domains:
        print(f"Domain: {domain}")
        com_available = is_domain_available(domain, ".com") if CHECK_COM else None
        no_available = is_domain_available(domain, ".no") if CHECK_NO else None

        if (com_available or not CHECK_COM) and (no_available or not CHECK_NO):
            available_both.append(domain)
            checked = " and ".join(filter(None, [".com" if CHECK_COM else "", ".no" if CHECK_NO else ""]))
            print(f"  ✅ {domain}: {checked} {'are' if CHECK_COM and CHECK_NO else 'is'} available\n")
        else:
            not_available_both.append(domain)
            status = []
            if CHECK_COM:
                status.append(".com available" if com_available else ".com taken")
            if CHECK_NO:
                status.append(".no available" if no_available else ".no taken")
            print(f"  ℹ️  {domain}: {', '.join(status)}\n")

    # Write results to files
    if available_both:
        with open("free.txt", "a") as f:
            for d in available_both:
                f.write(d + "\n")

    if not_available_both:
        with open("not-free.txt", "a") as f:
            for d in not_available_both:
                f.write(d + "\n")

    print("=" * 50)
    checked = " and ".join(filter(None, [".com" if CHECK_COM else "", ".no" if CHECK_NO else ""]))
    print("Summary:")
    if available_both:
        print(f"✅ Domains available for {checked}:")
        for d in available_both:
            print(f"   - {d}")
    else:
        print(f"❌ No domains were available for {checked}.")


if __name__ == "__main__":
    main()
