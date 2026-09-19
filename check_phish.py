import os
import re
import sys
import difflib
import hashlib
import math
from datetime import datetime
from email import message_from_string
from urllib.parse import urlparse, unquote
from io import BytesIO

# Optional Advanced Threat Intel Libraries (Fail-safe imports)
try:
    import requests
    NETWORK_CHECKS_ENABLED = True
except ImportError:
    NETWORK_CHECKS_ENABLED = False

try:
    import whois
    WHOIS_ENABLED = True
except ImportError:
    WHOIS_ENABLED = False

try:
    from PIL import Image
    from pyzbar.pyzbar import decode as qr_decode
    QUISHING_CHECKS_ENABLED = True
except ImportError:
    QUISHING_CHECKS_ENABLED = False

try:
    from PyPDF2 import PdfReader
    PDF_CHECKS_ENABLED = True
except ImportError:
    PDF_CHECKS_ENABLED = False


def display_banner():
    """Displays the tool name and ASCII art."""
    banner = r"""
                 O  o
            _\_   o
         \\/  ('>
         ( \__|
         \___/
    
    Check Phish By Ali Burhan | sqlerror
    https://github.com/ab-ratul/check-phish/
    Version 1.0 - Enterprise Triage & Threat Engine
    [Static & Safe Execution Mode]
    """
    print(banner)


class PhishingEmailAnalyzer:
    def __init__(self, raw_email_content):
        self.raw_content = raw_email_content
        self.email_obj = message_from_string(raw_email_content)
        self.risk_score = 0
        self.indicators = []
        self.sender_email = ""
        self.sender_display_name = ""
        self.decoded_body = ""
        self.target_brands = ["paypal", "microsoft", "google", "apple", "amazon", "netflix", "chase", "bank"]
        self.free_webmail_providers = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "proton.me", "mail.com"]
        self.scanned_domains = set()

    def shannon_entropy(self, data):
        """Calculates the Shannon entropy to detect DGA domains."""
        if not data:
            return 0
        entropy = 0
        for x in set(data):
            p_x = float(data.count(x)) / len(data)
            entropy += - p_x * math.log(p_x, 2)
        return entropy

    def run_analysis(self):
        """Executes the complete multi-vector phishing detection pipeline."""
        self._extract_sender_and_body()
        self._analyze_routing_and_origin()
        self._analyze_sender_and_impersonation()
        self._analyze_bec_and_social_engineering()
        self._analyze_obfuscation_evasion()
        self._analyze_text_and_lures()
        self._analyze_links_and_payloads()
        self._analyze_attachments()
        
        self.risk_score = min(self.risk_score, 100)

        if self.risk_score >= 70:
            verdict = "Malicious"
            action = "Block Domain & Escalate"
        elif self.risk_score >= 40:
            verdict = "Suspicious"
            action = "Warn User"
        else:
            verdict = "Safe"
            action = "Close Incident"

        return {
            "risk_score": self.risk_score,
            "verdict": verdict,
            "recommended_action": action,
            "indicators": self.indicators
        }

    def _extract_sender_and_body(self):
        """Extracts sender information and body from RFC headers and .eml formats."""
        from_header = self.email_obj.get("From", "")
        if from_header:
            email_match = re.search(r'<([^>]+)>', from_header)
            self.sender_email = email_match.group(1).lower() if email_match else from_header.lower()
            name_match = re.search(r'^"?([^"<]+)"?\s*<', from_header)
            self.sender_display_name = name_match.group(1).strip() if name_match else ""

        body_content = ""
        for part in self.email_obj.walk():
            content_type = part.get_content_type()
            if content_type in ["text/plain", "text/html"]:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_content += payload.decode('utf-8', errors='ignore') + " "
                except Exception:
                    pass

        if not body_content.strip():
            body_content = self.raw_content

        self.decoded_body = body_content

    def _analyze_routing_and_origin(self):
        """Extracts tracking pixels and anomalies from routing headers."""
        # Tracking Pixel Detection (Common in SES / automated phishing)
        if re.search(r'<img[^>]+style=["\'][^>]*display:\s*none[^>]*src=["\']http', self.decoded_body, re.IGNORECASE) or \
           re.search(r'<img[^>]+width=["\']?1["\']?[^>]+height=["\']?1["\']?[^>]+src=["\']http', self.decoded_body, re.IGNORECASE):
            self.risk_score += 15
            self.indicators.append("Privacy Threat: A hidden 1x1 tracking pixel was detected. The attacker is tracking email opens.")

        received_headers = self.email_obj.get_all("Received")
        if received_headers:
            earliest_received = received_headers[-1]
            ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', earliest_received)
            if ips:
                origin_ip = ips[-1]
                if not origin_ip.startswith(("10.", "192.168.", "127.")):
                    self.indicators.append(f"Routing Origin: Email originated near external IP {origin_ip}.")

    def _analyze_sender_and_impersonation(self):
        """Checks for Reply-To mismatches, free webmail misuse, and impersonation."""
        if not self.sender_email:
            return

        sender_domain = self.sender_email.split('@')[-1]
        
        # BEC Check: Asymmetric Reply-To Spoofing
        reply_to = self.email_obj.get("Reply-To", "")
        if reply_to:
            reply_to_match = re.search(r'<([^>]+)>', reply_to)
            reply_email = reply_to_match.group(1).lower() if reply_to_match else reply_to.lower()
            reply_domain = reply_email.split('@')[-1]
            
            if sender_domain != reply_domain:
                self.risk_score += 45
                self.indicators.append(f"Severe BEC Risk: Email sent from '{sender_domain}' but replies are diverted to '{reply_domain}'.")

        # Impersonation Check
        domain_name_only = sender_domain.split('.')[0]
        for brand in self.target_brands:
            if brand in self.sender_display_name.lower() and brand not in sender_domain:
                self.risk_score += 45
                self.indicators.append(f"Brand impersonation: Display name claims '{brand}', but routes from '{sender_domain}'.")

    def _analyze_bec_and_social_engineering(self):
        """Scans for generic greetings, secrecy demands, and financial lures."""
        content = self.decoded_body.lower()
        
        # Multi-lingual generic greetings
        greetings = [r'\bdear customer\b', r'\bdear user\b', r'\bsehr geehrte damen und herren\b']
        for greeting in greetings:
            if re.search(greeting, content, re.IGNORECASE):
                self.risk_score += 15
                self.indicators.append(f"Social Engineering: A generic greeting was used instead of a personalized name.")
                break

        secrecy_patterns = [r'keep this (as a )?surprise', r'strictly confidential', r'do not (tell|discuss with) anyone']
        for pattern in secrecy_patterns:
            if re.search(pattern, content):
                self.risk_score += 35
                self.indicators.append("Secrecy tactic detected: Sender insists on confidentiality to bypass peer verification.")
                break

    def _analyze_obfuscation_evasion(self):
        """Scans for invisible HTML text formatting."""
        if re.search(r'(display:\s*none|font-size:\s*0|visibility:\s*hidden|color:\s*(?:transparent|#ffffff|white))', self.decoded_body, re.IGNORECASE):
            self.risk_score += 20
            self.indicators.append("Advanced Evasion: Hidden HTML elements detected, often used to poison AI filters.")

    def _analyze_text_and_lures(self):
        """Scans for obfuscation via hyphenation spacing."""
        if re.search(r'\b([a-zA-Z])-(?:[a-zA-Z]-){2,}[a-zA-Z]\b', self.decoded_body):
            self.risk_score += 35
            self.indicators.append("Text obfuscation detected via hyphenated spacing.")

    def _analyze_links_and_payloads(self):
        """Extracts URLs and performs safe redirect analysis."""
        html_links = re.findall(r'<a[^>]+href=["\'](https?://[^"\']+)["\'][^>]*>(.*?)</a>', self.decoded_body, re.IGNORECASE | re.DOTALL)
        for href_url, anchor_html in html_links:
            clean_anchor = re.sub(r'<[^>]+>', '', anchor_html).strip()
            self._evaluate_link(href_url, clean_anchor)

        raw_urls = re.findall(r'(?<!href=["\'])\bhttps?://[^\s<>"]+', self.decoded_body)
        for url in raw_urls:
            self._evaluate_link(url)

    def _evaluate_link(self, url, anchor_text=""):
        domain = urlparse(url).netloc.lower()
        if domain in self.scanned_domains:
            return
        self.scanned_domains.add(domain)

        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
            self.risk_score += 50
            self.indicators.append(f"Direct IP link detected: '{domain}'.")

        domain_no_tld = domain.split('.')[0]
        entropy = self.shannon_entropy(domain_no_tld)
        if entropy > 4.0 and len(domain_no_tld) > 8:
            self.risk_score += 30
            self.indicators.append(f"Infrastructure: High entropy domain '{domain}' suggests a Domain Generation Algorithm (DGA).")

        if anchor_text:
            anchor_domain = re.search(r'(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}', anchor_text)
            if anchor_domain and anchor_domain.group(0).lower() != domain:
                self.risk_score += 55
                self.indicators.append(f"Deceptive link mismatch: Visible text shows '{anchor_domain.group(0)}' but leads to '{domain}'.")

        # 100% Safe Redirect Tracing via HTTP HEAD (Does not execute or download)
        if NETWORK_CHECKS_ENABLED and domain:
            try:
                resp = requests.head(url, timeout=3, allow_redirects=True)
                if len(resp.history) > 1:
                    final_url = resp.url
                    self.risk_score += 25
                    self.indicators.append(f"Link Obfuscation: URL redirects through {len(resp.history)} hops to land at '{final_url}'.")
            except Exception:
                pass
                
        if WHOIS_ENABLED and domain:
            try:
                domain_info = whois.whois(domain)
                creation_date = domain_info.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                if creation_date:
                    age_days = (datetime.now() - creation_date).days
                    if age_days < 90:
                        self.risk_score += 45
                        self.indicators.append(f"Burner Domain: '{domain}' was registered only {age_days} days ago.")
            except Exception:
                pass

    def _analyze_attachments(self):
        """Analyzes attachments for malicious extensions and safely hashes payloads."""
        for part in self.email_obj.walk():
            if part.get_content_maintype() == 'multipart' or part.get('Content-Disposition') is None:
                continue
            
            filename = part.get_filename()
            if not filename:
                continue
                
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            
            file_hash = hashlib.sha256(payload).hexdigest()
            self.indicators.append(f"Attachment logged: '{filename}'. SHA-256 Hash: {file_hash}")
            
            ext = filename.split('.')[-1].lower()
            if ext in ['exe', 'scr', 'vbs', 'js', 'iso', 'img', 'bat', 'sh']:
                self.risk_score += 50
                self.indicators.append(f"Payload: Highly dangerous attachment extension detected (.{ext}).")
                
            if QUISHING_CHECKS_ENABLED and ext in ['png', 'jpg', 'jpeg']:
                try:
                    img = Image.open(BytesIO(payload))
                    decoded_objects = qr_decode(img)
                    for obj in decoded_objects:
                        qr_data = obj.data.decode('utf-8')
                        self.risk_score += 60
                        self.indicators.append(f"Quishing Threat: Malicious QR code extracted routing to: {qr_data}")
                except Exception:
                    pass

            if PDF_CHECKS_ENABLED and ext == 'pdf':
                try:
                    reader = PdfReader(BytesIO(payload))
                    for page in reader.pages:
                        if "/JS" in page or "/JavaScript" in page or "/OpenAction" in page:
                            self.risk_score += 50
                            self.indicators.append(f"Payload: Embedded script or auto-launch action detected inside PDF '{filename}'.")
                            break
                except Exception:
                    pass


def main():
    while True:
        try:
            display_banner()
            print("Select your input method:")
            print("1. Load raw email from a file (.txt, .eml)")
            print("2. Paste raw email directly into the terminal")
            print("3. Exit Check Phish")
            
            choice = input("\nEnter your choice (1, 2, or 3): ").strip()
            
            if choice == "3":
                print("\nExiting Check Phish tool safely. Goodbye!")
                sys.exit(0)
                
            raw_email_content = ""
            source_description = ""
            
            if choice == "1":
                file_path = input("Enter the file path of the raw email (.txt, .eml): ").strip()
                if not os.path.exists(file_path):
                    print(f"\n[!] Error: The file '{file_path}' does not exist. Press Enter to continue.")
                    input()
                    os.system('cls' if os.name == 'nt' else 'clear')
                    continue
                with open(file_path, "r", encoding="utf-8", errors='ignore') as file:
                    raw_email_content = file.read()
                source_description = f"File: {file_path}"
                
            elif choice == "2":
                print("\nPaste your raw email content below.")
                print("When you are finished, press Ctrl+D (Linux/macOS) or Ctrl+Z followed by Enter (Windows):")
                print("-" * 65)
                raw_email_content = sys.stdin.read()
                # Clear stdin buffer for next loop
                if sys.platform != 'win32':
                    sys.stdin = open('/dev/tty')
                print("-" * 65)
                source_description = "Direct Terminal Paste"
                
                if not raw_email_content.strip():
                    print("\n[!] Error: No email content was provided. Press Enter to continue.")
                    input()
                    os.system('cls' if os.name == 'nt' else 'clear')
                    continue
            else:
                print("\n[!] Error: Invalid choice selected. Press Enter to continue.")
                input()
                os.system('cls' if os.name == 'nt' else 'clear')
                continue

            if NETWORK_CHECKS_ENABLED or WHOIS_ENABLED:
                print("\nInitializing safe static infrastructure checks (No payloads will be executed)...")

            analyzer = PhishingEmailAnalyzer(raw_email_content)
            result = analyzer.run_analysis()
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_filename = f"CheckPhish_Report_{timestamp}.txt"
            
            report_lines = [
                "Check Phish By Ali Burhan - Threat Analysis Report",
                "=" * 65,
                f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"Source: {source_description}",
                f"Risk Score: {result['risk_score']}/100",
                f"Assessment: {result['verdict']}",
                f"Recommended Action: {result['recommended_action']}",
                "=" * 65,
                "Key Indicators Found:"
            ]
            
            if not result['indicators']:
                report_lines.append(" - No security red flags detected.")
            for ind in result['indicators']:
                report_lines.append(f" - {ind}")
                
            report_lines.extend([
                "",
                "Human Firewall Guidance:",
                " - Pause: Do not proceed or make any financial commitments.",
                " - Verify: Validate the request using a trusted phone number or in person.",
                " - Report: Forward this message immediately to your security operations center."
            ])

            report_content = "\n".join(report_lines)
            
            print("\n" + report_content + "\n")
            
            with open(report_filename, "w", encoding="utf-8") as report_file:
                report_file.write(report_content)
                
            print(f"[+] Analysis complete. The result has been saved to {report_filename}.")
            print("\nPress Enter to analyze another email, or Ctrl+C to exit.")
            input()
            os.system('cls' if os.name == 'nt' else 'clear')

        except KeyboardInterrupt:
            print("\n\nOperation cancelled by the user via Ctrl+C. Exiting Check Phish tool safely. Goodbye!")
            sys.exit(0)


if __name__ == "__main__":
    main()
