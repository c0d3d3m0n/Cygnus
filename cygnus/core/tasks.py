# # import subprocess
# # from django.core.management.base import BaseCommand
# # from cygnus.core.tasks import run_nmap_scan
# # from cygnus.core.models import Target

# import subprocess
# import json
# import os
# import tempfile
# import whois
# import dns.resolver
# import requests
# from core.models import Scan, Target, Subdomain
# from celery import shared_task

# def run_command(command):
#     # Runs a system command safely and returns output or error.
#     try:
#         result = subprocess.run(
#             command,
#             capture_output=True,
#             text=True,
#             check=True
#         )
#         return result.stdout
#     except FileNotFoundError:
#         return f"Error: {command[0]} not found. Install it first."
#     except subprocess.CalledProcessError as e:
#         return f"Command failed:\n{e.stderr}"
    
# @shared_task
# def run_nmap_scan(target_id):
  
#     # Runs an nmap scan on the given target and stores the result.
    
#     try:
#         target = Target.objects.get(id=target_id)
#     except Target.DoesNotExist:
#         return f"Target with ID {target_id} does not exist."

#     command = ["nmap", "-sV","-sC","--script=http-enum", "-T4", "-A", target.domain]
#     output = run_command(command)

#     # Store the scan result in the database
#     scan = Scan.objects.create(
#         target=target,
#         scan_type="nmap",
#         command=" ".join(command),
#         result=output,
#         status="success" if "Error" not in output else "failed"
#     )
#     scan.save()
#     return f"Nmap scan completed for {target.domain}."

# @shared_task
# def gobuster_scan(target_id, wordlist_path="wordlists/gobuster/common.txt"):
    
#     # Runs a DirBuster scan on the given target and stores the result.

#     try:
#         target = Target.objects.get(id=target_id)
#     except Target.DoesNotExist:
#         return f"Target with ID {target_id} does not exist."

#     command = ["gobuster", "-u",f"http://{target.domain}","-w", wordlist_path]
#     output = run_command(command)

#     # Store the scan result in the database
#     scan = Scan.objects.create(
#         target=target,
#         scan_type="dirb",
#         command=" ".join(command),
#         result=output,
#         status="success" if "Error" not in output else "failed"
#     )
#     scan.save()
#     return f"DirBuster scan completed for {target.domain}."

# @shared_task
# def amass_scan(target_id):
#     # Runs an Amass scan on the given target and stores the result.

#     try:
#         target = Target.objects.get(id=target_id)
#     except Target.DoesNotExist:
#         return f"Target with ID {target_id} does not exist."

#     command = ["amass", "enum", "-d", target.domain, "-o", f"/tmp/{target.domain}_amass.txt"]
#     output = run_command(command)

#     # Read the output file if it was created
#     try:
#         with open(f"/tmp/{target.domain}_amass.txt", "r") as f:
#             file_output = f.read()
#     except FileNotFoundError:
#         file_output = "Amass output file not found."

#     # Store the scan result in the database
#     scan = Scan.objects.create(
#         target=target,
#         scan_type="amass",
#         command=" ".join(command),
#         result=file_output,
#         status="success" if "Error" not in output else "failed"
#     )
#     scan.save()
#     return f"Amass scan completed for {target.domain}."



# def get_temp_path(filename):
#     return os.path.join(tempfile.gettempdir(), filename)

# @shared_task
# def httpx_scan(target_id):
#     # Runs an httpx scan on the given target and stores the result.

#     try:
#         target = Target.objects.get(id=target_id)
#     except Target.DoesNotExist:
#         return f"Target with ID {target_id} does not exist."

#     input_file = get_temp_path(f"{target.domain}_amass.txt")
#     output_file = get_temp_path(f"{target.domain}_alive.txt")
#     command = [
#         "httpx",
#         "-l", input_file,
#         "-o", output_file,
#         "-silent",
#         "-status-code",
#         "-title",
#         "-tech-detect"
#     ]
#     output = run_command(command)

#     try:
#         with open(output_file, "r") as f:
#             file_output = f.read()
#     except FileNotFoundError:
#         file_output = "httpx output file not found."

#     # Store the scan result in the database
#     scan = Scan.objects.create(
#         target=target,
#         scan_type="httpx",
#         command=" ".join(command),
#         result=file_output,
#         status="success" if "Error" not in output else "failed"
#     )
#     scan.save()
#     return f"httpx scan completed for {target.domain}."


# @shared_task
# def httpx_tech_detection_scan(target_id):
#     """
#     Runs httpx-toolkit with technology detection (-td) on the given target
#     and stores the result in the database.
#     """
#     try:
#         target = Target.objects.get(id=target_id)
#     except Target.DoesNotExist:
#         return f"Target with ID {target_id} does not exist."

#     command = [
#         "httpx-toolkit",
#         "-l", f"/tmp/{target.domain}_alive.txt",  # input file with live subdomains
#         "-o", f"/tmp/{target.domain}_tech.json",  # output file
#         "-json",  # ensure JSON format
#         "-td"     # enable technology detection
#     ]
#     output = run_command(command)

#     # Read the output file if created
#     try:
#         with open(f"/tmp/{target.domain}_tech.json", "r") as f:
#             file_output = f.read()
#     except FileNotFoundError:
#         file_output = "httpx-toolkit tech detection output file not found."

#     # Store result in DB
#     scan = Scan.objects.create(
#         target=target,
#         scan_type="httpx-toolkit-tech-detection",
#         command=" ".join(command),
#         result=file_output,
#         status="success" if "Error" not in output else "failed"
#     )
#     scan.save()

#     return f"httpx-toolkit technology detection completed for {target.domain}."

# @shared_task
# def passive_whois_scan(target_id):
#     try:
#         target = Target.objects.get(id=target_id)
#     except Target.DoesNotExist:
#         return f"Target with ID {target_id} does not exist."

#     try:
#         whois_info = whois.whois(target.domain)
#         result = str(whois_info)
#         status = "success"
#     except Exception as e:
#         result = f"WHOIS lookup failed: {str(e)}"
#         status = "failed"

#     scan = Scan.objects.create(
#         target=target,
#         scan_type="passive-whois",
#         command=f"whois {target.domain}",
#         result=result,
#         status=status
#     )
#     scan.save()
#     return f"Passive WHOIS scan completed for {target.domain}."

# @shared_task
# def passive_dns_scan(target_id):
#     try:
#         target = Target.objects.get(id=target_id)
#     except Target.DoesNotExist:
#         return f"Target with ID {target_id} does not exist."

#     records = {}
#     try:
#         for rtype in ["A", "AAAA", "MX", "NS", "TXT"]:
#             answers = dns.resolver.resolve(target.domain, rtype, raise_on_no_answer=False)
#             records[rtype] = [str(rdata) for rdata in answers]
#         result = json.dumps(records, indent=2)
#         status = "success"
#     except Exception as e:
#         result = f"DNS lookup failed: {str(e)}"
#         status = "failed"

#     scan = Scan.objects.create(
#         target=target,
#         scan_type="passive-dns",
#         command=f"DNS lookup {target.domain}",
#         result=result,
#         status=status
#     )
#     scan.save()
#     return f"Passive DNS scan completed for {target.domain}."

# @shared_task
# def passive_cert_scan(target_id):
#     # """
#     # Performs a certificate transparency scan using crt.sh, parses the
#     # results, and saves unique subdomains found.
#     # """
#     try:
#         target = Target.objects.get(id=target_id)
#     except Target.DoesNotExist:
#         # If the target is deleted before the task runs, we can't proceed.
#         return f"Task aborted: Target with ID {target_id} does not exist."

#     # Using a wildcard search for subdomains of the target domain.
#     url = f"https://crt.sh/?q=%.{target.domain}&output=json"
#     command_str = f"crt.sh query for %.{target.domain}"
    
#     found_subdomains = set()
#     scan_result_summary = ""
#     status = "failed" # Default status

#     try:
#         # Set a reasonable timeout and headers to mimic a browser.
#         headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
#         response = requests.get(url, timeout=20, headers=headers)
        
#         # Raise an exception for bad status codes (4xx or 5xx).
#         response.raise_for_status()

#         # It's possible to get a 200 OK with an empty response if nothing is found.
#         if response.text:
#             # Use a set to automatically handle duplicate entries.
#             unique_domains = set()
            
#             # The response is a newline-delimited JSON stream.
#             for line in response.text.strip().split('\n'):
#                 try:
#                     cert_data = json.loads(line)
#                     # Add both common_name and all name_values to our set.
#                     unique_domains.add(cert_data.get('common_name'))
#                     # name_value can contain multiple domains separated by newlines.
#                     if 'name_value' in cert_data:
#                         for name in cert_data['name_value'].split('\n'):
#                             unique_domains.add(name)
#                 except json.JSONDecodeError:
#                     # Ignore lines that are not valid JSON.
#                     continue

#             # Clean and validate the domains before adding them.
#             for domain in unique_domains:
#                 if domain and target.domain in domain:
#                     # Remove wildcard prefixes if they exist.
#                     clean_domain = domain.lstrip('*.')
#                     found_subdomains.add(clean_domain)
            
#             # Create or update Subdomain objects.
#             # This is more efficient than creating one by one.
#             newly_created_count = 0
#             for sub in found_subdomains:
#                 # get_or_create returns a tuple: (object, created_boolean)
#                 _, created = Subdomain.objects.get_or_create(
#                     domain_name=sub,
#                     target=target
#                 )
#                 if created:
#                     newly_created_count += 1
            
#             scan_result_summary = f"Scan successful. Discovered {len(found_subdomains)} unique subdomains. Added {newly_created_count} new entries to the database."
#             status = "success"
#         else:
#             scan_result_summary = "Scan completed, but no certificates were found for the target."
#             status = "success"

#     except requests.exceptions.Timeout:
#         scan_result_summary = "crt.sh query failed: The request timed out."
#     except requests.exceptions.RequestException as e:
#         scan_result_summary = f"crt.sh query failed: An error occurred ({str(e)})."
#     except Exception as e:
#         # Catch any other unexpected errors during processing.
#         scan_result_summary = f"An unexpected error occurred: {str(e)}"
        
#     # Create one final Scan object to log the activity.
#     # .create() automatically saves the instance.
#     Scan.objects.create(
#         target=target,
#         scan_type="passive-cert",
#         command=command_str,
#         result=scan_result_summary,
#         status=status
#     )

#     return f"Passive certificate scan completed for {target.domain}."



import subprocess
import json
import os
import tempfile
import re
import whois
import dns.resolver
import requests
import shodan

from celery import shared_task
from cryptography.fernet import Fernet
from core.models import Target, ScanSession, ScanTask, Subdomain, Port, ScanArtifact

# Load encryption key (generate/store in env or .env file)
FERNET_KEY = os.getenv("SCAN_ENCRYPTION_KEY", Fernet.generate_key())
cipher = Fernet(FERNET_KEY)


# ---------------------------
# Utility Functions
# ---------------------------

def validate_domain(domain: str) -> bool:
    """Ensure input is a valid domain or IP."""
    domain_regex = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")
    ip_regex = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
    return bool(domain_regex.match(domain) or ip_regex.match(domain))


def run_command(command):
    """Run a CLI command safely."""
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout or result.stderr
    except FileNotFoundError:
        return f"Error: {command[0]} not found. Install it first."
    except subprocess.CalledProcessError as e:
        return f"Command failed:\n{e.stderr}"


def get_temp_path(filename):
    return os.path.join(tempfile.gettempdir(), filename)


def save_scan(session, scan_type, command, result, status="success"):
    """Encrypt result and save a ScanTask."""
    encrypted = cipher.encrypt(result.encode()).decode()
    return ScanTask.objects.create(
        session=session,
        scan_type=scan_type,
        command=command,
        result=encrypted,
        status=status
    )


# ---------------------------
# Active Scans
# ---------------------------

@shared_task
def run_nmap_scan(session_id):
    try:
        session = ScanSession.objects.get(id=session_id)
        target = session.target
    except ScanSession.DoesNotExist:
        return f"Session {session_id} does not exist."

    if not validate_domain(target.domain):
        return f"Invalid domain/IP: {target.domain}"

    command = ["nmap", "-sV", "-sC", "--script=http-enum", "-T4", "-A", target.domain]
    output = run_command(command)

    # Parse simple open ports from output
    for line in output.splitlines():
        if "/tcp" in line and "open" in line:
            parts = line.split()
            port_number = int(parts[0].split("/")[0])
            service = parts[2] if len(parts) > 2 else ""
            Port.objects.get_or_create(
                session=session,
                port_number=port_number,
                service=service
            )

    save_scan(session, "nmap", " ".join(command), output, "success")
    return f"Nmap scan completed for {target.domain}."


@shared_task
def gobuster_scan(session_id, wordlist_path="wordlists/gobuster/common.txt"):
    try:
        session = ScanSession.objects.get(id=session_id)
        target = session.target
    except ScanSession.DoesNotExist:
        return f"Session {session_id} does not exist."

    command = ["gobuster", "-u", f"http://{target.domain}", "-w", wordlist_path]
    output = run_command(command)

    save_scan(session, "gobuster", " ".join(command), output, "success")
    return f"Gobuster scan completed for {target.domain}."


@shared_task
def amass_scan(session_id):
    try:
        session = ScanSession.objects.get(id=session_id)
        target = session.target
    except ScanSession.DoesNotExist:
        return f"Session {session_id} does not exist."

    outfile = get_temp_path(f"{target.domain}_amass.txt")
    command = ["amass", "enum", "-d", target.domain, "-o", outfile]
    output = run_command(command)

    try:
        with open(outfile, "r") as f:
            file_output = f.read()
            for sub in file_output.splitlines():
                Subdomain.objects.get_or_create(session=session, domain_name=sub, discovered_by="amass")
    except FileNotFoundError:
        file_output = "Amass output file not found."

    save_scan(session, "amass", " ".join(command), file_output, "success")
    return f"Amass scan completed for {target.domain}."


@shared_task
def httpx_scan(session_id):
    try:
        session = ScanSession.objects.get(id=session_id)
        target = session.target
    except ScanSession.DoesNotExist:
        return f"Session {session_id} does not exist."

    input_file = get_temp_path(f"{target.domain}_amass.txt")
    output_file = get_temp_path(f"{target.domain}_alive.txt")
    command = ["httpx", "-l", input_file, "-o", output_file, "-silent", "-status-code", "-title", "-tech-detect"]
    run_command(command)

    try:
        with open(output_file, "r") as f:
            file_output = f.read()
    except FileNotFoundError:
        file_output = "httpx output file not found."

    save_scan(session, "httpx", " ".join(command), file_output, "success")
    return f"httpx scan completed for {target.domain}."


# ---------------------------
# Passive Scans
# ---------------------------

@shared_task
def passive_whois_scan(session_id):
    try:
        session = ScanSession.objects.get(id=session_id)
        target = session.target
    except ScanSession.DoesNotExist:
        return f"Session {session_id} does not exist."

    try:
        whois_info = whois.whois(target.domain)
        result = str(whois_info)
        status = "success"
    except Exception as e:
        result = f"WHOIS lookup failed: {str(e)}"
        status = "failed"

    save_scan(session, "whois", f"whois {target.domain}", result, status)
    return f"WHOIS scan completed for {target.domain}."


@shared_task
def passive_dns_scan(session_id):
    try:
        session = ScanSession.objects.get(id=session_id)
        target = session.target
    except ScanSession.DoesNotExist:
        return f"Session {session_id} does not exist."

    records = {}
    try:
        for rtype in ["A", "AAAA", "MX", "NS", "TXT"]:
            answers = dns.resolver.resolve(target.domain, rtype, raise_on_no_answer=False)
            records[rtype] = [str(rdata) for rdata in answers]
        result = json.dumps(records, indent=2)
        status = "success"
    except Exception as e:
        result = f"DNS lookup failed: {str(e)}"
        status = "failed"

    save_scan(session, "dns", f"DNS lookup {target.domain}", result, status)
    return f"DNS scan completed for {target.domain}."


@shared_task
def passive_cert_scan(session_id):
    try:
        session = ScanSession.objects.get(id=session_id)
        target = session.target
    except ScanSession.DoesNotExist:
        return f"Session {session_id} does not exist."

    url = f"https://crt.sh/?q=%.{target.domain}&output=json"
    try:
        response = requests.get(url, timeout=20, headers={"User-Agent": "ReconFramework"})
        response.raise_for_status()
        unique_domains = {entry["common_name"] for entry in response.json() if "common_name" in entry}
        for entry in response.json():
            if "name_value" in entry:
                unique_domains.update(entry["name_value"].split("\n"))

        for sub in unique_domains:
            if sub and target.domain in sub:
                Subdomain.objects.get_or_create(session=session, domain_name=sub.lstrip("*."), discovered_by="crt.sh")

        result = f"Discovered {len(unique_domains)} unique subdomains from crt.sh"
        status = "success"
    except Exception as e:
        result = f"crt.sh query failed: {str(e)}"
        status = "failed"

    save_scan(session, "crt.sh", "crt.sh query", result, status)
    return f"crt.sh scan completed for {target.domain}."


# ---------------------------
# API-based Scans
# ---------------------------

@shared_task
def shodan_scan(session_id, api_key):
    try:
        session = ScanSession.objects.get(id=session_id)
        target = session.target
    except ScanSession.DoesNotExist:
        return f"Session {session_id} does not exist."

    try:
        api = shodan.Shodan(api_key)
        host = api.host(target.domain)
        for item in host.get("data", []):
            Port.objects.get_or_create(
                session=session,
                port_number=item["port"],
                service=item.get("product", ""),
                banner=item.get("data", "")
            )
        result = json.dumps(host, indent=2)
        status = "success"
    except Exception as e:
        result = f"Shodan lookup failed: {str(e)}"
        status = "failed"

    save_scan(session, "shodan", f"Shodan API for {target.domain}", result, status)
    return f"Shodan scan completed for {target.domain}."


from celery import chain

@shared_task
def run_active_recon(session_id):
    """Run all active recon scans in sequence"""
    job = chain(
        run_nmap_scan.s(session_id),
        gobuster_scan.s(session_id),
        amass_scan.s(session_id),
        httpx_scan.s(session_id)
    )
    job.apply_async()
    return f"Active recon started for session {session_id}"


@shared_task
def run_passive_recon(session_id, shodan_api_key=None):
    """Run all passive recon scans"""
    job = chain(
        passive_whois_scan.s(session_id),
        passive_dns_scan.s(session_id),
        passive_cert_scan.s(session_id)
    )
    if shodan_api_key:
        job |= shodan_scan.s(session_id, shodan_api_key)
    job.apply_async()
    return f"Passive recon started for session {session_id}"


@shared_task
def run_complete_scan(session_id, shodan_api_key=None):
    """Run active + passive recon together"""
    job = chain(
        run_active_recon.s(session_id),
        run_passive_recon.s(session_id, shodan_api_key)
    )
    job.apply_async()
    return f"Complete scan started for session {session_id}"
