# import subprocess
# from django.core.management.base import BaseCommand
# from cygnus.core.tasks import run_nmap_scan
# from cygnus.core.models import Target

import subprocess
import json
import os
import tempfile
import whois
from core.models import Scan, Target
from celery import shared_task

def run_command(command):
    
    # Runs a system command safely and returns output or error.
    
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except FileNotFoundError:
        return f"Error: {command[0]} not found. Install it first."
    except subprocess.CalledProcessError as e:
        return f"Command failed:\n{e.stderr}"
    
@shared_task
def run_nmap_scan(target_id):
  
    # Runs an nmap scan on the given target and stores the result.
    
    try:
        target = Target.objects.get(id=target_id)
    except Target.DoesNotExist:
        return f"Target with ID {target_id} does not exist."

    command = ["nmap", "-sV","-sC","--script=http-enum", "-T4", "-A", target.domain]
    output = run_command(command)

    # Store the scan result in the database
    scan = Scan.objects.create(
        target=target,
        scan_type="nmap",
        command=" ".join(command),
        result=output,
        status="success" if "Error" not in output else "failed"
    )
    scan.save()
    return f"Nmap scan completed for {target.domain}."

@shared_task
def gobuster_scan(target_id, wordlist_path="wordlists/gobuster/common.txt"):
    
    # Runs a DirBuster scan on the given target and stores the result.

    try:
        target = Target.objects.get(id=target_id)
    except Target.DoesNotExist:
        return f"Target with ID {target_id} does not exist."

    command = ["gobuster", "-u",f"http://{target.domain}","-w", wordlist_path]
    output = run_command(command)

    # Store the scan result in the database
    scan = Scan.objects.create(
        target=target,
        scan_type="dirb",
        command=" ".join(command),
        result=output,
        status="success" if "Error" not in output else "failed"
    )
    scan.save()
    return f"DirBuster scan completed for {target.domain}."

@shared_task
def amass_scan(target_id):
    # Runs an Amass scan on the given target and stores the result.

    try:
        target = Target.objects.get(id=target_id)
    except Target.DoesNotExist:
        return f"Target with ID {target_id} does not exist."

    command = ["amass", "enum", "-d", target.domain, "-o", f"/tmp/{target.domain}_amass.txt"]
    output = run_command(command)

    # Read the output file if it was created
    try:
        with open(f"/tmp/{target.domain}_amass.txt", "r") as f:
            file_output = f.read()
    except FileNotFoundError:
        file_output = "Amass output file not found."

    # Store the scan result in the database
    scan = Scan.objects.create(
        target=target,
        scan_type="amass",
        command=" ".join(command),
        result=file_output,
        status="success" if "Error" not in output else "failed"
    )
    scan.save()
    return f"Amass scan completed for {target.domain}."



def get_temp_path(filename):
    return os.path.join(tempfile.gettempdir(), filename)

@shared_task
def httpx_scan(target_id):
    # Runs an httpx scan on the given target and stores the result.

    try:
        target = Target.objects.get(id=target_id)
    except Target.DoesNotExist:
        return f"Target with ID {target_id} does not exist."

    input_file = get_temp_path(f"{target.domain}_amass.txt")
    output_file = get_temp_path(f"{target.domain}_alive.txt")
    command = [
        "httpx",
        "-l", input_file,
        "-o", output_file,
        "-silent",
        "-status-code",
        "-title",
        "-tech-detect"
    ]
    output = run_command(command)

    try:
        with open(output_file, "r") as f:
            file_output = f.read()
    except FileNotFoundError:
        file_output = "httpx output file not found."

    # Store the scan result in the database
    scan = Scan.objects.create(
        target=target,
        scan_type="httpx",
        command=" ".join(command),
        result=file_output,
        status="success" if "Error" not in output else "failed"
    )
    scan.save()
    return f"httpx scan completed for {target.domain}."


@shared_task
def httpx_tech_detection_scan(target_id):
    """
    Runs httpx-toolkit with technology detection (-td) on the given target
    and stores the result in the database.
    """
    try:
        target = Target.objects.get(id=target_id)
    except Target.DoesNotExist:
        return f"Target with ID {target_id} does not exist."

    command = [
        "httpx-toolkit",
        "-l", f"/tmp/{target.domain}_alive.txt",  # input file with live subdomains
        "-o", f"/tmp/{target.domain}_tech.json",  # output file
        "-json",  # ensure JSON format
        "-td"     # enable technology detection
    ]
    output = run_command(command)

    # Read the output file if created
    try:
        with open(f"/tmp/{target.domain}_tech.json", "r") as f:
            file_output = f.read()
    except FileNotFoundError:
        file_output = "httpx-toolkit tech detection output file not found."

    # Store result in DB
    scan = Scan.objects.create(
        target=target,
        scan_type="httpx-toolkit-tech-detection",
        command=" ".join(command),
        result=file_output,
        status="success" if "Error" not in output else "failed"
    )
    scan.save()

    return f"httpx-toolkit technology detection completed for {target.domain}."

@shared_task
def passive_whois_scan(target_id):
    try:
        target = Target.objects.get(id=target_id)
    except Target.DoesNotExist:
        return f"Target with ID {target_id} does not exist."

    try:
        whois_info = whois.whois(target.domain)
        result = str(whois_info)
        status = "success"
    except Exception as e:
        result = f"WHOIS lookup failed: {str(e)}"
        status = "failed"

    scan = Scan.objects.create(
        target=target,
        scan_type="passive-whois",
        command=f"whois {target.domain}",
        result=result,
        status=status
    )
    scan.save()
    return f"Passive WHOIS scan completed for {target.domain}."


