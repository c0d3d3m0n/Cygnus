
import os
import json
from cryptography.fernet import Fernet

from django.http import JsonResponse, HttpResponse
from django.shortcuts import get_object_or_404
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import render

from core.models import Target, ScanSession, ScanTask, Subdomain, Port
from core.tasks import (
    run_nmap_scan, gobuster_scan, amass_scan,
    httpx_scan, passive_whois_scan, passive_dns_scan,
    passive_cert_scan, shodan_scan,
    run_active_recon, run_passive_recon, run_complete_scan
)

# Encryption key
FERNET_KEY = os.getenv("SCAN_ENCRYPTION_KEY")
cipher = Fernet(FERNET_KEY)


# ---------------------------
# Target & Session Endpoints
# ---------------------------



def dashboard_view(request, session_id):
    session = get_object_or_404(ScanSession, id=session_id)
    return render(request, "dashboard.html", {"session_id": session.id})


@api_view(["POST"])
def add_target(request):
    """Add a new target"""
    domain = request.data.get("domain")
    if not domain:
        return Response({"error": "Domain is required"}, status=400)

    target, created = Target.objects.get_or_create(domain=domain)
    session = ScanSession.objects.create(target=target, name="Default Session")
    return Response({"target_id": target.id, "session_id": session.id})


@api_view(["GET"])
def list_sessions(request):
    """List all scan sessions"""
    sessions = ScanSession.objects.all().values("id", "target__domain", "name", "started_at")
    return Response(list(sessions))


# ---------------------------
# Trigger Scan Tasks
# ---------------------------

@api_view(["POST"])
def start_scan(request, session_id):
    """Start a scan by type"""
    scan_type = request.data.get("scan_type")
    api_key = request.data.get("api_key", None)  # for Shodan

    try:
        session = ScanSession.objects.get(id=session_id)
    except ScanSession.DoesNotExist:
        return Response({"error": "Session not found"}, status=404)

    if scan_type == "nmap":
        run_nmap_scan.delay(session.id)
    elif scan_type == "gobuster":
        gobuster_scan.delay(session.id)
    elif scan_type == "amass":
        amass_scan.delay(session.id)
    elif scan_type == "httpx":
        httpx_scan.delay(session.id)
    elif scan_type == "whois":
        passive_whois_scan.delay(session.id)
    elif scan_type == "dns":
        passive_dns_scan.delay(session.id)
    elif scan_type == "crtsh":
        passive_cert_scan.delay(session.id)
    elif scan_type == "shodan" and api_key:
        shodan_scan.delay(session.id, api_key)
    else:
        return Response({"error": "Invalid scan type or missing API key"}, status=400)

    return Response({"message": f"{scan_type} scan started."})


# ---------------------------
# Get Scan Results
# ---------------------------

@api_view(["GET"])
def get_scan_results(request, session_id):
    """Get decrypted scan results for a session"""
    try:
        session = ScanSession.objects.get(id=session_id)
    except ScanSession.DoesNotExist:
        return Response({"error": "Session not found"}, status=404)

    scans = []
    for task in session.tasks.all():
        try:
            decrypted_result = cipher.decrypt(task.result.encode()).decode()
        except Exception:
            decrypted_result = "Error decrypting result."

        scans.append({
            "id": task.id,
            "scan_type": task.scan_type,
            "command": task.command,
            "status": task.status,
            "created_at": task.created_at,
            "result": decrypted_result,
        })

    return Response(scans)


# ---------------------------
# Subdomains & Ports
# ---------------------------

@api_view(["GET"])
def get_subdomains(request, session_id):
    subdomains = Subdomain.objects.filter(session_id=session_id).values("domain_name", "discovered_by", "created_at")
    return Response(list(subdomains))


@api_view(["GET"])
def get_ports(request, session_id):
    ports = Port.objects.filter(session_id=session_id).values("port_number", "service", "banner", "created_at")
    return Response(list(ports))


# ---------------------------
# Report Generation
# ---------------------------

@api_view(["GET"])
def generate_report(request, session_id, format="json"):
    """Generate a scan report (JSON or PDF)"""
    try:
        session = ScanSession.objects.get(id=session_id)
    except ScanSession.DoesNotExist:
        return Response({"error": "Session not found"}, status=404)

    # Collect data
    scans = []
    for task in session.tasks.all():
        try:
            decrypted_result = cipher.decrypt(task.result.encode()).decode()
        except Exception:
            decrypted_result = "Error decrypting result."
        scans.append({
            "scan_type": task.scan_type,
            "status": task.status,
            "result": decrypted_result,
        })

    report_data = {
        "target": session.target.domain,
        "session": session.name,
        "scans": scans,
        "subdomains": list(session.subdomains.all().values("domain_name", "discovered_by")),
        "ports": list(session.ports.all().values("port_number", "service", "banner")),
    }

    # JSON Export
    if format == "json":
        return JsonResponse(report_data, safe=False)

    # PDF Export
    elif format == "pdf":
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        from io import BytesIO

        buffer = BytesIO()
        pdf = canvas.Canvas(buffer, pagesize=letter)
        pdf.setTitle(f"Recon Report - {session.target.domain}")

        pdf.drawString(50, 750, f"Recon Report for {session.target.domain}")
        pdf.drawString(50, 730, f"Session: {session.name}")

        y = 700
        for scan in scans:
            pdf.drawString(50, y, f"{scan['scan_type']} ({scan['status']}):")
            y -= 15
            pdf.drawString(70, y, scan["result"][:200] + "...")
            y -= 40

        pdf.save()
        buffer.seek(0)
        return HttpResponse(buffer, content_type="application/pdf")

    else:
        return Response({"error": "Invalid report format"}, status=400)


@api_view(["POST"])
def start_recon(request, session_id):
    scan_type = request.data.get("scan_type")
    api_key = request.data.get("api_key", None)

    if scan_type == "active":
        run_active_recon.delay(session_id)
    elif scan_type == "passive":
        run_passive_recon.delay(session_id, api_key)
    elif scan_type == "complete":
        run_complete_scan.delay(session_id, api_key)
    else:
        return Response({"error": "Invalid scan type"}, status=400)

    return Response({"message": f"{scan_type.capitalize()} recon started."})
