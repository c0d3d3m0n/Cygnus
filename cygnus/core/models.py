from django.db import models

class Target(models.Model):
    """
    Stores the target domain or IP for reconnaissance.
    """
    name = models.CharField(max_length=255)
    domain = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.domain


class Scan(models.Model):
    """
    Stores results of active or passive scans.
    """
    target = models.ForeignKey(Target, on_delete=models.CASCADE, related_name="scans")
    scan_type = models.CharField(max_length=50)  # e.g., 'nmap', 'whois', 'crtsh'
    command = models.TextField(blank=True, null=True)  # For active scans
    result = models.TextField(blank=True, null=True)  # Stores API/command output
    status = models.CharField(max_length=20, default="pending")  # pending, success, failed
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.scan_type} scan for {self.target.domain}"
