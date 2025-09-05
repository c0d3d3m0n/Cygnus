from django.db import models

# class Target(models.Model):
#     """
#     Stores the target domain or IP for reconnaissance.
#     """
#     name = models.CharField(max_length=255)
#     domain = models.CharField(max_length=255, unique=True)
#     created_at = models.DateTimeField(auto_now_add=True)

#     def __str__(self):
#         return self.domain


# class Scan(models.Model):
#     """
#     Stores results of active or passive scans.
#     """
#     target = models.ForeignKey(Target, on_delete=models.CASCADE, related_name="scans")
#     scan_type = models.CharField(max_length=50)  # e.g., 'nmap', 'whois', 'crtsh'
#     command = models.TextField(blank=True, null=True)  # For active scans
#     result = models.TextField(blank=True, null=True)  # Stores API/command output
#     status = models.CharField(max_length=20, default="pending")  # pending, success, failed
#     created_at = models.DateTimeField(auto_now_add=True)

#     def __str__(self):
#         return f"{self.scan_type} scan for {self.target.domain}"



# class Subdomain(models.Model):
#     """
#     Stores discovered subdomains for a target.
#     """
#     target = models.ForeignKey(Target, on_delete=models.CASCADE, related_name="subdomains")
#     name = models.CharField(max_length=255)
#     source = models.CharField(max_length=50)  # e.g., 'crtsh', 'amass', 'sublist3r'
#     created_at = models.DateTimeField(auto_now_add=True)

#     def __str__(self):
#         return self.name


class Target(models.Model):
    domain = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.domain

class ScanSession(models.Model):
    target = models.ForeignKey(Target, on_delete=models.CASCADE, related_name="sessions")
    name = models.CharField(max_length=100, default="Default Session")
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.name} for {self.target.domain}"


class ScanTask(models.Model):
    session = models.ForeignKey(ScanSession, on_delete=models.CASCADE, related_name="tasks")
    scan_type = models.CharField(max_length=50)  # nmap, subfinder, httpx, shodan
    command = models.TextField(blank=True, null=True)
    result = models.TextField()   # encrypted before saving
    status = models.CharField(max_length=20, default="pending")  # pending, running, success, failed
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.scan_type} on {self.session.target.domain}"


class Subdomain(models.Model):
    session = models.ForeignKey(ScanSession, on_delete=models.CASCADE, related_name="subdomains")
    domain_name = models.CharField(max_length=255)
    discovered_by = models.CharField(max_length=100)  # amass, subfinder, crt.sh
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("session", "domain_name")

    def __str__(self):
        return self.domain_name


class Port(models.Model):
    session = models.ForeignKey(ScanSession, on_delete=models.CASCADE, related_name="ports")
    subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE, null=True, blank=True)
    port_number = models.IntegerField()
    service = models.CharField(max_length=100, blank=True, null=True)
    banner = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("session", "port_number", "subdomain")
