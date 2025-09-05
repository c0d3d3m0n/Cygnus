<div align="center">

  ____    __     __    ____     _   _     _   _     ____    
 / ___|   \ \   / /   / ___|   | \ | |   | | | |   / ___|   
| |        \ \ / /   | |  _    |  \| |   | | | |   \___ \   
| |         \ V /    | | | |   | . ` |   | | | |    ___) |  
| |___       | |     | |_| |   | |\  |   | |_| |   |____/   
 \____|      |_|      \____|   |_| \_|    \___/             



A next-generation web application reconnaissance framework.

</div>

Cygnus is a powerful and comprehensive web application reconnaissance framework designed to automate and streamline the process of information gathering. It combines both passive and active scanning techniques to provide security professionals, penetration testers, and bug bounty hunters with a holistic view of a target's web presence.

🚀 Key Features
Dual Reconnaissance Modes: Seamlessly switch between passive (non-intrusive) and active (intrusive) scanning methodologies.

Intuitive Web Interface: A clean, modern, and user-friendly web dashboard to manage scans, view results, and generate reports.

Extensible Module System: Easily add new scanning modules and tools to expand Cygnus's capabilities.

Comprehensive Reporting: Generate detailed and actionable reports in various formats (JSON, PDF, HTML).

Target Scoping: Define and manage the scope of your reconnaissance to keep scans focused and organized.

API-Driven: A robust API for integrating Cygnus into your existing security workflows and toolchains.

Task Scheduling: Schedule scans to run at specific times for continuous monitoring.

scanners Scanning Capabilities
Cygnus is equipped with a wide array of scanning modules to ensure thorough reconnaissance.

passive Passive Reconnaissance (Non-Intrusive)
Subdomain Enumeration: Discovers subdomains using search engines, public datasets, and DNS analytics.

WHOIS & DNS Lookup: Gathers domain registration information, nameservers, and DNS records (A, MX, TXT, etc.).

Technology Stack Identification: Identifies web technologies like CMS, frameworks, web servers, and analytics tools.

Shodan/Censys/BinaryEdge Integration: Queries IoT search engines for exposed services and device information.

GitHub/GitLab Dorking: Scans public code repositories for sensitive information and leaked credentials.

Wayback Machine Analysis: Fetches historical URLs and content from the Internet Archive.

Certificate Transparency Logs: Mines CT logs for related domains and subdomains.

🎯 Active Reconnaissance (Intrusive)
Port Scanning: Actively probes for open TCP/UDP ports using techniques like SYN, TCP Connect, and UDP scans.

Web Server & Directory Probing: Discovers hidden files, directories, and administrative panels.

Screenshotting: Takes screenshots of discovered web pages for quick visual analysis.

HTTP Header Analysis: Fetches and analyzes security headers (CSP, HSTS, CORS) for potential misconfigurations.

Vulnerability Scanning (Light): Identifies low-hanging fruit vulnerabilities like outdated server software and exposed panels.

DNS Zone Transfer: Attempts to perform a DNS zone transfer to enumerate all DNS records.

Subdomain Takeover Detection: Actively checks for dangling DNS records pointing to services that can be taken over.

🛠️ Tech Stack
Backend: Python (FastAPI/Django), Celery

Frontend: React.js / Vue.js, Tailwind CSS

Database: PostgreSQL / MongoDB

Cache: Redis

Containerization: Docker, Docker Compose

⚙️ Getting Started
Prerequisites
Python 3.8+

Node.js & npm

Docker & Docker Compose

Git

Installation
Clone the repository:

git clone [https://github.com/your-username/cygnus.git](https://github.com/your-username/cygnus.git)
cd cygnus

Configuration:

Copy the example environment file: cp .env.example .env

Open the .env file and add your necessary API keys (Shodan, GitHub, etc.) and configure your database settings.

Build and run with Docker Compose:

docker-compose up --build -d

Access the application:

The Cygnus web interface will be available at http://localhost:3000.

The API documentation will be available at http://localhost:8000/docs.

🖥️ Usage
Login: Access the web interface and create an account or log in.

Create a Project/Workspace: Organize your scans by creating a new project.

Define a Target: Add a new target domain (e.g., example.com) to your project.

Launch a Scan:

Select the target.

Choose a scan profile (e.g., "Passive Only", "Full Recon", or a custom selection of modules).

Click "Start Scan".

View Results: Once the scan is complete, the results will be populated in the dashboard, where you can filter, search, and analyze the findings.

📜 Reporting
To generate a report, navigate to the "Reports" section of a completed scan. You can choose from various formats and customize the data you want to include.

🤝 Contributing
Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are greatly appreciated.

Please refer to our CONTRIBUTING.md file for guidelines on how to contribute to the project.

🗺️ Roadmap
[ ] Integration with more third-party services (VirusTotal, AlienVault OTX).

[ ] Advanced visual graphing of target infrastructure.

[ ] Team collaboration features (multi-user projects, role-based access).

[ ] Custom alerting and notifications (Slack, Discord, Email).

[ ] Full-text search across all collected data.

See the open issues for a full list of proposed features (and known issues).

📄 License
Distributed under the MIT License. See LICENSE for more information.

🙏 Acknowledgments
Cygnus is built upon the shoulders of giants. We would like to thank the developers of the following open-source tools that are integrated into this framework:

Nmap

subfinder

httpx

And many more...

<div align="center">
Made with ❤️ by Your Name / Your Team
</div>
