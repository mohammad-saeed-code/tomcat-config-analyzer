# tomcat-config-analyzer
A lightweight, automated security analyzer for **Apache Tomcat configuration hardening**.  
This tool scans key Tomcat config files and identifies misconfigurations, insecure defaults, weak authentication setups, missing hardening rules, and unsafe deployment practices.

Built for security engineers, SOC analysts, DevOps teams, and auditors who need fast, accurate Tomcat configuration validation.

---

## 🔒 Overview
Apache Tomcat is widely used across enterprise environments—but its default configuration is not secure.  
This project helps you quickly evaluate a Tomcat installation by analyzing:

- `server.xml`
- `web.xml`
- `tomcat-users.xml`
- Additional optional configuration files

For each issue, the analyzer provides **clear explanations**, **risk context**, and **recommended hardening actions**.

---

## 🚀 Features
- ✔️ Detects insecure connectors  
- ✔️ Validates SSL/TLS configuration  
- ✔️ Checks for exposed management interfaces  
- ✔️ Flags weak or default Tomcat credentials  
- ✔️ Identifies dangerous HTTP methods  
- ✔️ Reviews session management security  
- ✔️ Analyzes role-based access configurations  
- ✔️ CLI output or JSON report  
- ✔️ Supports Tomcat 7/8/9/10+  
- ✔️ Easy to integrate into CI/CD pipelines  

---

## 📥 Installation
```bash
git clone https://github.com/mohammad-saeed-code/tomcat-config-analyzer
cd tomcat-config-analyzer
sudo python tomcat-config-analyzer tomcat_base -o <output file>
