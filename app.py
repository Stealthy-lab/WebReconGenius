from flask import Flask, render_template, request
import socket
import subprocess
import httpx
import os
from bs4 import BeautifulSoup

app = Flask(__name__)

def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return None

def run_nmap(ip):
    try:
        result = subprocess.check_output(["nmap", "-Pn", "-T4", "-sV", ip], stderr=subprocess.DEVNULL)
        return result.decode()
    except:
        return "Error ejecutando Nmap."

def run_whatweb(domain):
    try:
        result = subprocess.check_output(["whatweb", domain], stderr=subprocess.DEVNULL)
        return result.decode()
    except:
        return "Error ejecutando WhatWeb."

def run_subfinder(domain):
    try:
        result = subprocess.check_output(["subfinder", "-d", domain, "-silent"], stderr=subprocess.DEVNULL)
        return result.decode().splitlines()
    except:
        return []

def fetch_headers(domain):
    try:
        r = httpx.get(f"http://{domain}", timeout=10)
        return dict(r.headers)
    except:
        return {}

def detect_login_panel(domain):
    try:
        url = f"http://{domain}"
        response = httpx.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        return bool(soup.find('input', {'type': 'password'}))
    except:
        return False

def check_common_backups(domain):
    common_files = ["/backup.zip", "/db.sql", "/site.bak", "/website.tar.gz"]
    found = []
    for path in common_files:
        try:
            url = f"http://{domain}{path}"
            r = httpx.head(url, timeout=5)
            if r.status_code == 200:
                found.append(url)
        except:
            continue
    return found

def detect_waf(headers):
    waf_signatures = ["cloudflare", "akamai", "sucuri", "incapsula", "aws", "imperva"]
    joined = " ".join([f"{k}: {v}" for k, v in headers.items()]).lower()
    for sig in waf_signatures:
        if sig in joined:
            return sig.capitalize()
    return None

def analyze(domain, ip, nmap, techs, subdomains, headers, login_panel, backups, waf):
    resumen = []

    if ip:
        resumen.append(f"Dirección IP resuelta: {ip}.")
    else:
        resumen.append("No se pudo resolver la IP del dominio.")

    if subdomains:
        resumen.append(f"Se encontraron {len(subdomains)} subdominios.")
    else:
        resumen.append("No se encontraron subdominios.")

    tech_line = techs.strip().split(" ", 1)[1] if " " in techs else techs
    tech_names = [t.strip() for t in tech_line.split(",")] if "," in tech_line else [tech_line.strip()]
    tech_names = list(filter(None, tech_names))
    if tech_names:
        resumen.append(f"Tecnologías detectadas: {', '.join(tech_names[:5])}.")
    else:
        resumen.append("No se detectaron tecnologías.")

    open_ports = nmap.lower().count("open")
    resumen.append(f"Se encontraron {open_ports} puertos abiertos con Nmap.")

    if login_panel:
        resumen.append("Se detectó un panel de login en la página principal.")
    else:
        resumen.append("No se detectó un panel de login.")

    if waf:
        resumen.append(f"Se detectó un WAF: {waf}.")
    else:
        resumen.append("No se detectó WAF.")

    if backups:
        resumen.append(f"Archivos de respaldo detectados: {len(backups)} ({', '.join(backups)}).")
    else:
        resumen.append("No se encontraron archivos de respaldo accesibles.")

    if "X-Frame-Options" not in headers:
        resumen.append("⚠️ Falta el encabezado de seguridad X-Frame-Options.")
    if "Server" in headers:
        resumen.append(f"🛰️ Servidor web: {headers['Server']}.")

    return "\n".join(resumen)

def export_report(domain, ip, nmap, techs, subdomains, headers, summary, login_panel, backups, waf):
    report_md = f"""# Informe WebReconGenius

**Dominio:** {domain}  
**IP:** {ip or 'No resuelta'}  
**Subdominios encontrados:** {len(subdomains)}

## Tecnologías detectadas
{techs.strip()}

## Puertos abiertos
{nmap.strip()}

## Subdominios
{chr(10).join(['- ' + s for s in subdomains]) or 'Ninguno'}

## Headers HTTP
{chr(10).join(['- ' + k + ': ' + v for k, v in headers.items()]) or 'Ninguno'}

## Seguridad
- WAF: {waf or 'No detectado'}
- Login panel: {'Detectado' if login_panel else 'No detectado'}
- Backups encontrados: {chr(10).join(['- ' + b for b in backups]) if backups else 'Ninguno'}

## Resumen general
{summary}
"""

    # Guardar .md
    report_path_md = os.path.join("reports", domain.replace(".", "_"), "report.md")
    os.makedirs(os.path.dirname(report_path_md), exist_ok=True)
    with open(report_path_md, "w") as rf:
        rf.write(report_md)

    # Guardar HTML
    html_body = f"""<html><body style='background:black;color:#0f0;font-family:monospace;padding:20px;'>
<h1>Informe - WebReconGenius</h1>
<pre>{report_md}</pre></body></html>"""
    with open(report_path_md.replace(".md", ".html"), "w") as rf:
        rf.write(html_body)

    return report_path_md

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        domain = request.form["domain"].strip()
        ip = resolve_ip(domain)
        nmap_result = run_nmap(ip) if ip else ""
        techs = run_whatweb(domain)
        subdomains = run_subfinder(domain)
        headers = fetch_headers(domain)
        login_panel = detect_login_panel(domain)
        backups = check_common_backups(domain)
        waf = detect_waf(headers)
        summary = analyze(domain, ip, nmap_result, techs, subdomains, headers, login_panel, backups, waf)

        export_report(domain, ip, nmap_result, techs, subdomains, headers, summary, login_panel, backups, waf)

        return render_template("result.html", domain=domain, ip=ip, nmap=nmap_result,
                               techs=techs, subdomains=subdomains, headers=headers,
                               summary=summary, login_panel=login_panel, backups=backups, waf=waf)
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
