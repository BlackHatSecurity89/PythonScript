#!/usr/bin/env python3
"""
Hardening Auditor - Auditor básico de hardening CIS/NIST
Uso exclusivo en entornos autorizados / defensivos.

Funciones:
- Validación de configuraciones Windows/Linux
- Revisión de políticas débiles
- Revisión de política de contraseñas
- Estado de firewall
- Detección de servicios inseguros
- Exportación JSON

Compatible con:
- Linux
- Windows (parcial, usando comandos nativos)
############################################################
Incluye auditorías para:
Windows / Linux
Detección automática del sistema operativo
Firewall
Linux: UFW / Firewalld / iptables
Windows: Windows Defender Firewall
Políticas de contraseña
Longitud mínima
Expiración / rotación
Configuración de cuentas
Servicios inseguros

Detecta si están habilitados:

Telnet
FTP
RSH
RLogin
TFTP
Rexec
Hardening CIS/NIST
Revisión SSH Root Login
Validación SSH seguro
Validación UAC Windows
Validación RDP habilitado/deshabilitado
Reporte JSON
Exporta resultados estructurados
#################################################################################
"""

import os
import json
import platform
import subprocess
from datetime import datetime

# ==============================
# CONFIGURACIÓN
# ==============================
INSECURE_SERVICES = [
    "telnet",
    "ftp",
    "rsh",
    "rlogin",
    "tftp",
    "rexec"
]

MIN_PASSWORD_LENGTH = 12

# ==============================
# UTILIDADES
# ==============================
def run_command(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout.strip()
    except Exception as e:
        return f"ERROR: {e}"

# ==============================
# FIREWALL
# ==============================
def check_firewall_linux():
    ufw = run_command("ufw status")
    firewalld = run_command("systemctl is-active firewalld")
    iptables = run_command("iptables -L")

    return {
        "ufw": ufw,
        "firewalld": firewalld,
        "iptables_rules_present": bool(iptables and "Chain" in iptables)
    }


def check_firewall_windows():
    output = run_command("netsh advfirewall show allprofiles")
    return {
        "enabled": "ON" in output.upper(),
        "raw": output[:1000]
    }

# ==============================
# POLÍTICA DE CONTRASEÑAS
# ==============================
def check_password_policy_linux():
    findings = {}
    try:
        with open("/etc/login.defs", "r") as f:
            content = f.read()

        for line in content.splitlines():
            if "PASS_MAX_DAYS" in line and not line.startswith("#"):
                findings["PASS_MAX_DAYS"] = line.split()[-1]
            if "PASS_MIN_DAYS" in line and not line.startswith("#"):
                findings["PASS_MIN_DAYS"] = line.split()[-1]
            if "PASS_MIN_LEN" in line and not line.startswith("#"):
                findings["PASS_MIN_LEN"] = line.split()[-1]

        findings["password_length_ok"] = int(findings.get("PASS_MIN_LEN", 0)) >= MIN_PASSWORD_LENGTH
    except Exception as e:
        findings["error"] = str(e)

    return findings


def check_password_policy_windows():
    output = run_command("net accounts")
    return {"raw": output}

# ==============================
# SERVICIOS INSEGUROS
# ==============================
def check_services_linux():
    output = run_command("systemctl list-units --type=service --all")
    findings = []

    for svc in INSECURE_SERVICES:
        if svc in output.lower():
            findings.append(svc)

    return findings


def check_services_windows():
    output = run_command("sc query state= all")
    findings = []

    for svc in INSECURE_SERVICES:
        if svc in output.lower():
            findings.append(svc)

    return findings

# ==============================
# CONFIGURACIONES BÁSICAS CIS/NIST
# ==============================
def check_linux_security_configs():
    findings = {}

    findings["root_ssh_disabled"] = False
    findings["ssh_protocol_secure"] = False

    try:
        with open("/etc/ssh/sshd_config", "r") as f:
            sshd = f.read()

        if "PermitRootLogin no" in sshd:
            findings["root_ssh_disabled"] = True

        if "Protocol 2" in sshd or "PubkeyAuthentication yes" in sshd:
            findings["ssh_protocol_secure"] = True

    except Exception as e:
        findings["ssh_check_error"] = str(e)

    return findings


def check_windows_security_configs():
    findings = {}

    uac = run_command('reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA')
    findings["uac_enabled"] = "0x1" in uac

    rdp = run_command('reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections')
    findings["rdp_disabled"] = "0x1" in rdp

    return findings

# ==============================
# AUDITORÍA PRINCIPAL
# ==============================
def run_audit():
    os_type = platform.system()
    report = {
        "timestamp": str(datetime.now()),
        "hostname": platform.node(),
        "os": os_type,
        "findings": {}
    }

    if os_type == "Linux":
        report["findings"]["firewall"] = check_firewall_linux()
        report["findings"]["password_policy"] = check_password_policy_linux()
        report["findings"]["insecure_services"] = check_services_linux()
        report["findings"]["security_configs"] = check_linux_security_configs()

    elif os_type == "Windows":
        report["findings"]["firewall"] = check_firewall_windows()
        report["findings"]["password_policy"] = check_password_policy_windows()
        report["findings"]["insecure_services"] = check_services_windows()
        report["findings"]["security_configs"] = check_windows_security_configs()

    else:
        report["error"] = "OS no soportado"

    return report

# ==============================
# EXPORTAR
# ==============================
def export_report(report, filename="hardening_report.json"):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)
    return filename

# ==============================
# MAIN
# ==============================
def main():
    print("=" * 60)
    print(" Hardening Auditor - CIS/NIST Compliance Checker")
    print("=" * 60)

    report = run_audit()
    file = export_report(report)

    print(json.dumps(report, indent=4))
    print(f"\n[✓] Reporte generado: {os.path.abspath(file)}")

if __name__ == "__main__":
    main()
