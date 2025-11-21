from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn
from rich import box
import os
import xml.etree.ElementTree as ET
import json
import re
import stat
import pwd
import grp
import argparse
import sys

def check_shutdown_port(conf_dir):

    name = "Shutdown port disabled"
    server_xml = os.path.join(conf_dir, "server.xml")
    try:
        root = ET.parse(server_xml).getroot()
        server = root if root.tag == "Server" else root.find("Server")
        if server is None:
            return {"name": name, "status": "ERROR", "score": 0.0, "evidence": "No <Server> element"}
        port = (server.get("port") or "").strip()
        addr = (server.get("address") or "0.0.0.0").strip()

        if port == "-1":
            return {"name": name, "status": "COMPLIANT", "score": 1.0, "evidence": "Server port=-1 (disabled)"}
        if addr in {"127.0.0.1", "localhost", "::1"}:
            return {"name": name, "status": "PARTIAL", "score": 0.5, "evidence": f"Shutdown port={port} bound to {addr}"}
        return {"name": name, "status": "NON-COMPLIANT", "score": 0.0, "evidence": f"Shutdown port={port} (should be -1)"}
    except Exception as e:
        return {"name": name, "status": "ERROR", "score": 0.0, "evidence": f"Parse error: {e}"}




def check_error_reporting_hardened(conf_dir):
    name = "Error reporting hardened (ErrorReportValve)"
    server_xml = os.path.join(conf_dir, "server.xml")

    if not os.path.isfile(server_xml):
        return {
            "name": name,
            "status": "ERROR",
            "score": 0.0,
            "evidence": f"server.xml not found: {server_xml}",
        }

    try:
        root = ET.parse(server_xml).getroot()
    except Exception as e:
        return {
            "name": name,
            "status": "ERROR",
            "score": 0.0,
            "evidence": f"Parse error: {e}",
        }

    valves = root.findall(".//Valve")
    err_valves = [v for v in valves if "ErrorReportValve" in (v.get("className") or "")]

    evid = []
    if not err_valves:
        return {
            "name": name,
            "status": "PARTIAL",
            "score": 0.5,
            "evidence": "No explicit ErrorReportValve found; default behaviour may leak stack traces/server info",
        }

    all_hardened = True
    any_insecure = False

    def _is_false(val: str) -> bool:
        v = (val or "").strip().lower()
        return v in {"false", "0", "no"}

    def _is_true_or_default(val: str) -> bool:
        v = (val or "").strip().lower()
        return v in {"true", "1", "yes", ""}

    for v in err_valves:
        sr_raw = v.get("showReport")
        si_raw = v.get("showServerInfo")

        sr_false = _is_false(sr_raw)
        si_false = _is_false(si_raw)

        if sr_false and si_false:
            evid.append("ErrorReportValve hardened (showReport=false, showServerInfo=false)")
            continue

        all_hardened = False
        details = []
        if _is_true_or_default(sr_raw):
            details.append(f"showReport={sr_raw if sr_raw is not None else '(default)'}")
        if _is_true_or_default(si_raw):
            details.append(f"showServerInfo={si_raw if si_raw is not None else '(default)'}")

        if details:
            any_insecure = True
            evid.append("Insecure ErrorReportValve: " + ", ".join(details))
        else:
            evid.append("ErrorReportValve present but configuration ambiguous")

    if any_insecure:
        return {
            "name": name,
            "status": "NON-COMPLIANT",
            "score": 0.0,
            "evidence": "; ".join(evid),
        }

    if all_hardened:
        return {
            "name": name,
            "status": "COMPLIANT",
            "score": 1.0,
            "evidence": "; ".join(evid) if evid else "All ErrorReportValve instances hardened",
        }

    return {
        "name": name,
        "status": "PARTIAL",
        "score": 0.5,
        "evidence": "; ".join(evid),
    }

def check_tls_keystore_config(tomcat_base, conf_dir):
    name = "TLS keystore correctly configured"
    server_xml = os.path.join(conf_dir, "server.xml")

    def _resolve_path(p):
        if not p:
            return None
        if os.path.isabs(p):
            return p
        return os.path.normpath(os.path.join(conf_dir, p))

    try:
        root = ET.parse(server_xml).getroot()
        connectors = root.findall(".//Connector")
    except Exception as e:
        return {"name": name, "status": "ERROR", "score": 0.0, "evidence": f"Parse error: {e}"}

    https = []
    for c in connectors:
        if (c.get("SSLEnabled") or "").lower() == "true" or \
           c.get("sslEnabledProtocols") or c.get("sslProtocol") or \
           (c.get("scheme") or "").lower() == "https" or \
           (c.get("secure") or "").lower() == "true":
            https.append(c)

    if not https:
        return {"name": name, "status": "COMPLIANT", "score": 1.0, "evidence": "No HTTPS connectors (nothing to check)"}

    had_cert_block = False
    bad_pwd = False
    missing_file = False
    partial_unknown = False
    evid = []

    for c in https:
        addr = (c.get("address") or "0.0.0.0")
        port = (c.get("port") or "?")
        shcs = c.findall(".//SSLHostConfig")
        if not shcs:
            partial_unknown = True
            evid.append(f"{addr}:{port} - no <SSLHostConfig> (keystore not explicitly referenced)")
            continue

        for shc in shcs:
            certs = shc.findall(".//Certificate")
            if not certs:
                partial_unknown = True
                evid.append(f"{addr}:{port} - <SSLHostConfig> without <Certificate> (cannot verify file)")
                continue

            for cert in certs:
                had_cert_block = True
                kfile = _resolve_path(cert.get("certificateKeystoreFile"))
                kpass = (cert.get("certificateKeystorePassword") or "").strip()
                typ = (cert.get("type") or "").strip()
                if not kfile:
                    partial_unknown = True
                    evid.append(f"{addr}:{port} - Certificate without certificateKeystoreFile")
                else:
                    if not os.path.isfile(kfile):
                        missing_file = True
                        evid.append(f"{addr}:{port} - keystore not found: {kfile}")
                    else:
                        evid.append(f"{addr}:{port} - keystore found: {kfile}")

                if kpass == "" or kpass is None:
                    partial_unknown = True
                    evid.append(f"{addr}:{port} - keystore password not specified")
                elif kpass.lower() == "changeit":
                    bad_pwd = True
                    evid.append(f"{addr}:{port} - keystore password is default 'changeit'")
                if typ:
                    evid.append(f"{addr}:{port} - type={typ}")

    if bad_pwd:
        return {"name": name, "status": "NON-COMPLIANT", "score": 0.0,
                "evidence": "; ".join(evid) if evid else "Keystore password 'changeit'"}
    if missing_file:
        return {"name": name, "status": "PARTIAL", "score": 0.5,
                "evidence": "; ".join(evid) if evid else "Keystore file(s) missing"}
    if partial_unknown or not had_cert_block:
        return {"name": name, "status": "PARTIAL", "score": 0.5,
                "evidence": "; ".join(evid) if evid else "HTTPS without verifiable keystore configuration"}

    return {"name": name, "status": "COMPLIANT", "score": 1.0,
            "evidence": "; ".join(evid) if evid else "Keystore present with non-default password"}


def check_password_hashing_enabled(conf_dir):
    name = "Password hashing enabled (CredentialHandler)"
    server_xml = os.path.join(conf_dir, "server.xml")
    tusers_xml = os.path.join(conf_dir, "tomcat-users.xml")

    users_present = False
    tusers_exists = os.path.isfile(tusers_xml)
    if tusers_exists:
        try:
            tu_root = ET.parse(tusers_xml).getroot()
            users_present = len(tu_root.findall(".//user")) > 0
        except Exception as e:
            users_present = True

    try:
        root = ET.parse(server_xml).getroot()
    except Exception as e:
        return {"name": name, "status": "ERROR", "score": 0.0, "evidence": f"Parse error in server.xml: {e}"}

    handlers = root.findall(".//Realm/CredentialHandler")
    algo = None
    if handlers:
        for h in handlers:
            a = (h.get("algorithm") or "").strip().upper()
            if a:
                algo = a
                break

    strong_algos = {"SHA-256", "SHA-512"}
    evid = []
    if tusers_exists:
        evid.append("tomcat-users.xml present")
    else:
        evid.append("tomcat-users.xml not present (external realm assumed)")

    if algo:
        evid.append(f"CredentialHandler algorithm={algo}")
    else:
        evid.append("CredentialHandler not found in <Realm> chain")

    if not tusers_exists:
        return {"name": name, "status": "COMPLIANT", "score": 1.0, "evidence": "; ".join(evid)}

    if not users_present:
        
        if algo in strong_algos:
            return {"name": name, "status": "COMPLIANT", "score": 1.0, "evidence": "; ".join(evid)}
        return {"name": name, "status": "PARTIAL", "score": 0.5, "evidence": "; ".join(evid) + "; no users defined"}

    
    if algo in strong_algos:
        return {"name": name, "status": "COMPLIANT", "score": 1.0, "evidence": "; ".join(evid)}

    if algo:  
        return {"name": name, "status": "PARTIAL", "score": 0.5,
                "evidence": "; ".join(evid) + " (algorithm not in {SHA-256,SHA-512})"}

    return {"name": name, "status": "NON-COMPLIANT", "score": 0.0,
            "evidence": "; ".join(evid) + " (local users without hashed passwords)"}



def check_https_tls_present(conf_dir):
    name = "HTTPS/TLS connector present"
    server_xml = os.path.join(conf_dir, "server.xml")
    try:
        root = ET.parse(server_xml).getroot()
        connectors = root.findall(".//Connector")

        https_eps = []
        public_http_eps = []

        for c in connectors:
            addr = (c.get("address") or "0.0.0.0").lower()
            port = c.get("port") or "?"
            scheme = (c.get("scheme") or "http").lower()
            ssl_on = (c.get("SSLEnabled") or "").lower() == "true"
            is_https = ssl_on or c.get("sslEnabledProtocols") or c.get("sslProtocol") or scheme == "https"

            if is_https:
                https_eps.append(f"{addr}:{port}")
            else:
                if addr not in {"127.0.0.1", "localhost", "::1"}:
                    public_http_eps.append(f"{addr}:{port}")

        if not https_eps:
            return {
                "name": name,
                "status": "NON-COMPLIANT",
                "score": 0.0,
                "evidence": "No HTTPS/TLS connectors found"
            }

        if public_http_eps:
            return {
                "name": name,
                "status": "PARTIAL",
                "score": 0.5,
                "evidence": f"HTTPS at {', '.join(https_eps)} but public HTTP at {', '.join(public_http_eps)}"
            }

        return {
            "name": name,
            "status": "COMPLIANT",
            "score": 1.0,
            "evidence": "HTTPS connectors: " + ", ".join(https_eps)
        }

    except Exception as e:
        return {"name": name, "status": "ERROR", "score": 0.0, "evidence": f"Parse error: {e}"}


def check_http_disabled_or_redirected(conf_dir):
   
    name = "HTTP disabled or forced to HTTPS"
    server_xml = os.path.join(conf_dir, "server.xml")
    try:
        root = ET.parse(server_xml).getroot()
        connectors = root.findall(".//Connector")

        http_conns = []
        for c in connectors:
            if (c.get("SSLEnabled") or "").lower() == "true" or c.get("sslEnabledProtocols") or c.get("sslProtocol"):
                continue
            scheme = (c.get("scheme") or "http").lower()
            if scheme == "http":
                http_conns.append(c)

        if not http_conns:
            return {"name": name, "status": "COMPLIANT", "score": 1.0, "evidence": "No HTTP connectors"}

        partial_ok = True
        partial_evid = []
        for c in http_conns:
            addr = (c.get("address") or "0.0.0.0").lower()
            port = c.get("port") or "?"
            rport = c.get("redirectPort")
            loopback = addr in {"127.0.0.1", "localhost", "::1"}
            has_redirect = rport is not None and str(rport).isdigit()
            if loopback and has_redirect:
                partial_evid.append(f"{addr}:{port} -> redirectPort {rport}")
            else:
                partial_ok = False
                break

        if partial_ok:
            return {"name": name, "status": "PARTIAL", "score": 0.5,
                    "evidence": "; ".join(partial_evid) if partial_evid else "HTTP restricted to loopback with redirect"}

        summary = ", ".join(f"{(c.get('address') or '0.0.0.0')}:{c.get('port') or '?'}" for c in http_conns)
        return {"name": name, "status": "NON-COMPLIANT", "score": 0.0,
                "evidence": f"Public or unsafe HTTP connectors: {summary}"}

    except Exception as e:
        return {"name": name, "status": "ERROR", "score": 0.0, "evidence": f"Parse error: {e}"}
    

def check_tls_versions_ciphers_hardened(conf_dir):

    name = "TLS versions/ciphers hardened"
    server_xml = os.path.join(conf_dir, "server.xml")
    try:
        root = ET.parse(server_xml).getroot()
        connectors = root.findall(".//Connector")

        https = []
        for c in connectors:
            if (c.get("SSLEnabled") or "").lower() == "true" or \
               c.get("sslEnabledProtocols") or c.get("sslProtocol") or \
               (c.get("scheme") or "").lower() == "https" or \
               (c.get("secure") or "").lower() == "true":
                https.append(c)

        if not https:
            return {"name": name, "status": "NON-COMPLIANT", "score": 0.0, "evidence": "No HTTPS connectors to evaluate"}

        weak_protos = {"sslv3", "tlsv1", "tlsv1.0", "tlsv1.1"}
        good_protos = {"tlsv1.2", "tlsv1.3"}
        weak_cipher_tokens = ["NULL", "RC4", "DES", "3DES", "MD5", "aNULL", "eNULL", "EXPORT", "DES40"]

        any_bad = False
        any_incomplete = False
        notes = []

        for c in https:
            proto_tokens = set()
            cipher_strs = []
            conn_proto = (c.get("sslEnabledProtocols") or c.get("sslProtocol") or "").strip()
            conn_ciph = (c.get("ciphers") or "").strip()
            if conn_proto:
                proto_tokens.update(p.lower() for p in re.split(r"[,\s]+", conn_proto) if p)
            if conn_ciph:
                cipher_strs.append(conn_ciph)

            for shc in c.findall(".//SSLHostConfig"):
                shc_protos = (shc.get("protocols") or "").strip()
                shc_ciphers = (shc.get("ciphers") or "").strip()
                if shc_protos:
                    proto_tokens.update(p.lower() for p in re.split(r"[,\s]+", shc_protos) if p)
                if shc_ciphers:
                    cipher_strs.append(shc_ciphers)

            if not proto_tokens:
                any_incomplete = True
                notes.append("Protocols unspecified (Connector/SSLHostConfig)")

            badp = sorted(proto_tokens & weak_protos)
            if badp:
                any_bad = True
                notes.append("Weak protos: " + ", ".join(badp))

            unknowns = proto_tokens - good_protos - weak_protos
            if unknowns:
                any_incomplete = True
                notes.append("Unrecognized protos: " + ", ".join(sorted(unknowns)))

            combined_ciphers = " ".join(cipher_strs)
            if any(tok.lower() in combined_ciphers.lower() for tok in weak_cipher_tokens):
                any_bad = True
                notes.append("Weak cipher token present")

        if any_bad:
            return {"name": name, "status": "NON-COMPLIANT", "score": 0.0,
                    "evidence": "; ".join(notes) or "Weak TLS configuration"}
        if any_incomplete:
            return {"name": name, "status": "PARTIAL", "score": 0.5,
                    "evidence": "; ".join(notes) or "Incomplete TLS configuration"}
        return {"name": name, "status": "COMPLIANT", "score": 1.0,
                "evidence": "Only TLSv1.2/1.3 permitted; no weak cipher tokens detected (Connector/SSLHostConfig evaluated)"}
    except Exception as e:
        return {"name": name, "status": "ERROR", "score": 0.0, "evidence": f"Parse error: {e}"}



def check_ajp_disabled_or_secured(conf_dir):

    name = "AJP disabled or secured"
    server_xml = os.path.join(conf_dir, "server.xml")
    try:
        root = ET.parse(server_xml).getroot()
        connectors = root.findall(".//Connector")

        def is_ajp(c):
            proto = (c.get("protocol") or "").lower()
            return "ajp" in proto

        ajp_conns = [c for c in connectors if is_ajp(c)]
        if not ajp_conns:
            return {"name": name, "status": "COMPLIANT", "score": 1.0, "evidence": "No AJP connectors"}

        issues = []
        all_meet_min = True
        evid_partial = []
        for c in ajp_conns:
            addr = (c.get("address") or "0.0.0.0").lower()
            port = c.get("port") or "?"
            loopback = addr in {"127.0.0.1", "localhost", "::1"}
            secret_required = (c.get("secretRequired") or "").lower() == "true"
            secret = c.get("secret")
            if loopback and secret_required and secret:
                evid_partial.append(f"{addr}:{port} (loopback + secretRequired + secret)")
                continue
            all_meet_min = False
            issues.append(
                f"{addr}:{port} loopback={loopback}, secretRequired={secret_required}, secret={'set' if secret else 'missing'}"
            )

        if all_meet_min:
            return {"name": name, "status": "PARTIAL", "score": 0.5,
                    "evidence": "; ".join(evid_partial) if evid_partial else "AJP present but minimally secured"}
        return {"name": name, "status": "NON-COMPLIANT", "score": 0.0,
                "evidence": "; ".join(issues) if issues else "AJP insecure"}
    except Exception as e:
        return {"name": name, "status": "ERROR", "score": 0.0, "evidence": f"Parse error: {e}"}



def check_default_admin_apps_locked(tomcat_base):

    name = "Default/admin webapps removed or locked down"
    webapps_dir = os.path.join(tomcat_base, "webapps")

    if not os.path.isdir(webapps_dir):
        return {
            "name": name,
            "status": "ERROR",
            "score": 0.0,
            "evidence": f"webapps dir not found: {webapps_dir}",
        }

    default_apps = ("docs", "examples")
    present = []
    removed = []

    for app in default_apps:
        app_dir = os.path.join(webapps_dir, app)
        app_war = os.path.join(webapps_dir, f"{app}.war")
        if os.path.isdir(app_dir) or os.path.exists(app_war):
            present.append(app)
        else:
            removed.append(app)

    evidence = []

    if present:
        evidence.append(
            "Default apps present: " + ", ".join(sorted(present))
        )
        if removed:
            evidence.append(
                "Removed defaults: " + ", ".join(sorted(removed))
            )
        return {
            "name": name,
            "status": "NON-COMPLIANT",
            "score": 0.0,
            "evidence": "; ".join(evidence),
        }

    evidence.append(
        "docs/examples removed; manager/host-manager evaluated in "
        "'Manager/Host-Manager access restricted' check."
    )
    return {
        "name": name,
        "status": "COMPLIANT",
        "score": 1.0,
        "evidence": "; ".join(evidence),
    }


def check_manager_access_restricted(tomcat_base):
    name = "Manager/Host-Manager access restricted"
    webapps_dir = os.path.join(tomcat_base, "webapps")
    ctx_dir = os.path.join(tomcat_base, "conf", "Catalina", "localhost")

    if not os.path.isdir(webapps_dir):
        return {
            "name": name,
            "status": "ERROR",
            "score": 0.0,
            "evidence": f"webapps dir not found: {webapps_dir}",
        }

    targets = [
        app for app in ("manager", "host-manager")
        if os.path.exists(os.path.join(webapps_dir, app))
        or os.path.exists(os.path.join(webapps_dir, f"{app}.war"))
    ]

    if not targets:
        return {
            "name": name,
            "status": "COMPLIANT",
            "score": 1.0,
            "evidence": "manager/host-manager not installed",
        }

    evid = []
    scope_scores = []

    def _scope_from_valves(valves):
        loopback_hits = []
        private_hits = []
        rules = []

        for v in valves:
            cls = (v.get("className") or "")
            allow = (v.get("allow") or "")
            deny = (v.get("deny") or "")

            if "RemoteAddrValve" in cls:
                rules.append(f"RemoteAddrValve allow='{allow}' deny='{deny}'")
                if re.search(r"127\.\d+\.\d+\.\d+|::1|0:0:0:0:0:0:0:1", allow):
                    loopback_hits.append("RemoteAddrValve")
                elif (
                    re.search(r"(?:^|[^\\])(10\.)", allow)
                    or re.search(r"(?:^|[^\\])(192\.168\.)", allow)
                    or re.search(r"(?:^|[^\\])(172\.(1[6-9]|2[0-9]|3[0-1])\.)", allow)
                ):
                    private_hits.append("RemoteAddrValve")

            elif "RemoteCIDRValve" in cls:
                cidrs_allow = [
                    x.strip() for x in allow.replace("|", ",").split(",") if x.strip()
                ]
                rules.append(f"RemoteCIDRValve allow='{','.join(cidrs_allow)}' deny='{deny}'")
                norm = [c.lower() for c in cidrs_allow]

                if (
                    "127.0.0.1" in norm
                    or "::1" in norm
                    or "0:0:0:0:0:0:0:1" in norm
                ):
                    loopback_hits.append("RemoteCIDRValve")

                if any(
                    c.startswith("10.")
                    or c.startswith("192.168.")
                    or c.startswith("172.")
                    or "/24" in c
                    or "/16" in c
                    or "/8" in c
                    for c in norm
                ):
                    private_hits.append("RemoteCIDRValve")

        if loopback_hits and not private_hits:
            return "loopback", "; ".join(rules) if rules else "loopback restriction"
        if private_hits:
            return "private", "; ".join(rules) if rules else "private-subnet restriction"
        return (
            "unrestricted" if rules else "missing",
            "; ".join(rules) if rules else "no RemoteAddrValve/RemoteCIDRValve",
        )

    for app in targets:
        ctx_file = os.path.join(ctx_dir, f"{app}.xml")
        if not os.path.isfile(ctx_file):
            evid.append(f"{app}: missing {ctx_file}")
            scope_scores.append("missing")
            continue

        try:
            root = ET.parse(ctx_file).getroot()
        except Exception as e:
            evid.append(f"{app}: parse error in {ctx_file} ({e})")
            scope_scores.append("missing")
            continue

        valves = root.findall(".//Valve")
        scope, details = _scope_from_valves(valves)
        scope_scores.append(scope)

        if scope == "loopback":
            evid.append(f"{app}: access restricted to loopback ({details})")
        elif scope == "private":
            evid.append(f"{app}: restricted to private subnets ({details})")
        elif scope == "unrestricted":
            evid.append(f"{app}: restriction present but effectively broad/public ({details})")
        else:  # "missing"
            evid.append(f"{app}: no network restriction valve ({details})")

    if all(s == "loopback" for s in scope_scores):
        return {
            "name": name,
            "status": "COMPLIANT",
            "score": 1.0,
            "evidence": "; ".join(evid),
        }
    if any(s in ("unrestricted", "missing") for s in scope_scores):
        return {
            "name": name,
            "status": "NON-COMPLIANT",
            "score": 0.0,
            "evidence": "; ".join(evid),
        }
    return {
        "name": name,
        "status": "PARTIAL",
        "score": 0.5,
        "evidence": "; ".join(evid),
    }




def check_tomcat_users_safe(conf_dir):
    name = "tomcat-users.xml safe for production"

    conf_dir_abs = os.path.abspath(conf_dir)
    path = os.path.join(conf_dir_abs, "tomcat-users.xml")

    if not os.path.isdir(conf_dir_abs):
        return {
            "name": name,
            "status": "ERROR",
            "score": 0.0,
            "evidence": f"Config directory does not exist or is not accessible: {conf_dir_abs}"
        }

    if not os.path.isfile(path):
        try:
            entries = ", ".join(sorted(os.listdir(conf_dir_abs)))
        except Exception as e:
            entries = f"<could not list directory: {e}>"

        return {
            "name": name,
            "status": "PARTIAL",
            "score": 0.5,
            "evidence": (
                f"tomcat-users.xml not present. Looked for: {path}. "
                f"Directory contents: {entries}. "
                "Assuming external realm; verify realm configuration separately."
            )
        }

    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except Exception as e:
        return {
            "name": name,
            "status": "ERROR",
            "score": 0.0,
            "evidence": f"Parse error in {path}: {e}"
        }

    m = re.match(r"\{(.*)\}", root.tag)
    if m:
        ns_uri = m.group(1)
        ns = {"t": ns_uri}
        users = root.findall(".//t:user", ns)
    else:
        users = root.findall(".//user")

    if not users:
        return {
            "name": name,
            "status": "COMPLIANT",
            "score": 1.0,
            "evidence": f"No local <user> elements found in {path}. Root tag: {root.tag}"
        }

    admin_role_re = re.compile(r"(manager|admin)", re.IGNORECASE)
    default_usernames = {"tomcat", "admin", "role1", "role2"}

    has_admin = False               
    has_empty_pwd = False
    has_default_user = False
    evid = []

    for u in users:
        username = (u.get("username") or "").strip()
        password = (u.get("password") or "").strip()
        roles_str = (u.get("roles") or "").strip()
        roles = [r.strip().lower() for r in roles_str.split(",") if r.strip()]

        if username.lower() in default_usernames:
            has_default_user = True
            evid.append(f"user '{username}': default username present")

        if password == "":
            has_empty_pwd = True
            evid.append(f"user '{username}': empty or missing password")

        if any(admin_role_re.search(r) for r in roles):
            has_admin = True
            evid.append(
                f"user '{username}': admin/manager-type roles -> {roles_str or '(none)'}"
            )
        else:
            evid.append(
                f"user '{username}': roles={roles_str or '(none)'}"
            )

    if has_empty_pwd or has_default_user:
        reasons = []
        if has_empty_pwd:
            reasons.append("empty or missing passwords")
        if has_default_user:
            reasons.append("default usernames")

        return {
            "name": name,
            "status": "NON-CPLIANT",
            "score": 0.0,
            "evidence": f"File: {path} | " + "; ".join(evid) + " | Issues: " + ", ".join(reasons)
        }

    return {
        "name": name,
        "status": "COMPLIANT",
        "score": 1.0,
        "evidence": f"File: {path} | " + "; ".join(evid)
    }



def check_secure_realm_configuration(conf_dir):

    name = "Secure Realm configuration (LockOutRealm, no UserDatabaseRealm)"
    server_xml = os.path.join(conf_dir, "server.xml")
    try:
        root = ET.parse(server_xml).getroot()
        realms = root.findall(".//Realm")
        if not realms:
            return {
                "name": name,
                "status": "NON-COMPLIANT",
                "score": 0.0,
                "evidence": "No <Realm> elements found"
            }

        classes = [(r.get("className") or "") for r in realms]
        has_lockout = any("LockOutRealm" in c for c in classes)
        has_userdb = any("UserDatabaseRealm" in c for c in classes)

        evid = []
        evid.append("LockOutRealm: " + ("present" if has_lockout else "missing"))
        evid.append("UserDatabaseRealm: " + ("present" if has_userdb else "not present"))

        if has_lockout and not has_userdb:
            return {"name": name, "status": "COMPLIANT", "score": 1.0, "evidence": "; ".join(evid)}
        if has_lockout and has_userdb:
            return {"name": name, "status": "PARTIAL", "score": 0.5, "evidence": "; ".join(evid)}
        return {"name": name, "status": "NON-COMPLIANT", "score": 0.0, "evidence": "; ".join(evid)}

    except Exception as e:
        return {"name": name, "status": "ERROR", "score": 0.0, "evidence": f"Parse error: {e}"}
    


def check_directory_listings_off(conf_dir):

    name = "Directory listings off"
    web_xml = os.path.join(conf_dir, "web.xml")

    if not os.path.isfile(web_xml):
        return {"name": name, "status": "ERROR", "score": 0.0, "evidence": f"web.xml not found: {web_xml}"}

    try:
        root = ET.parse(web_xml).getroot()
        default_servlets = []
        for s in root.findall(".//servlet"):
            sname = (s.findtext("servlet-name") or "").strip().lower()
            sclass = (s.findtext("servlet-class") or "").strip()
            if sname == "default" or "org.apache.catalina.servlets.DefaultServlet" in sclass:
                default_servlets.append(s)

        if not default_servlets:
            return {"name": name, "status": "COMPLIANT", "score": 1.0,
                    "evidence": "DefaultServlet not explicitly defined (uses secure defaults)"}

        for s in default_servlets:
            for ip in s.findall(".//init-param"):
                pname = (ip.findtext("param-name") or "").strip().lower()
                pval = (ip.findtext("param-value") or "").strip().lower()
                if pname == "listings":
                    if pval in {"true", "yes", "1"}:
                        return {"name": name, "status": "NON-COMPLIANT", "score": 0.0,
                                "evidence": "DefaultServlet listings=true"}
                    if pval in {"false", "no", "0"}:
                        return {"name": name, "status": "COMPLIANT", "score": 1.0,
                                "evidence": "DefaultServlet listings=false"}
                    return {"name": name, "status": "NON-COMPLIANT", "score": 0.0,
                            "evidence": f"DefaultServlet listings set to ambiguous value '{pval}'"}

        return {"name": name, "status": "COMPLIANT", "score": 1.0,
                "evidence": "No listings param found (defaults to false)"}

    except Exception as e:
        return {"name": name, "status": "ERROR", "score": 0.0, "evidence": f"Parse error: {e}"}
    


def check_conf_permissions(tomcat_base):
    name = "conf/ ownership & permissions hardened"
    conf_dir = os.path.join(tomcat_base, "conf")

    if not os.path.isdir(conf_dir):
        return {
            "name": name,
            "status": "ERROR",
            "score": 0.0,
            "evidence": f"conf directory not found: {conf_dir}",
        }

    evidence = []
    non_compliant = False
    partial = False
    owners = set()

    def stat_path(path):
        st = os.stat(path)
        mode = stat.S_IMODE(st.st_mode)
        owner = pwd.getpwuid(st.st_uid).pw_name
        group = grp.getgrgid(st.st_gid).gr_name
        return mode, owner, group

    try:
        dmode, downer, dgroup = stat_path(conf_dir)
        owners.add(downer)
        evidence.append(f"conf/: owner={downer}, group={dgroup}, mode={oct(dmode)}")

        if dmode > 0o750:
            non_compliant = True
            evidence.append("conf/: permissions too loose (expected ≤ 0750)")

        if dmode & 0o007:
            non_compliant = True
            if dmode & 0o004:
                evidence.append("conf/: world-readable (other read bit set)")
            if dmode & 0o002:
                evidence.append("conf/: world-writable (!!)")
            if dmode & 0o001:
                evidence.append("conf/: world-executable (other exec bit set)")

    except Exception as e:
        return {
            "name": name,
            "status": "ERROR",
            "score": 0.0,
            "evidence": f"Cannot stat conf/: {e}",
        }

    key_files = ("server.xml", "web.xml", "tomcat-users.xml")
    for fname in key_files:
        fpath = os.path.join(conf_dir, fname)
        if not os.path.exists(fpath):
            evidence.append(f"{fname}: not present")
            partial = True
            continue

        try:
            fmode, fowner, fgroup = stat_path(fpath)
            owners.add(fowner)
            evidence.append(
                f"{fname}: owner={fowner}, group={fgroup}, mode={oct(fmode)}"
            )

            if fmode > 0o640:
                non_compliant = True
                evidence.append(f"{fname}: too permissive (expected ≤ 0640)")

            if fmode & 0o007:
                non_compliant = True
                if fmode & 0o004:
                    evidence.append(f"{fname}: world-readable (other read bit set)")
                if fmode & 0o002:
                    evidence.append(f"{fname}: world-writable (!!)")
                if fmode & 0o001:
                    evidence.append(f"{fname}: world-executable (other exec bit set)")

        except Exception as e:
            non_compliant = True
            evidence.append(f"{fname}: stat error ({e})")

    if "root" in owners:
        partial = True
        evidence.append(
            f"Ownership includes root (owners={sorted(owners)}); "
            "prefer a dedicated non-root service account for all conf/ objects"
        )

    if len(owners) > 1:
        partial = True
        evidence.append(
            f"conf/ and key files are owned by multiple accounts {sorted(owners)}; "
            "prefer a single dedicated service account"
        )

    if non_compliant:
        return {
            "name": name,
            "status": "NON-CPLIANT",
            "score": 0.0,
            "evidence": "; ".join(evidence),
        }

    if partial:
        return {
            "name": name,
            "status": "PARTIAL",
            "score": 0.5,
            "evidence": "; ".join(evidence),
        }

    return {
        "name": name,
        "status": "COMPLIANT",
        "score": 1.0,
        "evidence": "; ".join(evidence),
    }


def check_lockout_realm_bruteforce(conf_dir):

    name = "Brute-force protection (LockOutRealm) configured"
    server_xml = os.path.join(conf_dir, "server.xml")

    if not os.path.isfile(server_xml):
        return {
            "name": name,
            "status": "ERROR",
            "score": 0.0,
            "evidence": f"server.xml not found: {server_xml}"
        }

    try:
        tree = ET.parse(server_xml)
        root = tree.getroot()
    except Exception as e:
        return {
            "name": name,
            "status": "ERROR",
            "score": 0.0,
            "evidence": f"Failed to parse server.xml: {e}"
        }

    lockout_realms = []
    for realm in root.iter("Realm"):
        class_name = realm.get("className", "")
        if class_name.endswith("LockOutRealm"):
            lockout_realms.append(realm)

    if not lockout_realms:
        return {
            "name": name,
            "status": "NON-CPLIANT",
            "score": 0.0,
            "evidence": "No LockOutRealm configured in server.xml"
        }

    evidence_lines = []
    any_compliant = False
    any_partial = False

    max_failure_count = 3        
    min_lockout_time_ms = 36000 

    for idx, lr in enumerate(lockout_realms, start=1):
        prefix = f"LockOutRealm[{idx}]"
        inner_realms = list(lr.findall("Realm"))

        fc_raw = lr.get("failureCount")
        lt_raw = lr.get("lockOutTime")

        has_inner = bool(inner_realms)
        fc_ok = False
        lt_ok = False

        if fc_raw is not None:
            try:
                fc_val = int(fc_raw)
                fc_ok = fc_val <= max_failure_count
                evidence_lines.append(
                    f"{prefix}: failureCount={fc_val} (<= {max_failure_count} required)"
                )
            except ValueError:
                evidence_lines.append(
                    f"{prefix}: failureCount={fc_raw} (not an integer)"
                )
        else:
            evidence_lines.append(f"{prefix}: failureCount not set")

        if lt_raw is not None:
            try:
                lt_val = int(lt_raw)
                lt_ok = lt_val >= min_lockout_time_ms
                evidence_lines.append(
                    f"{prefix}: lockOutTime={lt_val}ms (>= {min_lockout_time_ms}ms required)"
                )
            except ValueError:
                evidence_lines.append(
                    f"{prefix}: lockOutTime={lt_raw} (not an integer)"
                )
        else:
            evidence_lines.append(f"{prefix}: lockOutTime not set")

        if not has_inner:
            evidence_lines.append(
                f"{prefix}: has no inner Realm; LockOutRealm will not actually protect anything"
            )

        if has_inner and fc_ok and lt_ok:
            any_compliant = True
        else:
            any_partial = True

    if any_compliant:
        status = "COMPLIANT"
        score = 1.0
    elif any_partial:
        status = "PARTIAL"
        score = 0.5
    else:
        status = "NON-COMPLIANT"
        score = 0.0

    return {
        "name": name,
        "status": status,
        "score": score,
        "evidence": " | ".join(evidence_lines)
    }


def check_trace_disabled(conf_dir):
    name = "TRACE method disabled on all connectors"
    server_xml = os.path.join(conf_dir, "server.xml")

    if not os.path.isfile(server_xml):
        return {
            "name": name,
            "status": "ERROR",
            "score": 0.0,
            "evidence": f"server.xml not found: {server_xml}",
        }

    try:
        root = ET.parse(server_xml).getroot()
    except ET.ParseError as e:
        return {
            "name": name,
            "status": "ERROR",
            "score": 0.0,
            "evidence": f"XML parse error in {server_xml}: {e}",
        }

    server = root if root.tag == "Server" else root.find("Server")
    if server is None:
        return {
            "name": name,
            "status": "ERROR",
            "score": 0.0,
            "evidence": "No <Server> element found in server.xml",
        }

    evidence = []
    bad = []
    partial = []

    for c in server.iter("Connector"):
        port = c.get("port", "?")
        allow_trace = c.get("allowTrace")

        if allow_trace is None:
            partial.append(f"Connector port {port}: allowTrace not explicitly set")
        elif allow_trace.lower() == "true":
            bad.append(f"Connector port {port}: allowTrace=true")
        else:
            evidence.append(f"Connector port {port}: allowTrace={allow_trace}")

    if bad:
        ev = [
            "TRACE enabled on one or more connectors: " + ", ".join(bad)
        ]
        if partial:
            ev.append(
                "Additionally, some connectors do not explicitly set allowTrace "
                f"(defaults may be safe but CIS recommends explicit false): {', '.join(partial)}"
            )
        return {
            "name": name,
            "status": "NON-COMPLIANT",
            "score": 0.0,
            "evidence": " ; ".join(ev),
        }

    if partial:
        return {
            "name": name,
            "status": "PARTIAL",
            "score": 0.5,
            "evidence": (
                "No connectors explicitly enable TRACE, but some do not set allowTrace. "
                "CIS recommends allowTrace=\"false\" on all connectors: "
                + ", ".join(partial)
            ),
        }

    return {
        "name": name,
        "status": "COMPLIANT",
        "score": 1.0,
        "evidence": (
            "All connectors have allowTrace explicitly set to false: "
            + ", ".join(evidence)
        ),
    }

def check_server_header_hardened(conf_dir):

    name = "Server / X-Powered-By headers hardened"
    server_xml = os.path.join(conf_dir, "server.xml")

    if not os.path.isfile(server_xml):
        return {
            "name": name,
            "status": "ERROR",
            "score": 0.0,
            "evidence": f"server.xml not found: {server_xml}",
        }

    try:
        root = ET.parse(server_xml).getroot()
    except ET.ParseError as e:
        return {
            "name": name,
            "status": "ERROR",
            "score": 0.0,
            "evidence": f"XML parse error in {server_xml}: {e}",
        }

    server_el = root if root.tag == "Server" else root.find("Server")
    if server_el is None:
        return {
            "name": name,
            "status": "ERROR",
            "score": 0.0,
            "evidence": "No <Server> element found in server.xml",
        }

    evidence_ok = []
    partial = []
    bad = []

    for c in server_el.iter("Connector"):
        port = c.get("port", "?")
        server = c.get("server")
        xpowered = c.get("xpoweredBy")

        if xpowered is not None:
            if xpowered.lower() == "true":
                bad.append(f"Connector port {port}: xpoweredBy=true (header enabled)")
            else:
                evidence_ok.append(
                    f"Connector port {port}: xpoweredBy={xpowered} (header disabled)"
                )
        else:
            partial.append(f"Connector port {port}: xpoweredBy not explicitly set")

        if server is None:
            partial.append(
                f"Connector port {port}: 'server' not set (likely default 'Apache Tomcat/*')"
            )
        else:
            low = server.lower()
            if "tomcat" in low or "apache" in low:
                bad.append(
                    f"Connector port {port}: server='{server}' (reveals product/version)"
                )
            else:
                evidence_ok.append(
                    f"Connector port {port}: server='{server}' (custom/non-identifying)"
                )

    if bad:
        ev = [
            "Server / X-Powered-By headers expose product or are explicitly enabled: "
            + "; ".join(bad)
        ]
        if partial:
            ev.append(
                "Some connectors also rely on defaults (no explicit server/xpoweredBy): "
                + "; ".join(partial)
            )
        return {
            "name": name,
            "status": "NON-COMPLIANT",
            "score": 0.0,
            "evidence": " ; ".join(ev),
        }

    if partial:
        return {
            "name": name,
            "status": "PARTIAL",
            "score": 0.5,
            "evidence": (
                "No connectors explicitly expose Tomcat in 'server' and none enable "
                "xpoweredBy, but some rely on defaults. Consider setting a generic "
                "server value and xpoweredBy=\"false\" explicitly on all connectors: "
                + "; ".join(partial)
            ),
        }

    return {
        "name": name,
        "status": "COMPLIANT",
        "score": 1.0,
        "evidence": (
            "All connectors either disable X-Powered-By and use a custom/non-identifying "
            "Server header: "
            + "; ".join(evidence_ok)
        ),
    }


IMPACT_WEIGHTS = {
    "HTTPS/TLS connector present": 2.5,
    "HTTP disabled or forced to HTTPS": 3.0,
    "TLS versions/ciphers hardened": 3.0,
    "Error reporting hardened (ErrorReportValve)": 2.0,
    "TLS keystore correctly configured": 2.0,
    "Secure Realm configuration (LockOutRealm, no UserDatabaseRealm)": 2.5,
    "Password hashing enabled (CredentialHandler)": 2.0,
    "Manager/Host-Manager access restricted": 2.0,
    "Default/admin webapps removed or locked down": 1.5,
    "tomcat-users.xml safe for production": 1.9,
    "conf/ ownership & permissions hardened": 1.7,
    "Brute-force protection (LockOutRealm) configured": 3.0,
    "Directory listings off": 1.0,
    "AJP disabled or secured": 2.5,
    "Shutdown port disabled": 1.0,
    "Manager/Host-Manager access restricted": 1.7,
    "conf/ ownership & permissions hardened": 2.0,
}

def _status_to_unit_score(status: str) -> float:
    if status == "COMPLIANT":
        return 1.0
    if status == "PARTIAL":
        return 0.5
    if status == "NON-COMPLIANT":
        return 0.0
    return 0.25

def _grade_from_ratio(ratio: float):
    if ratio < 0.35:
        return 1, "critical"
    if ratio < 0.60:
        return 2, "weak"
    if ratio < 0.85:
        return 3, "moderate"
    return 4, "hardened"

def main():
    parser = argparse.ArgumentParser(
        description="Apache Tomcat Security Configuration Auditor"
    )
    parser.add_argument(
        "tomcat_base",
        help="Path to Tomcat base directory (e.g. /opt/apache-tomcat-10.1.48)",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Optional output file to save results as JSON",
    )
    args = parser.parse_args()

    tomcat_base = args.tomcat_base.rstrip("/")
    conf_dir = os.path.join(tomcat_base, "conf")

    if not os.path.isdir(conf_dir):
        print(f"[!] Error: Invalid Tomcat base directory: {tomcat_base}")
        sys.exit(1)

    console = Console()

    checks = [
        check_shutdown_port(conf_dir),
        check_https_tls_present(conf_dir),
        check_http_disabled_or_redirected(conf_dir),
        check_tls_versions_ciphers_hardened(conf_dir),
        check_ajp_disabled_or_secured(conf_dir),
        check_error_reporting_hardened(conf_dir),
        check_tls_keystore_config(tomcat_base, conf_dir),
        check_trace_disabled(conf_dir),
        check_server_header_hardened(conf_dir)
        check_default_admin_apps_locked(tomcat_base),
        check_manager_access_restricted(tomcat_base),
        check_password_hashing_enabled(conf_dir),
        check_tomcat_users_safe(conf_dir),
        check_secure_realm_configuration(conf_dir),
        check_lockout_realm_bruteforce(conf_dir),
        check_directory_listings_off(conf_dir),
        check_conf_permissions(tomcat_base),
    ]

    table = Table(
        title="Tomcat Security Hardening Audit",
        style="bold cyan",
        box=box.SIMPLE_HEAVY,
    )
    table.add_column("Check", style="bold white")
    table.add_column("Status", style="bold")
    table.add_column("Score", justify="center", style="white")
    table.add_column("Evidence", overflow="fold")

    color_map = {
        "COMPLIANT": "green",
        "PARTIAL": "yellow",
        "NON-COMPLIANT": "red",
        "ERROR": "bright_black",
    }

    for result in checks:
        color = color_map.get(result["status"], "white")
        table.add_row(
            result["name"],
            f"[{color}]{result['status']}[/{color}]",
            f"{result['score']:.1f}",
            result["evidence"],
        )

    console.print()
    console.print(table)
    console.print()

    total_weight = 0.0
    achieved = 0.0
    problem_points = []
    for r in checks:
        name = r["name"]
        w = IMPACT_WEIGHTS.get(name, 1.0)
        unit = _status_to_unit_score(r["status"])
        total_weight += w
        achieved += (unit * w)

        if r["status"] in ("NON-COMPLIANT", "PARTIAL", "ERROR"):
            if r["status"] == "NON-COMPLIANT":
                penalty = 1.0
            elif r["status"] == "PARTIAL":
                penalty = 0.5
            else:  
                penalty = 0.75
            problem_points.append((w * penalty, r))

    ratio = (achieved / total_weight) if total_weight > 0 else 0.0
    tier, label = _grade_from_ratio(ratio)
    numeric_1_to_4 = 1.0 + (ratio * 3.0)

    with Progress(
        TextColumn("[bold]Overall hardening[/bold]"),
        BarColumn(),
        TextColumn("{task.percentage:>3.0f}%"),
        console=console,
        transient=True,
    ) as progress:
        t = progress.add_task("score", total=100)
        progress.update(t, completed=int(ratio * 100))

    score_text = (
        f"[bold white]Weighted score:[/bold white] {achieved:.2f}/{total_weight:.2f}  "
        f"([bold]{ratio*100:.1f}%[/bold])\n"
        f"[bold white]Final rating (1–4):[/bold white] [bold]{numeric_1_to_4:.2f}[/bold] → "
        f"[bold]{tier} = {label.upper()}[/bold]"
    )
    panel_style = {1: "red", 2: "yellow", 3: "cyan", 4: "green"}.get(tier, "white")
    console.print(Panel(score_text, title="Final Score", border_style=panel_style))

    if problem_points:
        problem_points.sort(key=lambda x: x[0], reverse=True)
        top = problem_points[:5]

        fixes = Table(title="Top Fixes To Prioritize", box=box.MINIMAL_DOUBLE_HEAD)
        fixes.add_column("Priority", justify="right")
        fixes.add_column("Check")
        fixes.add_column("Status", justify="center")
        fixes.add_column("Why it matters (weight • hint)")

        for i, (_, r) in enumerate(top, start=1):
            name = r["name"]
            w = IMPACT_WEIGHTS.get(name, 1.0)

            hint = ""
            if "TLS versions" in name:
                hint = "Limit to TLS1.2/1.3; drop weak ciphers"
            elif "HTTP disabled" in name:
                hint = "Remove public HTTP or redirect to HTTPS"
            elif "Error reporting hardened" in name:
                hint = "Configure ErrorReportValve with showReport=false and showServerInfo=false"
            elif "TLS keystore" in name:
                hint = "Ensure keystore exists; avoid 'changeit'"
            elif "AJP" in name:
                hint = "Loopback bind + secretRequired + strong secret"
            elif "Brute-force protection" in name:
                hint = "Tune LockOutRealm (failureCount<=5, lockOutTime>=600000ms)"
            elif "Realm" in name:
                hint = "Use LockOutRealm; avoid UserDatabaseRealm in production"
            elif "Password hashing" in name:
                hint = "Enable CredentialHandler (e.g. SHA-256/512)"
            elif "Manager/Host-Manager" in name:
                hint = "Restrict via RemoteAddr/CIDRValve to loopback"
            elif "tomcat-users" in name:
                hint = "No default users; no admin roles; no weak/empty passwords"
            elif "conf/ ownership" in name:
                hint = "Tighten perms (dir≤0750, files≤0640) & service owner"
            elif "Default/admin webapps" in name:
                hint = "Remove docs/examples; restrict admin apps"
            elif "Shutdown port" in name:
                hint = "Set <Server port='-1'>"
            elif "Directory listings" in name:
                hint = "Ensure listings=false for DefaultServlet"
            elif "TRACE method disabled" in name:
                hint = "Set allowTrace=\"false\" on all connectors in server.xml"
            elif "Server / X-Powered-By headers hardened" in name:
                hint = "Set a generic 'server' value and xpoweredBy=\"false\" on all connectors"

            c = color_map.get(r["status"], "white")
            fixes.add_row(
                f"#{i}",
                name,
                f"[{c}]{r['status']}[/{c}]",
                f"weight={w} • {hint}",
            )

        console.print()
        console.print(fixes)

    if args.output:
        enriched = {
            "results": checks,
            "summary": {
                "weighted_achieved": round(achieved, 2),
                "weighted_total": round(total_weight, 2),
                "ratio": round(ratio, 4),
                "final_numeric_1_to_4": round(numeric_1_to_4, 2),
                "tier": tier,
                "label": label,
            },
        }
        try:
            with open(args.output, "w") as f:
                json.dump(enriched, f, indent=4)
            console.print(f"[green]✔ Results saved to {args.output}[/green]")
        except Exception as e:
            console.print(f"[red]✖ Failed to write output file: {e}[/red]")



if __name__ == "__main__":
    main()