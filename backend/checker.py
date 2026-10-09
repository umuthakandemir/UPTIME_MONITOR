import json, socket, ssl, re, subprocess, platform, time, os, shutil, ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse
import httpx



SECURITY_HEADER_RULES = [
    ("Strict-Transport-Security", "HSTS", "HTTPS", "HTTPS yanıtlarında HSTS bulunmalı; önerilen temel değer max-age=31536000 ve includeSubDomains."),
    ("Content-Security-Policy", "CSP", "HTTPS", "XSS ve kaynak enjeksiyonu riskini azaltmak için Content-Security-Policy."),
    ("X-Frame-Options", "X-Frame-Options", "HTTP", "Clickjacking riskini azaltır; CSP frame-ancestors ile de sağlanabilir."),
    ("X-Content-Type-Options", "X-Content-Type-Options", "HTTP", "Değerin nosniff olması beklenir."),
    ("Referrer-Policy", "Referrer-Policy", "HTTP", "Referer bilgisinin kontrollü gönderilmesini sağlar."),
    ("Permissions-Policy", "Permissions-Policy", "HTTP", "Tarayıcı özellikleri ve cihaz API'lerinin kullanımını sınırlar."),
    ("Cross-Origin-Opener-Policy", "COOP", "HTTP", "Pencere izolasyonunu güçlendirir; cross-origin saldırı yüzeyini azaltır."),
    ("Cross-Origin-Resource-Policy", "CORP", "HTTP", "Cross-origin kaynak erişimini sınırlar."),
    ("Cross-Origin-Embedder-Policy", "COEP", "HTTP", "Cross-origin kaynakların embed edilmesini kontrollü hale getirir."),
]

def analyze_security_headers(headers, is_https=True):
    actual={str(k).lower():str(v) for k,v in headers.items()}
    checks=[]
    for header,label,transport,desc in SECURITY_HEADER_RULES:
        key=header.lower()
        value=actual.get(key)
        applicable=(transport!="HTTPS" or is_https)
        present=bool(value)
        valid=True
        if header=="X-Content-Type-Options" and value and value.lower().strip()!="nosniff":
            valid=False
        if header=="Strict-Transport-Security" and value and "max-age=" not in value.lower():
            valid=False
        status="PASS" if applicable and present and valid else ("NOT_APPLICABLE" if not applicable else "FAIL")
        checks.append({"header":header,"label":label,"status":status,"value":value or "", "description":desc})
    advanced=[]
    for header in ("Cross-Origin-Embedder-Policy","Cross-Origin-Opener-Policy","Cross-Origin-Resource-Policy"):
        value=actual.get(header.lower())
        advanced.append({"header":header,"present":bool(value),"value":value or ""})
    informational=[]
    for header in ("server","x-powered-by","via"):
        value=actual.get(header)
        if value:
            informational.append({"header":header,"value":value})
    applicable=[x for x in checks if x["status"]!="NOT_APPLICABLE"]
    passed=sum(x["status"]=="PASS" for x in applicable)
    score=round(passed/max(1,len(applicable))*100)
    grade="A+" if score==100 else "A" if score>=83 else "B" if score>=67 else "C" if score>=50 else "D" if score>=34 else "F"
    return {"score":score,"grade":grade,"checks":checks,"advanced":advanced,"informational":informational,
            "present_headers":sorted(list(actual.keys())),"missing_headers":[x["header"] for x in applicable if x["status"]=="FAIL"]}

def _tls_probe(host, port, version, timeout=4):
    versions = {
        "TLSv1.0": getattr(ssl.TLSVersion, "TLSv1", None),
        "TLSv1.1": getattr(ssl.TLSVersion, "TLSv1_1", None),
        "TLSv1.2": getattr(ssl.TLSVersion, "TLSv1_2", None),
        "TLSv1.3": getattr(ssl.TLSVersion, "TLSv1_3", None),
    }
    value = versions.get(version)
    if value is None:
        return {"supported": False, "available": False, "reason": "Python/OpenSSL bu sürümü desteklemiyor."}
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = value
    ctx.maximum_version = value
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cipher = tls.cipher()[0] if tls.cipher() else ""
                # Python ssl exposes the negotiated cipher reliably; key exchange/authentication
                # are normalized from the OpenSSL cipher-suite naming convention.
                cu = cipher.upper()
                key_exchange = "ECDHE" if "ECDHE" in cu else ("DHE" if "DHE" in cu else ("RSA" if "RSA" in cu else ("TLS 1.3 automatic" if (tls.version() or version) == "TLSv1.3" else "Bilinmiyor")))
                authentication = "ECDSA" if "ECDSA" in cu else ("RSA" if "RSA" in cu else ("TLS 1.3 certificate authentication" if (tls.version() or version) == "TLSv1.3" else "Bilinmiyor"))
                bits = None
                try: bits = tls.cipher()[2]
                except Exception: pass
                group = ""
                try:
                    # OpenSSL/Python does not expose the TLS 1.3 group on every build.
                    # SSLSocket.shared_ciphers is still useful for legacy suites; keep the
                    # value conservative rather than inventing a negotiated group.
                    if (tls.version() or version) == "TLSv1.3": group = "OpenSSL otomatik grup (örn. X25519)"
                except Exception: pass
                return {"supported": True, "available": True, "cipher": cipher, "protocol": tls.version() or version, "key_exchange": key_exchange, "key_exchange_group": group, "authentication": authentication, "encryption_bits": bits}
    except Exception as exc:
        return {"supported": False, "available": True, "reason": str(exc)[:240]}

def _certificate_assessment(host, port, cert_data):
    now = datetime.utcnow()
    expires = cert_data.get("expires_at")
    remaining = int((expires - now).total_seconds() / 86400) if expires else None
    hostname_ok = None
    verification_error = ""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, int(port)), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                hostname_ok = True
                verified = tls.getpeercert()
                if not verified:
                    hostname_ok = False
    except ssl.CertificateError as exc:
        hostname_ok = False
        verification_error = str(exc)
    except ssl.SSLError as exc:
        verification_error = str(exc)
    except Exception as exc:
        verification_error = str(exc)
    return {
        "remaining_days": remaining,
        "expired": bool(remaining is not None and remaining < 0),
        "expiring_soon": bool(remaining is not None and 0 <= remaining <= 30),
        "hostname_valid": hostname_ok,
        "verification_error": verification_error,
    }

def _sslyze_deep_scan(host, port, timeout=120):
    """Run SSLyze's full Python package CLI and return its machine-readable result.
    SSLyze covers protocol/cipher suites, certificate deployment, elliptic curves,
    session resumption, renegotiation, downgrade protection and known TLS attacks
    such as Heartbleed/ROBOT/CCS where supported by the installed release.
    """
    if not shutil.which("python"):
        return {"available": False, "error": "Python çalıştırıcısı bulunamadı."}
    target=f"{host}:{int(port)}"
    cmd=["python", "-m", "sslyze", "--json_out", "-", "--quiet", target]
    try:
        proc=subprocess.run(cmd,capture_output=True,text=True,timeout=timeout)
    except FileNotFoundError:
        return {"available": False, "error": "SSLyze kurulu değil."}
    except subprocess.TimeoutExpired:
        return {"available": False, "error": f"SSLyze taraması {timeout} saniyede tamamlanmadı."}
    stdout=(proc.stdout or "").strip()
    stderr=(proc.stderr or "").strip()
    if not stdout:
        return {"available": False, "error": (stderr[-1200:] or "SSLyze çıktı üretmedi.")}
    try:
        data=json.loads(stdout)
    except json.JSONDecodeError:
        # Some releases may emit a small non-JSON prefix despite --quiet.
        first=stdout.find("{"); last=stdout.rfind("}")
        if first>=0 and last>first:
            try: data=json.loads(stdout[first:last+1])
            except Exception: return {"available":False,"error":stderr[-1200:] or stdout[-1200:]}
        else:
            return {"available":False,"error":stderr[-1200:] or stdout[-1200:]}
    return {"available": proc.returncode==0 or bool(data), "target":target, "raw":data, "stderr":stderr[-1200:]}

def _walk_strings(obj, needles=()):
    out=[]
    if isinstance(obj,dict):
        for k,v in obj.items():
            if any(n in str(k).lower() for n in needles): out.append((str(k),v))
            out.extend(_walk_strings(v,needles))
    elif isinstance(obj,list):
        for v in obj: out.extend(_walk_strings(v,needles))
    return out

def _sslyze_findings(raw):
    """Normalize SSLyze result into findings while remaining compatible with schema revisions."""
    findings=[]
    def add(sev,title,detail): findings.append({"severity":sev,"title":title,"detail":detail,"source":"SSLyze"})
    accepted=[]; enabled_protocols=[]
    def walk(obj, parent=""):
        if isinstance(obj,dict):
            for k,v in obj.items():
                lk=str(k).lower(); ctx=f"{parent}.{lk}" if parent else lk
                if isinstance(v,list) and ("accepted_cipher" in lk or lk in {"accepted_ciphers","accepted_cipher_suites"}):
                    accepted.extend(str(x) for x in v)
                    if v and any(x in ctx for x in ("tls_1_0","tls_1_1","tlsv1.0","tlsv1.1","ssl_2_0","ssl_3_0")):
                        enabled_protocols.append(ctx)
                if isinstance(v,bool) and v:
                    if any(x in lk for x in ("heartbleed","robot","ccs_injection","insecure_renegotiation")):
                        add("critical" if "heartbleed" in lk or "robot" in lk or "ccs" in lk else "high",lk.replace("_"," ").title(),"SSLyze güvenlik kontrolü pozitif/riskli sonuç verdi.")
                if isinstance(v,str) and v.lower() in {"vulnerable","vulnerable_to_attack","vulnerable_to_heartbleed"}:
                    sev="critical" if any(x in lk for x in ("heartbleed","robot","ccs")) else "high"
                    add(sev,lk.replace("_"," ").title(),f"SSLyze sonucu: {v}.")
                walk(v,ctx)
        elif isinstance(obj,list):
            for v in obj: walk(v,parent)
    walk(raw)
    accepted_text=" ".join(accepted).lower()
    if any("tls_1_0" in x or "tlsv1.0" in x for x in enabled_protocols): add("critical","TLS 1.0 destekleniyor","TLS 1.0 cipher suite kabul edildi; modern TLS ile sınırlandırılması önerilir.")
    if any("tls_1_1" in x or "tlsv1.1" in x for x in enabled_protocols): add("critical","TLS 1.1 destekleniyor","TLS 1.1 cipher suite kabul edildi; modern TLS ile sınırlandırılması önerilir.")
    if any("ssl_2_0" in x for x in enabled_protocols): add("critical","SSLv2 destekleniyor","SSLv2 kabul edildi; tamamen kapatılmalıdır.")
    if any("ssl_3_0" in x for x in enabled_protocols): add("critical","SSLv3 destekleniyor","SSLv3 kabul edildi; tamamen kapatılmalıdır.")
    for term,sev,title,detail in [
        ("rc4","critical","RC4 cipher suite kabul ediliyor","RC4 modern TLS için güvenli kabul edilmez."),
        ("3des","high","3DES cipher suite kabul ediliyor","3DES/SWEET32 riski nedeniyle kaldırılması önerilir."),
        ("null","critical","NULL cipher suite kabul ediliyor","Şifrelemesiz cipher kabul ediliyor."),
        ("export","critical","EXPORT cipher suite kabul ediliyor","EXPORT seviyesinde zayıf şifreleme kabul ediliyor."),
        ("md5","high","MD5 tabanlı cipher kabul ediliyor","MD5 tabanlı kriptografi modern güvenlik gereksinimleri için zayıftır."),
    ]:
        if term in accepted_text: add(sev,title,detail)
    return findings

def _sslyze_score(findings):
    score=100
    for f in findings:
        score-= {"critical":35,"high":20,"warning":10,"medium":12,"low":5}.get(f.get("severity"),8)
    return max(0,min(100,score))

def _qualys_ssl_labs(host, port=443, timeout=8, poll_seconds=60):
    """Optional Qualys SSL Labs API assessment for public HTTPS hosts.
    This is kept separate from SSLyze: SSLyze is local/deep; Qualys supplies the
    SSL Labs grades and endpoint-specific findings when the target is public.
    """
    if os.getenv("SSL_LABS_ENABLED","true").lower() not in {"1","true","yes","on"}:
        return {"available":False,"enabled":False,"message":"SSL Labs API devre dışı."}
    try:
        ipaddress.ip_address(host.strip("[]"))
        return {"available":False,"enabled":True,"message":"SSL Labs public hostname testi IP hedeflerinde uygulanmaz."}
    except ValueError:
        pass
    try:
        import httpx
        base="https://api.ssllabs.com/api/v3/analyze"
        params={"host":host,"publish":"off","all":"done","ignoreMismatch":"on"}
        with httpx.Client(timeout=timeout,follow_redirects=True) as client:
            r=client.get(base,params=params); r.raise_for_status(); data=r.json()
            started=time.time()
            while data.get("status") in {"DNS","IN_PROGRESS"} and time.time()-started < poll_seconds:
                time.sleep(4)
                r=client.get(base,params=params); r.raise_for_status(); data=r.json()
            if data.get("status")!="READY":
                return {"available":False,"enabled":True,"status":data.get("status"),"raw":data}
            endpoints=data.get("endpoints") or []
            selected=[]
            for ep in endpoints:
                if int(ep.get("port",443))==int(port): selected.append(ep)
            return {"available":True,"enabled":True,"status":"READY","host":host,"port":port,"grade":(selected[0].get("grade") if selected else data.get("grade")),"grades":sorted(set(str(x.get("grade")) for x in selected if x.get("grade"))),"endpoints":selected,"raw":data}
    except Exception as exc:
        return {"available":False,"enabled":True,"error":str(exc)[:1200]}

def tls_security_scan(host, port=443, deep=True):
    checked = {name: _tls_probe(host, port, name) for name in ("TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3")}
    enabled_legacy = [v for v in ("TLSv1.0", "TLSv1.1") if checked[v].get("supported")]
    modern = [v for v in ("TLSv1.2", "TLSv1.3") if checked[v].get("supported")]
    cert_data=None; cert_assessment={}
    try:
        cert_data=certificate(host,port); cert_assessment=_certificate_assessment(host,port,cert_data)
    except Exception as exc: cert_assessment={"verification_error":str(exc)}
    findings=[]
    if enabled_legacy: findings.append({"severity":"critical","title":"Eski TLS sürümü açık","detail":f"{', '.join(enabled_legacy)} destekleniyor. TLS 1.0/1.1 kapatılmalı.","source":"native"})
    if not modern: findings.append({"severity":"critical","title":"Modern TLS bulunamadı","detail":"TLS 1.2 veya TLS 1.3 ile güvenli bağlantı kurulamadı.","source":"native"})
    elif "TLSv1.3" not in modern: findings.append({"severity":"warning","title":"TLS 1.3 kullanılamıyor","detail":"TLS 1.2 çalışıyor ancak TLS 1.3 sunulmuyor.","source":"native"})
    if cert_assessment.get("expired"): findings.append({"severity":"critical","title":"Sertifika süresi dolmuş","detail":"TLS sertifikasının geçerlilik süresi geçmiş.","source":"certificate"})
    elif cert_assessment.get("expiring_soon"): findings.append({"severity":"warning","title":"Sertifika yakında sona eriyor","detail":f"Sertifika yaklaşık {cert_assessment.get('remaining_days')} gün içinde sona erecek.","source":"certificate"})
    if cert_assessment.get("hostname_valid") is False: findings.append({"severity":"critical","title":"Hostname doğrulaması başarısız","detail":cert_assessment.get("verification_error") or "Sertifika hedef hostname ile eşleşmiyor.","source":"certificate"})
    deep_result=_sslyze_deep_scan(host,port,timeout=int(os.getenv("SSLYZE_TIMEOUT","120"))) if deep else {"available":False,"skipped":True,"message":"Derin SSLyze taraması manuel olarak başlatılabilir."}
    deep_findings=_sslyze_findings(deep_result.get("raw",{})) if deep_result.get("available") else []
    # de-duplicate same issue titles
    seen={(f.get("title"),f.get("detail")) for f in findings}
    findings.extend(f for f in deep_findings if (f.get("title"),f.get("detail")) not in seen)
    native_score=100-sum({"critical":35,"high":20,"warning":10,"medium":12,"low":5}.get(f.get("severity"),8) for f in findings)
    native_score=max(0,min(100,native_score))
    qualys=_qualys_ssl_labs(host,port) if deep else {"available":False,"enabled":False,"message":"Derin SSL Labs analizi manuel TLS taramasında çalıştırılır."}
    qualys_grade=qualys.get("grade") if qualys.get("available") else None
    grade=qualys_grade or ("A+" if native_score>=95 else "A" if native_score>=85 else "B" if native_score>=70 else "C" if native_score>=55 else "D" if native_score>=40 else "F")
    # Enforce a conservative grade cap for deprecated protocol support, independent of the score.
    if enabled_legacy:
        grade = "F" if any(f.get("severity")=="critical" for f in findings) and native_score < 60 else "C"
    hsts={"available":False,"present":False,"max_age_seconds":None,"include_subdomains":False,"preload_directive":False,"browser_preload_status":"unknown"}
    try:
        with httpx.Client(timeout=5, follow_redirects=True, verify=False) as client:
            resp=client.get(f"https://{host}/")
            header=resp.headers.get("strict-transport-security", "")
            hsts.update({"available":True,"present":bool(header),"header":header})
            import re as _re
            m=_re.search(r"max-age\s*=\s*(\d+)", header, _re.I)
            hsts["max_age_seconds"]=int(m.group(1)) if m else None
            hsts["include_subdomains"]="includesubdomains" in header.lower()
            hsts["preload_directive"]=bool(_re.search(r"(?:^|;)\s*preload(?:;|$)",header,_re.I))
        try:
            with httpx.Client(timeout=4, follow_redirects=True) as client:
                pre=client.get("https://hstspreload.org/api/v2/status",params={"domain":host})
                if pre.status_code==200:
                    pd=pre.json(); hsts["browser_preload_status"]=pd.get("status", "unknown"); hsts["preloaded"]=pd.get("status")=="preloaded"
        except Exception: pass
    except Exception as exc: hsts["error"]=str(exc)[:180]
    caa={"available":False,"records":[],"error":""}
    try:
        import dns.resolver
        answers=dns.resolver.resolve(host, "CAA", lifetime=4)
        caa={"available":True,"records":[{"flags":int(x.flags),"tag":str(x.tag),"value":str(x.value).strip('\"')} for x in answers],"error":""}
    except Exception as exc:
        # No CAA RRset is not the same as an unresolvable domain.
        caa={"available":True,"records":[],"error":str(exc)[:180]}
    ciphers=[]
    for probe in checked.values():
        if probe.get("supported") and probe.get("cipher"):
            name=probe["cipher"].upper()
            level="Insecure" if any(x in name for x in ("NULL","RC4","3DES","DES-CBC","EXPORT","MD5")) else "Weak" if "CBC" in name else "Secure"
            entry={"name":probe["cipher"],"protocol":probe.get("protocol"),"security":level,"bits":probe.get("encryption_bits")}
            if entry not in ciphers: ciphers.append(entry)
    attacks={"Heartbleed":{"status":"not_tested"},"POODLE":{"status":"not_tested"},"ROBOT":{"status":"not_tested"},"DROWN":{"status":"not_tested"}}
    for finding in findings:
        title=(finding.get("title") or "").lower()
        for attack in attacks:
            if attack.lower() in title: attacks[attack]["status"]="vulnerable"
    chain={"available":False,"note":"Uzak TLS el sıkışması yalnızca leaf sertifikasını her zaman sunar; tam zincir analizi SSLyze çıktısı mevcut olduğunda değerlendirilir.","leaf":cert_data,"verification":cert_assessment}
    pq={"tls13_supported":"TLSv1.3" in modern,"post_quantum_key_exchange":"not_verified","note":"Post-quantum anahtar değişimi, TLS 1.3 varlığından tek başına çıkarılamaz; özel grup müzakeresi doğrulanmalıdır."}
    return {"available":True,"engine":"OpenSSL + cryptography + SSLyze + Qualys SSL Labs API","target":f"{host}:{int(port)}","score":native_score,"grade":grade,"tls_versions":checked,"modern_protocols":modern,"legacy_protocols":enabled_legacy,"certificate":cert_data,"certificate_assessment":cert_assessment,"certificate_chain":chain,"cipher_suites":ciphers,"hsts":hsts,"caa":caa,"vulnerabilities":attacks,"post_quantum_readiness":pq,"pci_dss_compliant":not bool(enabled_legacy),"findings":findings,"sslyze":deep_result,"ssl_labs":qualys,"summary":"TLS/SSL yapılandırması güçlü görünüyor." if not findings else "TLS/SSL yapılandırmasında güvenlik açısından incelenmesi gereken bulgular var."}

def _ranges(text):
    out=[]
    for part in (text or "200-299").split(","):
        part=part.strip()
        if not part: continue
        try:
            if "-" in part:
                a,b=part.split("-",1); out.append((int(a),int(b)))
            else:
                v=int(part); out.append((v,v))
        except ValueError:
            continue
    return out or [(200,299)]

def in_ranges(code, text):
    return any(a <= code <= b for a,b in _ranges(text))


def ignored_http_codes(value):
    out=set()
    for part in str(value or "").split(","):
        part=part.strip()
        if part.isdigit():
            code=int(part)
            if 100 <= code <= 599: out.add(code)
    return out

def http_status_is_up(code, ranges="200-299", ignored="401,403"):
    try: code=int(code)
    except Exception: return False
    return code in ignored_http_codes(ignored) or in_ranges(code, ranges)

def certificate(host, port=443, timeout=8):
    """TLS sertifikasını doğrulamadan okuyup güvenilir biçimde ayrıştırır.
    Süresi dolmuş/self-signed sertifikalarda bile sertifika metadata'sını alabilir.
    """
    with socket.create_connection((host, int(port)), timeout=timeout) as sock:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(sock, server_hostname=host) as s:
            cert_der = s.getpeercert(binary_form=True)
            cipher_name = s.cipher()[0] if s.cipher() else None

    if not cert_der:
        raise RuntimeError("Sunucu sertifika göndermedi")

    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        def names(oid):
            return [x.value for x in cert.subject.get_attributes_for_oid(oid)]

        subject_cn = (names(x509.NameOID.COMMON_NAME) or [""])[0]
        issuer_cn = (cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME) or [None])[0].value if cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME) else ""

        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            sans = []

        exp = cert.not_valid_after_utc.replace(tzinfo=None)
        sig_name = ""
        try: sig_name = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else ""
        except Exception: pass
        public_key_type = type(cert.public_key()).__name__
        return {
            "subject": subject_cn,
            "issuer": issuer_cn,
            "expires_at": exp,
            "not_before": cert.not_valid_before_utc.replace(tzinfo=None),
            "serial_number": str(cert.serial_number),
            "version": cert.version.name,
            "san": sans,
            "cipher": cipher_name or "",
            "signature_algorithm": sig_name,
            "public_key_type": public_key_type,
        }
    except ImportError:
        # cryptography kurulu değilse mevcut Python ssl parser'ına kontrollü fallback.
        pem = ssl.DER_cert_to_PEM_cert(cert_der)
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
            f.write(pem)
            path = f.name
        try:
            c = ssl._ssl._test_decode_cert(path)
        finally:
            try: os.unlink(path)
            except OSError: pass
        subj = dict(x[0] for x in c.get("subject", []))
        iss = dict(x[0] for x in c.get("issuer", []))
        exp = datetime.strptime(c["notAfter"], "%b %d %H:%M:%S %Y %Z")
        return {
            "subject": subj.get("commonName", ""),
            "issuer": iss.get("commonName", ""),
            "expires_at": exp,
            "not_before": datetime.strptime(c["notBefore"], "%b %d %H:%M:%S %Y %Z"),
            "serial_number": c.get("serialNumber", ""),
            "version": c.get("version"),
            "san": [v for _, v in c.get("subjectAltName", [])],
            "cipher": cipher_name or "",
        }


def _resolved_host_ip(host):
    try:
        infos=socket.getaddrinfo(host,None,socket.AF_UNSPEC,socket.SOCK_STREAM)
        for info in infos:
            if info and info[4]: return info[4][0]
    except Exception: pass
    return None

def _http_peer_ip(response,host):
    try:
        stream=response.extensions.get("network_stream")
        if stream and hasattr(stream,"get_extra_info"):
            addr=stream.get_extra_info("server_addr")
            if isinstance(addr,(tuple,list)) and addr: return addr[0]
            if isinstance(addr,str): return addr
    except Exception: pass
    return _resolved_host_ip(host)

def _tcp(host,port,timeout=8):
    with socket.create_connection((host,int(port)),timeout=timeout): pass

def _ping_target(value):
    """Accept an IP, hostname, or URL and return the host used for ICMP."""
    raw=str(value or "").strip()
    if not raw:
        raise ValueError("Ping hedefi zorunludur")
    candidate=raw if "://" in raw else ("//"+raw if "/" in raw else raw)
    if candidate.startswith("//"):
        parsed=urlparse(candidate)
        host=parsed.hostname or ""
    elif "://" in candidate:
        host=urlparse(candidate).hostname or ""
    else:
        host=raw.split("/",1)[0].split(":",1)[0]
    if not host:
        raise ValueError("Geçerli bir IP, hostname veya URL girin")
    return host

def _ping(host,timeout=5):
    system=platform.system().lower(); start=time.perf_counter()
    if "windows" in system:
        cmd=["ping","-n","1","-w",str(int(timeout*1000)),host]
    else:
        cmd=["ping","-c","1","-W",str(max(1,int(timeout))),host]
    p=subprocess.run(cmd,capture_output=True,text=True,timeout=timeout+2)
    if p.returncode != 0: raise RuntimeError((p.stderr or p.stdout or "Ping failed").strip())
    return round((time.perf_counter()-start)*1000,2)

def check(service):
    t=time.perf_counter(); o={"status":"DOWN","code":None,"latency":0,"error":"","cert":None,"rule_signature":""}
    opts=json.loads(service.protocol_options or "{}")
    typ=(service.monitor_type or "http").lower()
    try:
        if typ in ("http","https","web"):
            raw=(service.url or opts.get("url") or "").strip()
            if not raw: raise ValueError("Web servisi için URL girilmelidir")
            if "://" not in raw: raw="https://"+raw
            parsed=urlparse(raw)
            if parsed.scheme not in ("http","https"): raise ValueError("Geçersiz web URL'si")
            # Web kontrolü HTTPS'i tercih eder. HTTPS bağlantısı kurulamazsa HTTP'yi otomatik dener.
            candidates=[raw]
            alt="http://"+parsed.netloc+parsed.path+(("?"+parsed.query) if parsed.query else "")
            if parsed.scheme=="https": candidates.append(alt)
            elif parsed.scheme=="http": candidates.append("https://"+parsed.netloc+parsed.path+(("?"+parsed.query) if parsed.query else ""))
            last_error=None; r=None
            for candidate in candidates:
                try:
                    r=httpx.get(candidate,timeout=float(opts.get("timeout",15)),verify=not service.ignore_cert_errors,follow_redirects=bool(opts.get("follow_redirects",True)),headers=opts.get("headers") or {})
                    break
                except Exception as ex:
                    last_error=ex
            if r is None:
                host = parsed.hostname or ""
                try:
                    o["server_reachable"] = bool(_ping(host, min(5, float(opts.get("ping_timeout", 3)))))
                except Exception as ping_error:
                    o["server_reachable"] = False
                    o["server_ping_error"] = str(ping_error)
                o["resolved_ip"] = _resolved_host_ip(host)
                raise RuntimeError(f"Web kontrolü başarısız: {last_error}")
            o["effective_url"]=str(r.url); o["code"]=r.status_code;o["latency"]=round((time.perf_counter()-t)*1000,2);o["resolved_ip"]=_http_peer_ip(r,parsed.hostname); o["headers"]={k:v for k,v in r.headers.items()}; o["header_security"]=analyze_security_headers(r.headers, str(r.url).lower().startswith("https://"))
            o["status"]="UP" if http_status_is_up(r.status_code,service.status_ranges,getattr(service,"ignored_http_status_codes","401,403")) else "DOWN"
            if o["status"]=="DOWN":
                try:
                    o["server_reachable"] = bool(_ping(parsed.hostname or "", min(5, float(opts.get("ping_timeout", 3)))))
                except Exception as ping_error:
                    o["server_reachable"] = False
                    o["server_ping_error"] = str(ping_error)
                o["error"] = (f"HTTP {r.status_code} status aralığı dışında · Sunucu erişilebilir" if o.get("server_reachable") else f"HTTP {r.status_code} status aralığı dışında · Sunucu ping başarısız")
            if service.content_monitoring:
                keys=json.loads(service.content_keywords or "[]")
                if service.content_mode=="contains":
                    miss=[k for k in keys if k not in r.text]
                    if miss:o["status"]="DOWN";o["error"] += " | Eksik içerik: "+", ".join(miss)
                elif service.content_mode=="not_contains":
                    hit=[k for k in keys if k in r.text]
                    if hit:o["status"]="DOWN";o["error"] += " | Yasak içerik: "+", ".join(hit)
                else:
                    bad=[k for k in keys if not re.search(k,r.text,re.I)]
                    if bad:o["status"]="DOWN";o["error"] += " | Regex eşleşmedi: "+", ".join(bad)
            if (str(o.get("effective_url",raw)).lower().startswith("https://")) and service.certificate_monitoring:
                p=urlparse(str(o.get("effective_url", raw)))
                try:
                    cert=certificate(p.hostname,p.port or 443)
                    o["cert"]=(cert["subject"],cert["issuer"],cert["expires_at"])
                    o["cert_details"]=cert
                except Exception as e:
                    o["error"] += " | Sertifika: "+str(e)
        elif typ=="ping":
            target=opts.get("host") or service.url.replace("ping://","").strip()
            host=_ping_target(target)
            o["resolved_ip"]=_resolved_host_ip(host);o["host"]=host;o["target"]=target
            o["latency"]=_ping(host,float(opts.get("timeout",5)));o["status"]="UP"
        elif typ=="tcp":
            _tcp(opts.get("host") or service.url.split("://",1)[-1].split(":",1)[0],opts.get("port",80),float(opts.get("timeout",8)))
            o["host"]=opts.get("host") or service.url.split("://",1)[-1].split(":",1)[0];o["port"]=int(opts.get("port",80));o["latency"]=round((time.perf_counter()-t)*1000,2);o["resolved_ip"]=_resolved_host_ip(opts.get("host") or service.url.split("://",1)[-1].split(":",1)[0]);o["status"]="UP"
        elif typ=="dns":
            host=opts.get("host") or service.url
            expected=opts.get("expected","" )
            addrs=socket.gethostbyname_ex(host)[2]
            o["resolved_ip"]=addrs[0] if addrs else _resolved_host_ip(host);o["host"]=host;o["dns_addresses"]=addrs
            o["latency"]=round((time.perf_counter()-t)*1000,2);o["status"]="UP"
            if expected and expected not in addrs:o["status"]="DOWN";o["error"]=f"DNS sonucu beklenmiyor: {', '.join(addrs)}"
        elif typ=="ssl":
            host=opts.get("host") or service.url; port=int(opts.get("port",443))
            cert=certificate(host,port)
            o["cert"]=(cert["subject"],cert["issuer"],cert["expires_at"])
            o["resolved_ip"]=_resolved_host_ip(host)
            o["host"]=host;o["port"]=port
            o["cert_details"]=cert
            try: o["tls_security"]=tls_security_scan(host,port,deep=False)
            except Exception as e: o["tls_security"]={"available":False,"message":str(e)}
            o["latency"]=round((time.perf_counter()-t)*1000,2);o["status"]="UP"
        elif typ=="smtp":
            host=opts.get("host"); port=int(opts.get("port",587)); use_ssl=bool(opts.get("ssl",False)); use_tls=bool(opts.get("tls",True))
            if use_ssl: server=__import__('smtplib').SMTP_SSL(host,port,timeout=10)
            else: server=__import__('smtplib').SMTP(host,port,timeout=10)
            with server:
                server.ehlo()
                if use_tls and not use_ssl: server.starttls(context=ssl.create_default_context()); server.ehlo()
                if opts.get("username"):
                    server.login(opts.get("username"),opts.get("password", ""))
            o["host"]=host;o["port"]=port;o["latency"]=round((time.perf_counter()-t)*1000,2);o["status"]="UP"
        elif typ=="mysql":
            import pymysql
            conn=pymysql.connect(host=opts.get("host"),port=int(opts.get("port",3306)),user=opts.get("username"),password=opts.get("password", ""),database=opts.get("database") or None,connect_timeout=8,read_timeout=8,write_timeout=8)
            conn.close();o["host"]=opts.get("host");o["port"]=int(opts.get("port",3306));o["latency"]=round((time.perf_counter()-t)*1000,2);o["status"]="UP"
        elif typ=="postgresql":
            import psycopg
            conn=psycopg.connect(host=opts.get("host"),port=int(opts.get("port",5432)),user=opts.get("username"),password=opts.get("password", ""),dbname=opts.get("database") or None,connect_timeout=8)
            conn.close();o["host"]=opts.get("host");o["port"]=int(opts.get("port",5432));o["latency"]=round((time.perf_counter()-t)*1000,2);o["status"]="UP"
        elif typ=="redis":
            import redis
            client=redis.Redis(host=opts.get("host"),port=int(opts.get("port",6379)),username=opts.get("username") or None,password=opts.get("password") or None,db=int(opts.get("database",0)),socket_connect_timeout=8,socket_timeout=8)
            client.ping();client.close();o["host"]=opts.get("host");o["port"]=int(opts.get("port",6379));o["latency"]=round((time.perf_counter()-t)*1000,2);o["status"]="UP"
        else: raise ValueError("Desteklenmeyen kontrol tipi")
    except Exception as e:
        o["latency"]=round((time.perf_counter()-t)*1000,2);o["error"]=str(e)
    return o
