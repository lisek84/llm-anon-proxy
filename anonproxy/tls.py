"""
TLS helpers. Resolve the cert/key to hand uvicorn: either the paths the user
supplied, or an auto-generated self-signed pair (ANONPROXY_TLS=true).

Self-signed generation prefers the `cryptography` library (no external process);
if it is absent it falls back to the `openssl` CLI. Either way the cert lands in
the data dir (0600 key) and is reused on the next start.
"""
import datetime
import ipaddress
import logging
import os
import stat
import subprocess

from .config import config

log = logging.getLogger("anonproxy.tls")


def _sans() -> list[str]:
    names = ["localhost", "127.0.0.1", "::1"]
    host = config.HOST
    if host and host not in ("0.0.0.0", "::"):
        names.append(host)
    names += [s.strip() for s in config.TLS_SAN.split(",") if s.strip()]
    # de-dup, keep order
    seen, out = set(), []
    for n in names:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def _chmod600(path: str) -> None:
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def _gen_with_cryptography(cert_path: str, key_path: str, sans: list[str]) -> bool:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError:
        return False

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "anonproxy")])
    alt = []
    for s in sans:
        try:
            alt.append(x509.IPAddress(ipaddress.ip_address(s)))
        except ValueError:
            alt.append(x509.DNSName(s))
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName(alt), critical=False)
        .sign(key, hashes.SHA256())
    )
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
    _chmod600(key_path)
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return True


def _gen_with_openssl(cert_path: str, key_path: str, sans: list[str]) -> bool:
    if not any(os.access(os.path.join(p, "openssl"), os.X_OK)
               for p in os.environ.get("PATH", "").split(os.pathsep) if p):
        return False
    san = ",".join(
        (f"IP:{s}" if _is_ip(s) else f"DNS:{s}") for s in sans)
    cmd = ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
           "-keyout", key_path, "-out", cert_path, "-days", "3650",
           "-subj", "/CN=anonproxy", "-addext", f"subjectAltName={san}"]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        log.warning("openssl cert generation failed: %s", exc)
        return False
    _chmod600(key_path)
    return True


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def resolve() -> tuple[str | None, str | None]:
    """Return (cert_path, key_path) for uvicorn, or (None, None) for plain HTTP."""
    if config.TLS_CERT and config.TLS_KEY:
        return config.TLS_CERT, config.TLS_KEY
    if not config.TLS:
        return None, None

    cert = str(config.DATA_DIR / "tls-cert.pem")
    key = str(config.DATA_DIR / "tls-key.pem")
    if os.path.exists(cert) and os.path.exists(key):
        return cert, key

    sans = _sans()
    log.info("generating self-signed TLS cert (SAN: %s)", ", ".join(sans))
    try:
        ok = _gen_with_cryptography(cert, key, sans) or _gen_with_openssl(cert, key, sans)
    except Exception:  # noqa: BLE001 - clean up partial files, then report below
        ok = False
    if ok:
        log.info("self-signed cert written to %s", cert)
        return cert, key

    for p in (cert, key):   # remove any partial/empty output
        try:
            if os.path.exists(p):
                os.unlink(p)
        except OSError:
            pass
    raise RuntimeError(
        "ANONPROXY_TLS=true but no cert could be generated (need the 'cryptography' "
        "package or the openssl CLI). Provide ANONPROXY_TLS_CERT/ANONPROXY_TLS_KEY, "
        "or terminate TLS with a reverse proxy.")
