"""Generate a self-signed TLS certificate for the dashboard (LAN use).
Usage: python scripts/gen_cert.py   -> writes data/tls_cert.pem + data/tls_key.pem
"""
import os, sys, datetime, ipaddress, socket
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]; s.close(); return ip
    except Exception:
        return "127.0.0.1"

def main():
    ip = lan_ip()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "camera.local")])
    san = x509.SubjectAlternativeName([
        x509.DNSName("camera.local"), x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        x509.IPAddress(ipaddress.ip_address(ip)),
    ])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=825))
            .add_extension(san, critical=False)
            .sign(key, hashes.SHA256()))
    with open(config.TLS_CERT, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(config.TLS_KEY, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()))
    os.chmod(config.TLS_KEY, 0o600)
    print("Wrote", config.TLS_CERT)
    print("Wrote", config.TLS_KEY)
    print(f"Valid for camera.local, localhost, 127.0.0.1, {ip}")
    print("Start with HTTPS:  CS_HTTPS=1 python app.py")

if __name__ == "__main__":
    main()
