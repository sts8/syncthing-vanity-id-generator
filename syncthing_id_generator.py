import base64
import datetime
from hashlib import sha256

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.x509 import Certificate


def create_key_and_cert() -> (EllipticCurvePrivateKey, Certificate):
    """
    https://github.com/syncthing/syncthing/blob/main/lib/tlsutil/tlsutil.go#L90
    https://cryptography.io/en/latest/x509/tutorial/#creating-a-self-signed-certificate
    """
    key = ec.generate_private_key(curve=ec.SECP384R1())

    subject = issuer = x509.Name([
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "Syncthing"),
        x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, "Automatically Generated"),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, "syncthing"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365 * 100)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName("syncthing")]),
        critical=False
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True
    ).add_extension(
        x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH, x509.ExtendedKeyUsageOID.CLIENT_AUTH]),
        critical=False
    ).add_extension(
        x509.KeyUsage(digital_signature=True, key_encipherment=True, key_agreement=False, key_cert_sign=False,
                      crl_sign=False, data_encipherment=False, decipher_only=False, encipher_only=False,
                      content_commitment=False),
        critical=True
    ).sign(key, hashes.SHA256())

    return key, cert


def luhn32(string: str) -> str:
    """
    https://github.com/syncthing/syncthing/blob/main/lib/protocol/luhn.go
    https://github.com/arthurdejong/python-stdnum/blob/master/stdnum/luhn.py
    """
    luhn_base_32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    n = 32
    number = tuple(luhn_base_32.index(i) for i in reversed(string))
    checksum = (sum(number[::2]) + sum(sum(divmod(i * 2, n)) for i in number[1::2])) % n
    return luhn_base_32[-checksum]


def calculate_syncthing_id(cert: Certificate) -> str:
    """ https://gist.github.com/spectras/b3a6f0093ddb1635b39279e9a539ca21 """
    cert_hash = sha256(cert.public_bytes(serialization.Encoding.DER))
    cert_hash_b32 = base64.b32encode(cert_hash.digest()).decode()

    result = cert_hash_b32.upper().rstrip('=')
    blocks = [result[pos:pos + 13] for pos in range(0, len(result), 13)]
    result = ''.join(block + luhn32(block) for block in blocks)
    blocks = [result[pos:pos + 7] for pos in range(0, len(result), 7)]

    return '-'.join(blocks)
