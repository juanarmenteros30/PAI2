import os
import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from cryptography import x509

def generate_private_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

def generate_ca(output_dir):
    private_key = generate_private_key()
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Sevilla"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Sevilla"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"U-Secure Root CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"U-Secure Root CA"),
    ])
    
    # Calculate Subject Key Identifier and Authority Key Identifier
    ski = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key())
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).add_extension(
        ski, critical=False
    ).add_extension(
        aki, critical=False
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        ), critical=True
    ).sign(private_key, hashes.SHA256())
    
    with open(os.path.join(output_dir, "ca-key.pem"), "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
        
    with open(os.path.join(output_dir, "ca-cert.pem"), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
        
    return private_key, cert

def generate_cert(output_dir, name, ca_key, ca_cert, is_server=False):
    private_key = generate_private_key()
    
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"U-Secure"),
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ])
    
    # Calculate Subject Key Identifier and Authority Key Identifier
    ski = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key())
    
    builder = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        ski, critical=False
    ).add_extension(
        aki, critical=False
    )
    
    # Definir el uso de la llave básica
    key_usage = x509.KeyUsage(
        digital_signature=True,
        key_encipherment=True,
        content_commitment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False
    )
    
    if is_server:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        ).add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        ).add_extension(key_usage, critical=True)
    else:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        ).add_extension(key_usage, critical=True)
        
    cert = builder.sign(ca_key, hashes.SHA256())
    
    with open(os.path.join(output_dir, f"{name}-key.pem"), "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
        
    with open(os.path.join(output_dir, f"{name}-cert.pem"), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

if __name__ == "__main__":
    certs_dir = os.path.join(os.path.dirname(__file__), "certs")
    os.makedirs(certs_dir, exist_ok=True)
    
    print("Generando CA Corporativa...")
    ca_key, ca_cert = generate_ca(certs_dir)
    
    print("Generando Certificado de Servidor...")
    generate_cert(certs_dir, "server", ca_key, ca_cert, is_server=True)
    
    print("Generando Certificados de Clientes Precargados (PDI, PAS, Investigadores)...")
    generate_cert(certs_dir, "pdi_user", ca_key, ca_cert, is_server=False)
    generate_cert(certs_dir, "pas_user", ca_key, ca_cert, is_server=False)
    generate_cert(certs_dir, "inv_user", ca_key, ca_cert, is_server=False)
    
    print(f"Certificados generados exitosamente en: {certs_dir}")
