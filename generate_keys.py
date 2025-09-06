from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# Generate private key
priv = ec.generate_private_key(ec.SECP256R1())
priv_pem = priv.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Generate public key
pub = priv.public_key()
pub_pem = pub.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Save keys to files
with open("private_key.pem", "wb") as f:
    f.write(priv_pem)
with open("public_key.pem", "wb") as f:
    f.write(pub_pem)

print("Generated private_key.pem and public_key.pem")
