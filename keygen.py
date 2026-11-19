import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

os.makedirs("keys", exist_ok=True)
roles = ["omega", "policy", "owner", "owner_confirm", "eu1"]

for role in roles:
    priv_path = f"keys/{role}.key"
    pub_path = f"keys/{role}.pub"
    if not os.path.exists(priv_path):
        key = Ed25519PrivateKey.generate()
        priv_bytes = key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_bytes = key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        with open(priv_path, "w") as f:
            f.write(priv_bytes.hex())
        with open(pub_path, "w") as f:
            f.write(pub_bytes.hex())
        os.chmod(priv_path, 0o600)
        print(f"Created new keypair for: {role}")
    else:
        print(f"Keypair already exists for: {role}")
