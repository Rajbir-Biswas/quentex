from pqcrypto.kem.ml_kem_512 import generate_keypair

public_key, secret_key = generate_keypair()

print("Public key length:", len(public_key))
print("Secret key length:", len(secret_key))
