from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def verify_certificate(ca_public_key_path, certificate_path):
    with open(ca_public_key_path, 'r') as file:
        ca_public_key_text = file.read()
    ca_public_key = RSA.import_key(ca_public_key_text)

    with open(certificate_path, 'r') as file:
        certificate_text = file.read()

    public_key_text, signature_text, body_text = certificate_text.split('\n')

    public_key = RSA.import_key(public_key_text)
    signature = bytes.fromhex(signature_text)
    body = body_text.encode('utf-8')

    # Verify the signature
    h = SHA256.new(body)
    try:
        pkcs1_15.new(ca_public_key).verify(h, signature)
        print("Signature is valid.")
    except (ValueError, TypeError):
        print("Signature is not valid.")

verify_certificate('c0.pem', 'c1.pem')

