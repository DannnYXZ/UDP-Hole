import secrets

def gen_token(size):
    return secrets.token_bytes(size)
