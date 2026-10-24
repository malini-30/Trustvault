import os

# Cheap password hashing for tests only (production uses N=2**15).
os.environ.setdefault("TV_SCRYPT_N", "1024")
