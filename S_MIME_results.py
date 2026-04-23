import os, datetime, uuid, time, statistics, sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509
from cryptography.x509 import NameOID

AES_MODE = "AES-GCM (128-bit)"
HASH_FUNC = "SHA-256"
RSA_PAD = "RSA-OAEP"
SIG_PAD = "RSA-PSS"

# KEY GENERATION (PKI simulation)
def gen_keys(name):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()

    cert = (x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .sign(priv, hashes.SHA256())
    )
    return priv, pub, cert

# SIGNATURE MODULE
def sign(msg, sk):
    print("\n[STEP 1: SIGN]")
    return sk.sign(
        msg,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

# ENCRYPTION MODULE (AES)
def encrypt(msg):
    print("\n[STEP 2: AES ENCRYPT]")
    key = AESGCM.generate_key(bit_length=128)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    return key, nonce, aes.encrypt(nonce, msg, None)

# KEY EXCHANGE MODULE (RSA)
def wrap_key(key, pub):
    print("\n[STEP 3: RSA KEY WRAP]")
    return pub.encrypt(
        key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

# VERIFICATION MODULE
def verify(msg, sig, pub):
    print("\n[STEP 7: VERIFY SIGNATURE]")
    try:
        pub.verify(
            sig,
            msg,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except:
        return False

# 
# BENCHMARKING SUITE
# 

def run_benchmarks(iterations=1000, payload_size=1024):
    print(f"\nInitializing Benchmark Suite (N={iterations}, Payload={payload_size} bytes)...")
    
    # 1. Setup dummy data for the tests
    msg = os.urandom(payload_size) 
    
    # Temporarily mute print statements from the cryptographic functions
    original_stdout = sys.stdout
    sys.stdout = open(os.devnull, 'w')
    
    # Pre-generate keys and payloads so we are ONLY timing the specific operations
    sp, s_pub, _ = gen_keys("Sender")
    rp, r_pub, _ = gen_keys("Receiver")
    sig = sign(msg, sp)
    key, nonce, cipher = encrypt(msg)
    ek = wrap_key(key, r_pub)
    
    # Arrays to hold timing data
    t_keygen, t_sign, t_enc, t_wrap, t_dec, t_ver = [], [], [], [], [], []
    
    #  RUN THE TESTS 
    for _ in range(iterations):
        start = time.perf_counter()
        gen_keys("Test")
        t_keygen.append((time.perf_counter() - start) * 1000)
        
    for _ in range(iterations):
        start = time.perf_counter()
        sign(msg, sp)
        t_sign.append((time.perf_counter() - start) * 1000)

    for _ in range(iterations):
        start = time.perf_counter()
        encrypt(msg)
        t_enc.append((time.perf_counter() - start) * 1000)

    for _ in range(iterations):
        start = time.perf_counter()
        wrap_key(key, r_pub)
        t_wrap.append((time.perf_counter() - start) * 1000)

    for _ in range(iterations):
        start = time.perf_counter()
        # Isolating the AES decrypt logic from your receive function
        AESGCM(key).decrypt(nonce, cipher, None)
        t_dec.append((time.perf_counter() - start) * 1000)

    for _ in range(iterations):
        start = time.perf_counter()
        verify(msg, sig, s_pub)
        t_ver.append((time.perf_counter() - start) * 1000)

    # Restore print statements
    sys.stdout = original_stdout

    # Helper function to print a formatted table row
    def print_row(name, algo, times):
        mean = statistics.mean(times)
        stdev = statistics.stdev(times)
        print(f"{name:<15} | {algo:<17} | {mean:>8.2f} | ± {stdev:>5.2f} | {min(times):>8.2f} | {max(times):>8.2f}")

    # Print the Final Table
    print("\nTable 1: Cryptographic Operation Performance (N=1000 runs, 1KB Payload)")
    print("-" * 80)
    print(f"{'Operation':<15} | {'Algorithm':<17} | {'Mean(ms)':>8} | {'StdDev':>7} | {'Min(ms)':>8} | {'Max(ms)':>8}")
    print("-" * 80)
    print_row("Key Generation", "RSA-2048", t_keygen)
    print_row("Sign", "RSA-PSS (SHA256)", t_sign)
    print_row("Encrypt", "AES-128-GCM", t_enc)
    print_row("Key Wrap", "RSA-OAEP", t_wrap)
    print_row("Decrypt", "AES-128-GCM", t_dec)
    print_row("Verify", "RSA-PSS (SHA256)", t_ver)
    print("-" * 80)
    print("Testing complete. These are the results.\n")

if __name__ == "__main__":
    run_benchmarks(iterations=1000, payload_size=1024)
