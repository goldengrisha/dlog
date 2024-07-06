import hashlib
import random


# Function to compute modular exponentiation (base^exp % mod)
def mod_exp(base, exp, mod):
    result = 1
    while exp > 0:
        if exp % 2 == 1:  # If exp is odd, multiply base with result
            result = (result * base) % mod
        base = (base * base) % mod  # Square the base
        exp //= 2
    return result


# Function to compute the hash of a message
def hash_message(message):
    return int.from_bytes(hashlib.sha256(message.encode()).digest(), byteorder="big")


# Miller-Rabin primality test function
def is_prime(n, k=20):
    """Miller-Rabin primality test"""
    if n <= 3:
        return n == 2 or n == 3
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Test for k random witnesses
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


# Generate a large prime number using Miller-Rabin test
def generate_large_prime(bits):
    while True:
        prime_candidate = random.getrandbits(bits)
        if is_prime(prime_candidate):
            return prime_candidate


# Generate a safe prime (p = 2q + 1 where q is prime)
def generate_safe_prime(bits):
    while True:
        q = generate_large_prime(bits - 1)
        p = 2 * q + 1
        if is_prime(p):
            return p


# Key generation with safe prime
def generate_keys():
    p = generate_safe_prime(128)  # Choose a safe prime p
    g = random.randint(2, p - 1)  # Choose a generator g
    x = random.randint(2, p - 2)  # Choose a private key x
    y = mod_exp(g, x, p)  # Compute public key y = g^x % p
    return p, g, x, y


# Prover side
def prove_discrete_log(p, g, x):
    k = random.randint(2, p - 2)  # Choose a random nonce k
    R = mod_exp(g, k, p)  # Compute R = g^k % p
    e = hash_message(str(R))  # Hash the value of R
    s = (k + x * e) % (p - 1)  # Compute s = k + x * e (mod p-1)
    return (R, s)


# Verifier side
def verify_discrete_log(p, g, y, proof):
    R, s = proof
    e = hash_message(str(R))  # Hash the value of R
    left = mod_exp(g, s, p)  # Compute g^s % p
    right = (R * mod_exp(y, e, p)) % p  # Compute (R * y^e) % p
    return left == right


# Example usage
p, g, x, y = generate_keys()

print("Prime p:", p)
print("Generator g:", g)
print("Private key x:", x)
print("Public key y:", y)

# Example usage of the rest of the protocol functions...

proof = prove_discrete_log(p, g, x)
print("\nProof:", proof)

result = verify_discrete_log(p, g, y, proof)
print("Verification result:", result)
