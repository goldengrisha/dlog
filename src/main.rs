use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};

// Function to compute modular exponentiation (base^exp % mod)
fn mod_exp(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
    base.modpow(exp, modulus)
}

// Function to compute the hash of a message
fn hash_message(message: &str) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.update(message.as_bytes());
    let hash = hasher.finalize();
    BigUint::from_bytes_be(&hash.to_vec())
}

// Generate a large prime number
fn generate_large_prime(bits: usize) -> BigUint {
    let mut rng = thread_rng();
    loop {
        let prime_candidate: BigUint = rng.gen_biguint(bits as u64);
        if is_prime(&prime_candidate) {
            return prime_candidate;
        }
    }
}

// Function to check if a number is prime (Miller-Rabin primality test)
fn is_prime(n: &BigUint) -> bool {
    if n <= &BigUint::one() {
        return false;
    }
    if n <= &BigUint::from(3 as u32) {
        return n == &BigUint::from(2 as u32) || n == &BigUint::from(3 as u32);
    }
    if n.is_even() {
        return false;
    }

    let mut d = n.clone() - BigUint::one();
    let mut r = 0;
    while d.is_even() {
        d >>= 1;
        r += 1;
    }

    let num_witnesses = 20; // Adjust number of witnesses for higher confidence
    let mut rng = thread_rng();

    for _ in 0..num_witnesses {
        let a: BigUint =
            rng.gen_biguint_range(&BigUint::from(2 as u32), &(n - BigUint::from(2 as u32)));
        let mut x = mod_exp(&a, &d, n);
        if x == BigUint::one() || x == n - BigUint::one() {
            continue;
        }
        let mut pass = false;
        for _ in 0..(r - 1) {
            x = mod_exp(&x, &BigUint::from(2 as u32), n);
            if x == n - BigUint::one() {
                pass = true;
                break;
            }
        }
        if !pass {
            return false;
        }
    }

    true
}

// Generate safe prime (p = 2q + 1 where q is prime)
fn generate_safe_prime(bits: usize) -> BigUint {
    loop {
        let q = generate_large_prime(bits - 1);
        let p = &q * &BigUint::from(2 as u32) + BigUint::one();
        if is_prime(&p) {
            return p;
        }
    }
}

// Key generation with safe prime
fn generate_keys(p: &BigUint, bits: usize) -> (BigUint, BigUint, BigUint, BigUint) {
    let mut rng = thread_rng();
    let g: BigUint = rng.gen_biguint_range(&BigUint::from(2 as u32), p); // Choose a generator g
    let x: BigUint =
        rng.gen_biguint_range(&BigUint::from(2 as u32), &(p - BigUint::from(2 as u32))); // Choose a private key x
    let y = mod_exp(&g, &x, p); // Compute public key y = g^x % p
    (p.clone(), g, x, y)
}

// Prove discrete logarithm using Schnorr protocol
fn prove_discrete_log(p: &BigUint, g: &BigUint, x: &BigUint) -> (BigUint, BigUint) {
    let mut rng = thread_rng();
    let k: BigUint =
        rng.gen_biguint_range(&BigUint::from(2 as u32), &(p - BigUint::from(2 as u32))); // Choose a random nonce k
    let r = mod_exp(&g, &k, p); // Compute R = g^k % p
    let e = hash_message(&r.to_str_radix(10)); // Hash the value of R
    let s = (&k + x * &e) % (p - BigUint::one()); // Compute s = k + x * e (mod p-1)
    (r, s)
}

// Verify discrete logarithm using Schnorr protocol
fn verify_discrete_log(p: &BigUint, g: &BigUint, y: &BigUint, proof: (BigUint, BigUint)) -> bool {
    let (r, s) = proof;
    let e = hash_message(&r.to_str_radix(10)); // Hash the value of R
    let left = mod_exp(&g, &s, p); // Compute g^s % p
    let right = (&r * mod_exp(&y, &e, p)) % p; // Compute (R * y^e) % p
    left == right
}

fn main() {
    let bits = 128;
    let p = generate_safe_prime(bits); // Choose a safe prime p
    let (p, g, x, y) = generate_keys(&p, bits);

    println!("Generated Keys:");
    println!("Prime p: {}", p);
    println!("Generator g: {}", g);
    println!("Private key x: {}", x);
    println!("Public key y: {}", y);

    let proof = prove_discrete_log(&p, &g, &x);
    println!("\nProof (r, s): {:?}", proof);

    let is_verified = verify_discrete_log(&p, &g, &y, proof);
    println!("Verification result: {}", is_verified);
}
