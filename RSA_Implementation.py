import random

# Generate prime numbers upto the limit
def sieve_of_eratosthenes(limit):
    sieve = [True] * (limit + 1)
    sieve[0] = sieve[1] = False
    primes = []

    for p in range(2, int(limit**0.5) + 1):
        if sieve[p]:
            for i in range(p * p, limit + 1, p):
                sieve[i] = False

    for p in range(2, limit + 1):
        if sieve[p]:
            primes.append(p)

    return primes

# Pre-generated primes for the Miller-Rabin test
first_primes_list = sieve_of_eratosthenes(500)

# Generate a random prime number of n bits
def nBitRandom(n):
    return random.randrange(2**(n-1) + 1, 2**n - 1)

# We are randomly generating prime numbers. For this we are 
# rejecting the number divisible by first few primes
def getLowLevelPrime(n):
    while True:
        pc = nBitRandom(n)
        for divisor in first_primes_list:
            if pc % divisor == 0 and divisor**2 <= pc:
                break
        else:
            return pc

# Miller Rabin Test
def isMillerRabinPassed(mrc):
    maxDivisionsByTwo = 0
    ec = mrc - 1
    while ec % 2 == 0:
        ec >>= 1
        maxDivisionsByTwo += 1
    assert(2**maxDivisionsByTwo * ec == mrc - 1)

    def trialComposite(round_tester):
        if pow(round_tester, ec, mrc) == 1:
            return False
        for i in range(maxDivisionsByTwo):
            if pow(round_tester, 2**i * ec, mrc) == mrc - 1:
                return False
        return True

    numberOfRabinTrials = 20
    for i in range(numberOfRabinTrials):
        round_tester = random.randrange(2, mrc)
        if trialComposite(round_tester):
            return False
    return True

def generate_prime(bits):
    while True:
        prime_candidate = getLowLevelPrime(bits)
        if isMillerRabinPassed(prime_candidate):
            return prime_candidate

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def generate_keypair(bits):
    p = generate_prime(bits)
    q = generate_prime(bits)
    # print(p,q)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randrange(2, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)
    d = mod_inverse(e, phi)
    return ((e, n), (d, n))

def mod_pow(base, exponent, modulus):
    result = 1
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent //= 2
    return result

def encrypt(public_key, plaintext):
    e, n = public_key
    encrypted = [mod_pow(ord(char), e, n) for char in plaintext]
    return encrypted

def decrypt(private_key, ciphertext):
    d, n = private_key
    decrypted = [chr(mod_pow(char, d, n)) for char in ciphertext]
    return ''.join(decrypted)

if __name__ == '__main__':
    bits = 100
    public_key, private_key = generate_keypair(bits)
    # print(public_key)
    # print(private_key)
    message = "I am good, thanks!!"

    encrypted_message = encrypt(public_key, message)
    decrypted_message = decrypt(private_key, encrypted_message)

    print("Original message:", message)
    print("Encrypted message:", encrypted_message)
    print("Decrypted message:", decrypted_message)
