import random
import secrets
import matplotlib.pyplot as plt
import time

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

# We are randomly generating prime numbers. For this we are rejecting the number divisible by first few primes
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

def text_to_binary(text):
    binary_text = ''.join(format(ord(char), '08b') for char in text)
    return binary_text

def binary_to_text(binary_text):
    text = ''.join(chr(int(binary_text[i:i+8], 2)) for i in range(0, len(binary_text), 8))
    return text

def generate_subkeys(num_rounds, key):
    subkeys = []
    for round in range(num_rounds):
        subkey = key[round % len(key): round % len(key) + 8]  # You can adjust the subkey size as needed
        subkeys.append(subkey)
    return subkeys

# Feistal network encryption
def feistel_network_encrypt(plain_text, num_rounds, key):
    left_half, right_half = plain_text[:len(plain_text)//2], plain_text[len(plain_text)//2:]
    subkeys = generate_subkeys(num_rounds, key)

    for round in range(num_rounds):
        left_half = ''.join([bit if bit in ('0', '1') else '0' for bit in left_half])
        left_half = left_half.zfill(len(right_half))  # Ensure left_half and right_half have the same length
        subkeys[round] = ''.join([bit if bit in ('0', '1') else '0' for bit in subkeys[round]])

        feistel_output = int(left_half, 2) ^ int(subkeys[round], 2)
        left_half, right_half = right_half, bin(feistel_output)[2:].zfill(len(left_half))

    left_half, right_half = right_half, left_half
    encrypted_text = left_half + right_half
    return encrypted_text


def feistel_network_decrypt(encrypted_text, num_rounds, key):
    left_half, right_half = encrypted_text[:len(encrypted_text)//2], encrypted_text[len(encrypted_text)//2:]
    subkeys = generate_subkeys(num_rounds, key)

    for round in range(num_rounds):
        feistel_output = int(left_half, 2) ^ int(subkeys[num_rounds - round - 1], 2)
        left_half, right_half = right_half, bin(feistel_output)[2:].zfill(len(left_half))

    left_half, right_half = right_half, left_half
    decrypted_text = left_half + right_half
    return decrypted_text

def rsa_encryption_time(public_key, message):
    start_time = time.time()
    encrypt(public_key, message)
    end_time = time.time()
    return end_time - start_time

def hybrid_encryption_time(key, public_key, num_rounds, message):
    start_time = time.time()
    encrypt(public_key, key)
    feistel_network_encrypt(message, num_rounds, key)
    end_time = time.time()
    return end_time - start_time

def rsa_decryption_time(private_key, cypher_text):
    start_time = time.time()
    decrypt(private_key, cypher_text)
    end_time = time.time()
    return end_time - start_time

def hybrid_decryption_time(encrpypted_key, private_key, num_rounds, cypher_text):
    start_time = time.time()
    key = decrypt(private_key, encrpypted_key)
    feistel_network_decrypt(cypher_text, num_rounds, key)
    end_time = time.time()
    return end_time - start_time

def compare_encryption_times(public_key, key, num_rounds, message, num_samples):
    rsa_times = []
    hybrid_times = []

    for i in range(num_samples):
        rsa_time = rsa_encryption_time(public_key, message[i])
        hybrid_time = hybrid_encryption_time(key, public_key, num_rounds, message[i])

        rsa_times.append(rsa_time)
        hybrid_times.append(hybrid_time)

    print(len(rsa_times))

    return rsa_times, hybrid_times

def compare_decryption_times(private_key, encrpypted_key, num_rounds, cypher_text_rsa, cypher_text_hybrid):
    rsa_time = rsa_decryption_time(private_key, cypher_text_rsa)
    hybrid_time = hybrid_decryption_time(encrpypted_key, private_key, num_rounds, cypher_text_hybrid)

    return rsa_time, hybrid_time

def plot_comparison_graph_encryption(public_key, key, num_rounds, message, num_samples):
    rsa_times, hybrid_times = compare_encryption_times(public_key, key, num_rounds, message, num_samples)

    plt.figure(figsize=(10, 6))
    plt.plot(range(1, num_samples+1), rsa_times, label='RSA Encryption')
    plt.plot(range(1, num_samples+1), hybrid_times, label='Hybrid Encryption')
    plt.xlabel('Sample Size (Increasing-->)')
    plt.ylabel('Encryption Time (seconds)')
    plt.title(f'RSA vs. Hybrid Encryption Time (Bits: {bits}, Key Length: {key_length}, Rounds: {num_rounds})')
    plt.legend()
    plt.grid(True)
    plt.show()

def plot_comparison_graph_decryption(public_key, private_key, key, num_rounds, message, num_samples):
    rsa_times = []
    hybrid_times = []
    encrpypted_key = encrypt(public_key, key)
    
    for i in range(num_samples):
        cypher_text_rsa = encrypt(public_key, message[i])
        cypher_text_hybrid = feistel_network_encrypt(message[i], num_rounds, key)
        rsa_time, hybrid_time = compare_decryption_times(private_key, encrpypted_key, num_rounds, cypher_text_rsa, cypher_text_hybrid)
        rsa_times.append(rsa_time)
        hybrid_times.append(hybrid_time)

    plt.figure(figsize=(10, 6))
    plt.plot(range(1, num_samples+1), rsa_times, label='RSA Decryption')
    plt.plot(range(1, num_samples+1), hybrid_times, label='Hybrid Decryption')
    plt.xlabel('Sample Size (Increasing-->)')
    plt.ylabel('Decryption Time (seconds)')
    plt.title(f'RSA vs. Hybrid Decryption Time (Bits: {bits}, Key Length: {key_length}, Rounds: {num_rounds})')
    plt.legend()
    plt.grid(True)
    plt.show()


if __name__ == '__main__':
  bits = 100
  key_length = 64
  num_rounds = 8
  message = ["hgjshfgjfhggkj",
             "kjkjfkgjskfgjkfgjjjfhg fh",
             "jhgsfghfjkghsfkjg skfdhgskf gshfg sfh",
             "hgsjkfhkjdhfj jhjhjklksfjghkldgh jllajfjdfakdhfuiwfrkaff",
             "jfdskfg jfgjkjdsk darshan heda alkdfj lsfflllllllllsdfffffffffffdsajfsl",
             "ddddddddddda;lsdjfaaaaaaasdkf aaaaaaifyukwertpklxoidfuoeirug eirooyg oserigiop soifygsyoifg wo",
             "ljgslkfjgoioi5jtgslfmvklsk sgisoerutosljvosifyugoie sioigysoiryhig iyosidyfighseriyiy89s 8ry98tgywer 8g9ewsakjhjkhj",
             "lskfjgosier gisoerugisolfjglsfkj lskjfgioosiugjsoijklsfjg slkjfiouioooooooooooowerjlwr iusouriguow iroyjushffg urysierugi ugiuriguysi",
             "skjldfkj gsoidfoyyyyyyyyy ioyoiosadfkljhsk fuoaldkfj ldkifuiowirua oifoaiuf aoiooooaeaosaljfdiueiejsdf ossssssssssssss oiufasdfioaaaaaai iuosaou7aowfod7adf",
             "fhauet6a7fd fukajhdjhuhueiuueadjhdjhf auyeurfhdujyiu sydufyhuywiueyf duyiu6yiu fbueiu6yduai dufiytiiiiiiiiiiiiiiiia udfhfadf  iuytdf7a6ef78 bef86f78a 78e6f87awef7876a7ef78"]
  num_samples = 10
  key = format(secrets.randbits(64), '064b')
  public_key, private_key = generate_keypair(bits)

  plot_comparison_graph_encryption(public_key, key, num_rounds, message, num_samples)
  plot_comparison_graph_decryption(public_key, private_key, key, num_rounds, message, num_samples)