import secrets

def text_to_binary(text):
    binary_text = ''.join(format(ord(char), '08b') for char in text)
    return binary_text

def binary_to_text(binary_text):
    text = ''.join(chr(int(binary_text[i:i+8], 2)) for i in range(0, len(binary_text), 8))
    return text

def generate_subkeys(num_rounds, key):
    subkeys = []
    for round in range(num_rounds):
        subkey = key[round % len(key): round % len(key) + 8]  # We can adjust the subkey size as needed
        subkeys.append(subkey)
    return subkeys

def feistel_network_encrypt(plain_text, num_rounds, key):
    left_half, right_half = plain_text[:len(plain_text)//2], plain_text[len(plain_text)//2:]
    subkeys = generate_subkeys(num_rounds, key)

    for round in range(num_rounds):
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

# Example usage:
plain_text = "hello"
key = format(secrets.randbits(64), '064b')
num_rounds = 8

binary_plain_text = text_to_binary(plain_text)
encrypted_text = feistel_network_encrypt(binary_plain_text, num_rounds, key)
print("Encrypted:", binary_to_text(encrypted_text))

decrypted_text = feistel_network_decrypt(encrypted_text, num_rounds, key)
print("Decrypted:", binary_to_text(decrypted_text))
