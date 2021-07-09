# This uses a key that is a number.
def caesar_encode(plaintext, key):
    plaintext = plaintext.lower()
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    for char in key:
        if char not in "0123456789":
            raise AssertionError("The key must be a number")
    key = int(key)
    # Shifts the plaintext, excluding characters that aren't in the alphabet
    ciphertext = ""
    for c in plaintext:
        if c not in alphabet:
            ciphertext += c
        elif c in alphabet:
            shifted = alphabet[(alphabet.index(c) + key) % len(alphabet)]
            ciphertext += shifted
    # Return ciphertext
    return ciphertext

# Here, the key is the key that was used to shift the original plaintext.
def caesar_decode(ciphertext, key):
    ciphertext = ciphertext.lower()
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    key = str(key)
    for char in key:
        if char not in "0123456789":
            raise AssertionError("The key must be a number")
    key = int(key)
    # Shifts the ciphertext, excluding characters that aren't in the alphabet
    plaintext = ""
    for c in ciphertext:
        if c not in alphabet:
            plaintext += c
        elif c in alphabet:
            shifted = alphabet[(alphabet.index(c) - key) % len(alphabet)]
            plaintext += shifted
    # Return ciphertext
    return plaintext

def bruteforce_caesar(encoded):
    for x in range(1, 27):
        a = caesar_decode(encoded, x)
        print("Key: " + str(x) + "; Result: " + a)