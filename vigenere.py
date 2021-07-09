def encode_vigenere(plaintext, key):
    plaintext = plaintext.lower()
    key = key.lower()
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    # By repeating the key, this creates a string of equal length to plain text
    # By adding to a list of special characters and account for those in the for loop, we can create a key_pair that repeats accurately.
    key_pair = ""
    str_all_special_characters = ""
    for x in range(0, len(plaintext)):
        num_special_char = len(str_all_special_char)
        if plaintext[x] not in alphabet:
            str_all_special_char += plaintext[x]
            key_pair += plaintext[x]
        if plaintext[x] in alphabet:
            key_pair += key[(x - num_special_char) % len(key)]
    # Takes each letter of the plain text and matches it with the corresponding letter of the key pair.
    # It shifts them by adding their indices together, preforming mod 26, and finding the letter in the alphabet at the position of the sum.
    ciphertext = ""
    for x in range(0, len(plaintext)):
        plain = plaintext[x]
        cipher = key_pair[x]
        if cipher not in alphabet:
            ciphertext += cipher
        else:
            new = alphabet.index(plain) + alphabet.index(cipher)
            final = alphabet[new % 26]
            ciphertext += final    
    return ciphertext
