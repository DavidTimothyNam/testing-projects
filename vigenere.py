def encode_vigenere():
    # Grabs the plaintext and the key from the user
        # Should include a statement that says to remove special characters, and that the output will be in lowercase and have spaces removed
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    plaintext = input("What is the text you would like to decrypt? \n").lower().replace(" ", "")
    key = input("Enter the key you would like to use: ")
    key_pair = ""
    # By repeating the key, this creates a string of equal length to plain text
    for x in range(0, len(plaintext)):
        key_pair += key[x % len(key)]
    # Takes each letter of the plain text and matches it with the corresponding letter of the key pair.
    # It shifts them by adding their indices together, preforming mod 26, and finding the letter in the alphabet at the position of the sum.
    ciphertext = ""
    for x in range(0, len(plaintext)):
        plain = plaintext[x]
        cipher = key_pair[x]
        new = alphabet.index(plain) + alphabet.index(cipher)
        final = alphabet[new % 26]
        ciphertext += final    
    print(ciphertext)

encode_vigenere()