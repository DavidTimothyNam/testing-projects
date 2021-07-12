# The (messy) code is my own, but I learned the mathematical concepts behind the cryptanalysis of the Vigènere cipher mainly from these websites:
    # http://practicalcryptography.com/cryptanalysis/stochastic-searching/cryptanalysis-vigenere-cipher/
    # https://en.wikipedia.org/wiki/Index_of_coincidence

# Purpose is to break up the ciphertext
def split_string(raw_ciphertext, period):
    all_sequences = []
    for x in range(0, period):
        new_sequence = ""
        y = x
        while y <= (len(raw_ciphertext) - 1):
            new_sequence += raw_ciphertext[y]
            y = y + period
        all_sequences.append(new_sequence)
    return all_sequences

def count_occurences(sequence):
    letters = []
    for c in sequence:
        if c not in letters:
            letters.append(c)
    occurences = []
    for x in letters:
        occurence = 0
        for c in sequence:
            if x == c:
                occurence += 1
        occurences.append(occurence)
    return occurences
        
def calc_IC(occurence, cut_ciphertext):
    c = 26
    all_prob = []
    for single in occurence:
        ni = single / len(cut_ciphertext)
        Ni = (single - 1) / (len(cut_ciphertext) - 1)
        prob = ni * Ni
        all_prob.append(prob)
    prob_sum = sum(all_prob)
    return(prob_sum)

def caesar_decode(ciphertext, key):
    ciphertext = ciphertext.lower()
    alphabet = "abcdefghijklmnopqrstuvwxyz"
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

# Same as count_occurences function, but this maps each occurence to it's letter so it can be used with crypto_chi_sq
def mapped_count_occurences(sequence):
    letters = {}
    for c in sequence:
        if c not in letters:
            letters[c] = ""
    # occurences = []
    for x in letters:
        occurence = 0
        for c in sequence:
            if x == c:
                occurence += 1
        letters.update({x : str(occurence)})
    return letters

# Intended use is to pass in output from the split_string function once the key length has been decided.
def crypto_chi_sq(splitted):
    letter_frequencies = {
        "a": 0.0812,
        "b": 0.0149,
        "c": 0.0271,
        "d": 0.0432,
        "e": 0.1202,
        "f": 0.0230,
        "g": 0.0203,
        "h": 0.0592,
        "i": 0.0731,
        "j": 0.0010,
        "k": 0.0069,
        "l": 0.0398,
        "m": 0.0261,
        "n": 0.0695,
        "o": 0.0768,
        "p": 0.0182,
        "q": 0.0011,
        "r": 0.0602,
        "s": 0.0628,
        "t": 0.0910,
        "u": 0.0288,
        "v": 0.0111,
        "w": 0.0209,
        "x": 0.0017,
        "y": 0.0211,
        "z": 0.0007,
    }
    
    all_chi_sq = {}
    all_decoded = []
    for i in range(0, 26):
        decoded = caesar_decode(splitted, i)
        all_decoded.append(decoded)
        actuals = mapped_count_occurences(decoded)
        holds_values = []
        for letter in actuals.keys(): # might need to do some int() converting in this general area
            actual = actuals[letter]
            expected = letter_frequencies[letter] * len(splitted)
            squared = (int(actual) - float(expected)) ** 2
            value = squared / expected
            holds_values.append(value)
        statistic = sum(holds_values)
        all_chi_sq.update({str(i) : str(statistic)})
    best_number = min(all_chi_sq, key=lambda x:float(all_chi_sq[x]))
    return(best_number)

def build_key(most_likely_keys, raw_ciphertext):
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    print("The following are 5 likely key lengths. Please note that if your ciphertext is particularly large, the actual key length may be a common factor of most of these values ")
    print(most_likely_keys)
    temp_values = []
    for value in most_likely_keys:
        for number in range(1, int(value)):
            if (int(value) % number) == 0:
                temp_values.append(number)
    values = []
    for b in temp_values:
        if b not in values:
            values.append(b)
    common_factors = values
    values = sorted(values)
    done = []
    for n in values:
        for x in most_likely_keys:
            if n not in done:
                if (int(x) % int(n)) != 0:
                    common_factors.remove(int(n))
                    done.append(n)
            else:
                pass
    common_factors = sorted(common_factors)
    print("If the key lengths are too big, try one of these common factors between them: ")
    print(common_factors)
    print("And if that list happened to be empty, here is a list of all factors for each number combined into one list: ")
    print(values)
    key_decision = input("Please enter your selection by typing the key length you would like to test, without the quotes: ")
    key_decision = int(key_decision)
    splitted = split_string(raw_ciphertext, key_decision)
    list_of_indices = []
    for string in splitted:
        a = crypto_chi_sq(string)
        list_of_indices.append(a)
    letters = []
    for value in list_of_indices:
        letters.append(alphabet[int(value)])
    key = ''.join(letters)
    print("The most-likely key has been determined: " + key.upper() + "\n")
    return key

def transition(lengths, key, raw_ciphertext, original_text):
    answer = input("""
    Enter the any of following numbers to proceed:
    1. Correct the key and decode
    2. Decode the given text using this key
    3. Calculate a different key with the key_lengths.
    4. (or any other character/number) Quit

    What would you like to do: """)
    print("\n")
    if answer not in "01234":
        print("Thank you, goodbye!")
    elif answer == "1":
        new_key = input("Enter the key you'd like to use instead: ")
        result = decode_vigenere(original_text, new_key)
        print(result)
        transition(lengths, new_key, raw_ciphertext, original_text)
    elif answer == "2":
        result = decode_vigenere(original_text, key)
        print(result)
        transition(lengths, key, raw_ciphertext, original_text)
    elif answer == "3":
        new_key = build_key(lengths, raw_ciphertext)
        transition(lengths, new_key, raw_ciphertext, original_text)
    elif answer == "4":
        print("Thank you, goodbye!")
        quit()

def full_find_key(orginal_ciphertext):
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    raw_ciphertext = original_ciphertext.lower()
    # Cleans up the input so that it is usable in the program
    for character in raw_ciphertext:
        if character not in alphabet:
            raw_ciphertext = raw_ciphertext.replace(character, "")
    # Work starts here:
    all_average_ICs = {}
    for key_value in range(2, (len(raw_ciphertext) // 5)): 
    # will return an error if the second argument is larger than the raw ciphertext
        list_of_occurences = []
        splitted = split_string(raw_ciphertext, key_value)
        # print(splitted) #
        for cut_ciphertext in splitted:
            occurences = count_occurences(cut_ciphertext)
            list_of_occurences.append(occurences)
        # print(list_of_occurences) # 
        pre_average_prob = []
        for cut_ciphertext in splitted:
            for value in list_of_occurences:
                a = calc_IC(value, cut_ciphertext)
                pre_average_prob.append(a)
        average = sum(pre_average_prob) / len(pre_average_prob)
        all_average_ICs.update({str(key_value) : average})
    max_5 = sorted(all_average_ICs, key=all_average_ICs.get, reverse=True)[:5]
    print("Calculations completed.")
    key = build_key(max_5, raw_ciphertext)
    transition(max_5, key, raw_ciphertext, orginal_ciphertext)

def decode_vigenere(ciphertext, key):
    ciphertext = ciphertext.lower()
    key = key.lower()
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    key_pair = ""
    str_all_special_char = ""    
    for x in range(0, len(ciphertext)):
        num_special_char = len(str_all_special_char)
        if ciphertext[x] not in alphabet:
            str_all_special_char += ciphertext[x]
            key_pair += ciphertext[x]
        if ciphertext[x] in alphabet:
            key_pair += key[(x - num_special_char) % len(key)]
    plaintext = ""
    for x in range(0, len(ciphertext)):
        cipher = ciphertext[x]
        plain = key_pair[x]
        if plain not in alphabet:
            plaintext += plain
        else:
            new = alphabet.index(cipher) - alphabet.index(plain)
            final = alphabet[new % 26]
            plaintext += final
    return plaintext

original_ciphertext = input("What text would you like to use with this? \n")
full_find_key(original_ciphertext)