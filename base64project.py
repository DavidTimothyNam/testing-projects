def intro():
    welcome = """Please state what base64 function you would like to preform:
    1. encode
    2. decode"""
    print(welcome)
    answer = input()
    if answer == "1" or answer == "encode":
        encode_b64()
    elif answer == "2" or answer == "decode":
        print("Not available yet, lol!")
        intro()
    else:
        intro()
    
def ask_continue():
    answer = input("Would you like to continue? (y/n) \n")
    if answer.lower() == "y" or answer.lower() == "yes":
        intro()
    elif answer.lower() == "n" or answer.lower() == "no":
        quit()

def encode_b64():
    b64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    text = input("What string would you like to encode?\n")
    # converts to the characters to padded binary characters (8-bit)
    binary_values = []
    for character in text:
        asc = ord(character)
        binary = format(asc, "08b")
        binary_values.append(binary)
    # joins the binary values into a single string
    combined = ''.join(binary_values)
    # converts binary into a string so it can be padded with 0's
    combined = str(combined)
    while len(combined) % 6 != 0:
        combined = combined + "0"
    # splits the binary string into 6-bit groups
    pre_b64 = []
    for i in range(0, len(combined), 6):
        pre_b64.append(combined[i:i+6])
    # puts together each encoded character in one string
    zero_padded = []
    for item in pre_b64:
        decimal = int(item, base = 2)
        char = b64_alphabet[decimal]
        zero_padded.append(char)
    zero_padded = ''.join(zero_padded)
    # pads with "=" signs so that the total number of characters is divisible by 4
    equal_padded = zero_padded
    while len(equal_padded) % 4 != 0:
        equal_padded = equal_padded + "="
    final = equal_padded
    print(final)
    ask_continue()

intro()

quit()