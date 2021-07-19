# The (messy) code is my own, but I learned the mathematical concepts behind the cryptanalysis of the Vigènere cipher mainly from these websites:
    # http://practicalcryptography.com/cryptanalysis/stochastic-searching/cryptanalysis-vigenere-cipher/
    # http://practicalcryptography.com/cryptanalysis/stochastic-searching/cryptanalysis-vigenere-cipher-part-2/
    # http://practicalcryptography.com/cryptanalysis/text-characterisation/quadgrams/
    # https://en.wikipedia.org/wiki/Index_of_coincidence
# Also credit to where I derived the 26 English letter frequencies, and the 676 English bigram frequencies!
    # https://www3.nd.edu/~busiforc/handouts/cryptography/letterfrequencies.html
    # https://gist.github.com/lydell/c439049abac2c9226e53

alphabet = "abcdefghijklmnopqrstuvwxyz"

# Asks the user for the text they want to use (either ciphertext or plaintext)
def get_text():
    original_ciphertext = input("Print the text you want to use: ")
    return original_ciphertext

# Calculates the chi-squared value for each string (used to make the key)
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
    all_decrypted = []
    for i in range(0, 26):
        decrypted = caesar_decrypt(splitted, i)
        all_decrypted.append(decrypted)
        letters = {}
        for c in decrypted:
            if c not in letters:
                letters[c] = ""
        # occurences = []
        for x in letters:
            occurence = 0
            for c in decrypted:
                if x == c:
                    occurence += 1
            letters.update({x : str(occurence)})
        holds_values = []
        for letter in letters.keys(): 
            actual = letters[letter]
            expected = letter_frequencies[letter] * len(splitted)
            squared = (int(actual) - float(expected)) ** 2
            value = squared / expected
            holds_values.append(value)
        statistic = sum(holds_values)
        all_chi_sq.update({str(i) : str(statistic)})
    best_number = min(all_chi_sq, key=lambda x:float(all_chi_sq[x]))
    return(best_number)

# decrypts caesar cipher
def caesar_decrypt(ciphertext, key):
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

# encrypts the Vigenere cipher
def encrypt_vigenere(plaintext, key):
    plaintext = plaintext.lower()
    key = key.lower()
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    # By repeating the key, this creates a string of equal length to plain text
    # By adding to a list of special characters and account for those in the for loop, we can create a key_pair that repeats accurately.
    key_pair = ""
    str_all_special_char = ""    
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

# decrypts Vigenere cipher
def decrypt_vigenere(ciphertext, key):
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

# Finds the five most likely key lengths
def find_key_lengths(ciphertext):
    # Cleans up the input so that it is usable in the program
    raw_ciphertext = ciphertext.lower()
    for character in raw_ciphertext:
        if character not in alphabet:
            raw_ciphertext = raw_ciphertext.replace(character, "")
    #
    all_average_ICs = {}
    #
    for key_period in range(2, (len(raw_ciphertext) // 5)):
        all_sequences = []
        for x in range(0, key_period):
            new_sequence = ""
            y = x
            while y <= (len(raw_ciphertext) - 1):
                new_sequence += raw_ciphertext[y]
                y = y + key_period
            all_sequences.append(new_sequence)
        # 
        list_of_occurences = []
        for cut_ciphertext in all_sequences:
            letters = {}
            for c in cut_ciphertext:
                if c not in letters:
                    letters[c] = ""
            # occurences = []
            for x in letters:
                occurence = 0
                for c in cut_ciphertext:
                    if x == c:
                        occurence += 1
                letters.update({x : str(occurence)})
            list_of_occurences.append(letters.values())
        # 
        pre_average_prob = []
        for cut_ciphertext in all_sequences:
            # print(cut_ciphertext, list_of_occurences)
            for value in list_of_occurences:
                all_prob = []
                # print(value) # 
                for single in value:
                    # print(single) #
                    single = int(single)
                    ni = single / len(cut_ciphertext)
                    Ni = (single - 1) / (len(cut_ciphertext) - 1)
                    prob = ni * Ni
                    all_prob.append(prob)
                prob_sum = sum(all_prob)
                pre_average_prob.append(prob_sum)
        average_IC = sum(pre_average_prob) / len(pre_average_prob)
        all_average_ICs.update({str(key_period) : average_IC})
    max_5 = sorted(all_average_ICs, key=all_average_ICs.get, reverse=True)[:5]
    return max_5, raw_ciphertext

# Shows the key lengths, asks the user to pick a key, and builds the key
def show_key_lengths(five_most_likely_key_lengths, original_ciphertext):
    raw_ciphertext = original_ciphertext.lower()
    for character in raw_ciphertext:
        if character not in alphabet:
            raw_ciphertext = raw_ciphertext.replace(character, "")
    temp_values = []
    for value in five_most_likely_key_lengths:
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
        for x in five_most_likely_key_lengths:
            if n not in done:
                if (int(x) % int(n)) != 0:
                    common_factors.remove(int(n))
                    done.append(n)
            else:
                pass
    common_factors = sorted(common_factors)
    print("The following are 5 likely key lengths. Please note that if your ciphertext is particularly large, the actual key length may be a common factor of most of these values ")
    print(five_most_likely_key_lengths)
    print("If the key lengths are too big, try one of these common factors between them: ")
    print(common_factors)
    print("And if that list happened to be empty, here is a list of all factors for each number combined into one list: ")
    print(values)
    print("\n")
    key_length_decision = input("Please enter your selection by typing the key length you would like to test, without the quotes: ")
    key_length_decision = int(key_length_decision)
    # Splits the string and calculates chi-squared for each string
    all_sequences = []
    for x in range(0, key_length_decision):
        new_sequence = ""
        y = x
        while y <= (len(raw_ciphertext) - 1):
            new_sequence += raw_ciphertext[y]
            y = y + key_length_decision
        all_sequences.append(new_sequence)
    list_of_indices = []
    for string in all_sequences:
        chi_sq = crypto_chi_sq(string)
        list_of_indices.append(chi_sq)
    letters = []
    for value in list_of_indices:
        letters.append(alphabet[int(value)])
    key = ''.join(letters)
    return key


## BIGRAM ANALYSIS ##
# This function calculates the bigram fitness of a text
def bigram_fitness(text):
    all_bigram_freq = {
        'aa': -4.548222663447575,
        'ab': -2.6386756462564924,
        'ac': -2.348942873589147,
        'ad': -2.4342036173238237,
        'ae': -3.9067002242980937,
        'af': -3.129553401113842,
        'ag': -2.688829318601468,
        'ah': -3.8650807329906387,
        'ai': -2.4996979853983206,
        'aj': -3.929864923980115,
        'ak': -2.980056137639067,
        'al': -1.963590890547617,
        'am': -2.5453594298618714,
        'an': -1.7022064357788929,
        'ao': -4.334778658835183,
        'ap': -2.6928337484746967,
        'aq': -4.648903384893256,
        'ar': -1.9686325535493048,
        'as': -2.059934442868982,
        'at': -1.8277672229136537,
        'au': -2.9243334441462325,
        'av': -2.6883888502396576,
        'aw': -3.2224552749464666,
        'ax': -3.7249334266039287,
        'ay': -2.662818706220755,
        'az': -3.925581141794223,
        'ba': -2.835039364145017,
        'bb': -3.961256495958408,
        'bc': -4.723648487178723,
        'bd': -4.606583458599215,
        'be': -2.239363651943029,
        'bf': -5.836493173973478,
        'bg': -5.592668393869561,
        'bh': -4.976011029339253,
        'bi': -2.9722545346289673,
        'bj': -3.6340533359298672,
        'bk': -6.028676997726195,
        'bl': -2.6318988294695846,
        'bm': -4.504587209515477,
        'bn': -4.678888136871057,
        'bo': -2.709052035631077,
        'bp': -5.261908665869248,
        'bq': -6.910486424097333,
        'br': -2.952492071179374,
        'bs': -3.338827361335687,
        'bt': -3.766904288587336,
        'bu': -2.732959298352908,
        'bv': -4.415227724806438,
        'bw': -5.530080695044063,
        'bx': -6.558870512664986,
        'by': -2.753332979281495,
        'bz': -6.4470064455658305,
        'ca': -2.2690852780259467,
        'cb': -5.200951484204759,
        'cc': -3.080198937716542,
        'cd': -4.651505733972915,
        'ce': -2.186140669703658,
        'cf': -4.851359519241861,
        'cg': -5.05267998358011,
        'ch': -2.2234688067907085,
        'ci': -2.5505450467422413,
        'cj': -5.9786050912447415,
        'ck': -2.9294962126129596,
        'cl': -2.826780647317315,
        'cm': -4.574297822651766,
        'cn': -5.065491869689364,
        'co': -2.100256230885057,
        'cp': -4.881204789156546,
        'cq': -4.2616524367148205,
        'cr': -2.8254871373901307,
        'cs': -3.6416278977078003,
        'ct': -2.3363256823371157,
        'cu': -2.7888421287740117,
        'cv': -5.681602957560221,
        'cw': -5.858106737943852,
        'cx': -6.507328343574672,
        'cy': -3.3796701224033225,
        'cz': -5.136294103424009,
        'da': -2.820829348953864,
        'db': -4.557044620396448,
        'dc': -4.598754897762522,
        'dd': -3.3690491077979274,
        'de': -2.1164416777035044,
        'df': -4.55617208450654,
        'dg': -3.5085922492092787,
        'dh': -4.264529174871146,
        'di': -2.3071826767348593,
        'dj': -4.320401836000793,
        'dk': -5.472746720759542,
        'dl': -3.49025640554877,
        'dm': -3.7404840770138716,
        'dn': -4.12093835324986,
        'do': -2.725299688417316,
        'dp': -4.761282494172943,
        'dq': -5.1507356480257895,
        'dr': -3.0682884158373334,
        'ds': -2.8987318933596975,
        'dt': -4.538249866302591,
        'du': -2.828388288346784,
        'dv': -3.7200435386023027,
        'dw': -4.088181705401292,
        'dx': -6.337499367871219,
        'dy': -3.2973735641704014,
        'dz': -6.107635550405537,
        'ea': -2.1623072363889726,
        'eb': -3.5674543905934137,
        'ec': -2.3212242902060614,
        'ed': -1.9325112891017178,
        'ee': -2.422961793896999,
        'ef': -2.788526730946649,
        'eg': -2.9225007946443085,
        'eh': -3.579652793534451,
        'ei': -2.736715167428937,
        'ej': -4.342327505853012,
        'ek': -3.783258880853254,
        'el': -2.2754770961901905,
        'em': -2.427519161888184,
        'en': -1.837361388484107,
        'eo': -3.139659251443887,
        'ep': -2.7655491844437843,
        'eq': -3.242209661041643,
        'er': -1.6886138957136505,
        'es': -1.8730917316934184,
        'et': -2.3844621012499774,
        'eu': -3.506503822797857,
        'ev': -2.59382833342865,
        'ew': -2.9325356663566557,
        'ex': -2.6694957439143088,
        'ey': -2.8424050579981306,
        'ez': -4.344550096357842,
        'fa': -2.7851567203388634,
        'fb': -5.561970385814517,
        'fc': -5.2392265074365,
        'fd': -5.305099273962989,
        'fe': -2.6260344639779354,
        'ff': -2.8347064626745957,
        'fg': -5.291095692604729,
        'fh': -5.737028910420781,
        'fi': -2.5457870374532807,
        'fj': -6.13518544084267,
        'fk': -5.93257802148355,
        'fl': -3.1877226365361864,
        'fm': -5.163723288160309,
        'fn': -5.377467069273074,
        'fo': -2.3117995445820148,
        'fp': -5.653422052593354,
        'fq': -7.2757593867787715,
        'fr': -2.6712359921457116,
        'fs': -4.258886071010386,
        'ft': -3.087967413763646,
        'fu': -3.0178422843605124,
        'fv': -6.543163844628072,
        'fw': -5.640535741136626,
        'fx': -6.540579116351953,
        'fy': -4.041050543826707,
        'fz': -7.028823625128811,
        'ga': -2.8295121962168084,
        'gb': -5.305783273873955,
        'gc': -5.6402964961497934,
        'gd': -4.500379299945351,
        'ge': -2.41432554527035,
        'gf': -4.91919707145616,
        'gg': -3.6063417954507684,
        'gh': -2.643012183906394,
        'gi': -2.8191960721621587,
        'gj': -6.41156589585592,
        'gk': -5.5845665682587455,
        'gl': -3.2172639937142384,
        'gm': -4.006204605771214,
        'gn': -3.182837373510596,
        'go': -2.879005769307549,
        'gp': -5.385254851444299,
        'gq': -6.911593291132091,
        'gr': -2.7060237533402516,
        'gs': -3.2907879539399656,
        'gt': -3.812404844907714,
        'gu': -3.0666670776444174,
        'gv': -6.373787599485544,
        'gw': -5.188675385551197,
        'gx': -6.7043185976017865,
        'gy': -3.5860303368433013,
        'gz': -5.914751909433576,
        'ha': -2.0334999183443667,
        'hb': -4.357552550240609,
        'hc': -4.910725241041519,
        'hd': -4.54416228548905,
        'he': -1.5121914267296148,
        'hf': -4.649137175223285,
        'hg': -5.558673774849608,
        'hh': -5.281981906008546,
        'hi': -2.117337845004827,
        'hj': -6.342183833730998,
        'hk': -5.630942215435933,
        'hl': -3.899908131059436,
        'hm': -3.894720086599876,
        'hn': -3.589088244622976,
        'ho': -2.314345963200632,
        'hp': -5.227581391652832,
        'hq': -5.373725939863899,
        'hr': -3.073695964611904,
        'hs': -3.8331505701832755,
        'ht': -2.8854361295205653,
        'hu': -3.1325751675786657,
        'hv': -5.6513395895079785,
        'hw': -4.321103153431859,
        'hx': -7.028598191553595,
        'hy': -3.3002568584589476,
        'hz': -5.419598189811673,
        'ia': -2.543205298078741,
        'ib': -3.006110451487753,
        'ic': -2.155704602675174,
        'id': -2.5294367669016307,
        'ie': -2.414938341723186,
        'if': -2.691955523880288,
        'ig': -2.5935255991580037,
        'ih': -4.67959298151452,
        'ii': -3.642402448288015,
        'ij': -4.954313520947933,
        'ik': -3.3674137169947618,
        'il': -2.364984359594471,
        'im': -2.497900846310696,
        'in': -1.613903359620323,
        'io': -2.0783489712717547,
        'ip': -3.0495805870900323,
        'iq': -3.946777096466436,
        'ir': -2.5014518245720274,
        'is': -1.9475254215766786,
        'it': -1.9495143954059546,
        'iu': -3.7592263255754115,
        'iv': -2.5408364534320205,
        'iw': -5.204389270873309,
        'ix': -3.6569462360068363,
        'iy': -5.654484801162182,
        'iz': -3.1915206062950223,
        'ja': -3.5873464405892386,
        'jb': -6.122610431738421,
        'jc': -5.912683964339217,
        'jd': -6.032701077218914,
        'je': -3.2849373581452364,
        'jf': -6.066061777615913,
        'jg': -6.435298796284612,
        'jh': -5.900964688948538,
        'ji': -4.558660383411753,
        'jj': -5.9759882060358605,
        'jk': -6.209614740144386,
        'jl': -5.9460898121367585,
        'jm': -5.886770684726277,
        'jn': -5.832056167905342,
        'jo': -3.269301127579078,
        'jp': -5.662775889084674,
        'jq': -10.0,
        'jr': -5.614723622987186,
        'js': -5.927878430700728,
        'jt': -5.985134221186309,
        'ju': -3.2313439290569983,
        'jv': -6.214737925955404,
        'jw': -6.383530666000693,
        'jx': -7.241352893890079,
        'jy': -6.4008934734067235,
        'jz': -7.106444047971442,
        'ka': -3.770682593557542,
        'kb': -5.045257402281448,
        'kc': -5.6490664853030275,
        'kd': -5.173855849292559,
        'ke': -2.670057367500772,
        'kf': -4.799310908863834,
        'kg': -4.591253004283925,
        'kh': -4.496865151142212,
        'ki': -3.0093130041048655,
        'kj': -5.909722300454167,
        'kk': -5.343575809851947,
        'kl': -3.9759324193303813,
        'km': -4.747342727272647,
        'kn': -3.288708910658851,
        'ko': -4.216376539068204,
        'kp': -5.138598467161215,
        'kq': -7.1777939118930965,
        'kr': -4.565156181137908,
        'ks': -3.323225052274422,
        'kt': -4.9858241985500795,
        'ku': -4.519177688027059,
        'kv': -5.805270410052898,
        'kw': -4.661911851258445,
        'kx': -6.705574105278993,
        'ky': -4.2255042975545285,
        'kz': -7.27191105445325,
        'la': -2.277753295115726,
        'lb': -4.174554688496842,
        'lc': -3.9273122992413634,
        'ld': -2.5975556873320733,
        'le': -2.081312301897789,
        'lf': -3.2718338968343197,
        'lg': -4.215534683371267,
        'lh': -4.790822754067938,
        'li': -2.204570364542281,
        'lj': -5.949160800851855,
        'lk': -3.7052137890096155,
        'll': -2.2391471477925795,
        'lm': -3.637877335897202,
        'ln': -4.231374051873244,
        'lo': -2.412419006117275,
        'lp': -3.720550106782488,
        'lq': -5.895958859829066,
        'lr': -3.9977791261429014,
        'ls': -2.849202154219059,
        'lt': -2.90785119259522,
        'lu': -2.8690574952934966,
        'lv': -3.4571009995177926,
        'lw': -3.898291019228666,
        'lx': -5.51506986450982,
        'ly': -2.371597258564874,
        'lz': -5.379502273567,
        'ma': -2.2477445656635244,
        'mb': -3.044526216793349,
        'mc': -4.365294417151676,
        'md': -5.173069076077714,
        'me': -2.1007232606207182,
        'mf': -4.418124869169737,
        'mg': -4.911912283421296,
        'mh': -5.273125583854426,
        'mi': -2.49799458332953,
        'mj': -5.98432008259784,
        'mk': -5.852843974310659,
        'ml': -4.336625358346811,
        'mm': -3.017416675359399,
        'mn': -4.056007665978235,
        'mo': -2.4725278365522594,
        'mp': -2.6212838069348576,
        'mq': -6.599903917427903,
        'mr': -4.507790739851299,
        'ms': -3.03229684007065,
        'mt': -4.864300021006011,
        'mu': -2.940745156050181,
        'mv': -5.537840394048852,
        'mw': -5.233626031757187,
        'mx': -6.452664893408842,
        'my': -3.2063044908362235,
        'mz': -6.463299208505959,
        'na': -2.45937653996253,
        'nb': -4.362916926581435,
        'nc': -2.3811720844175266,
        'nd': -1.8689329107111792,
        'ne': -2.160068245110781,
        'nf': -3.172755292535869,
        'ng': -2.020900335661766,
        'nh': -3.9632229893659034,
        'ni': -2.469528181027521,
        'nj': -3.955209612740661,
        'nk': -3.2873043055070696,
        'nl': -3.1952888824902215,
        'nm': -3.5567450614708567,
        'nn': -3.1380792872997207,
        'no': -2.332944203883511,
        'np': -4.219271913093251,
        'nq': -4.225482091757565,
        'nr': -4.038495977267533,
        'ns': -2.293335588937203,
        'nt': -1.9824445054148174,
        'nu': -3.104331893541597,
        'nv': -3.2839369591216476,
        'nw': -4.236796316319534,
        'nx': -4.5815552366003836,
        'ny': -3.0091399270729204,
        'nz': -4.359611384597331,
        'oa': -3.2404374084474457,
        'ob': -3.0147046079937905,
        'oc': -2.7788334045051384,
        'od': -2.708965593520217,
        'oe': -3.413067813655289,
        'of': -1.9299712699177416,
        'og': -3.026760305323513,
        'oh': -3.6705132063184016,
        'oi': -3.0567491789621815,
        'oj': -4.156400204393283,
        'ok': -3.1917093014772067,
        'ol': -2.437121354093105,
        'om': -2.262603076098913,
        'on': -1.7549696611835055,
        'oo': -2.677244957002003,
        'op': -2.6499244701919156,
        'oq': -4.984403166314234,
        'or': -1.8939658914121995,
        'os': -2.5376517726144763,
        'ot': -2.3544762451823837,
        'ou': -2.0604795895833217,
        'ov': -2.749368891615328,
        'ow': -2.480857391336614,
        'ox': -3.731061528635214,
        'oy': -3.441516026079852,
        'oz': -4.459392329222665,
        'pa': -2.4900284345493713,
        'pb': -4.883153222028444,
        'pc': -4.929626328740923,
        'pd': -4.921301350147923,
        'pe': -2.320581929598475,
        'pf': -4.837177568609888,
        'pg': -5.324554851799865,
        'ph': -3.0250739230700496,
        'pi': -2.9097627458907915,
        'pj': -6.001371410134289,
        'pk': -5.086595318193745,
        'pl': -2.580065581306684,
        'pm': -3.7970715206289403,
        'pn': -4.924684251703793,
        'po': -2.442044080151505,
        'pp': -2.8647222949377764,
        'pq': -6.418768923681861,
        'pr': -2.323790403812556,
        'ps': -3.2630366040142547,
        'pt': -2.975587677595823,
        'pu': -2.9807166522237685,
        'pv': -5.656260475727077,
        'pw': -4.91824003925487,
        'px': -6.281856474720699,
        'py': -3.929454126065422,
        'pz': -5.645226773605947,
        'qa': -5.816901065651269,
        'qb': -6.415391115232232,
        'qc': -6.39811953796456,
        'qd': -6.7342598239624,
        'qe': -6.692464934171529,
        'qf': -6.473444281532243,
        'qg': -10.0,
        'qh': -7.029401730347954,
        'qi': -5.498150167958518,
        'qj': -7.075580794830044,
        'qk': -10.0,
        'ql': -5.623544634769077,
        'qm': -6.454619898424927,
        'qn': -6.180728604693747,
        'qo': -6.328190144282994,
        'qp': -7.015340973490442,
        'qq': -6.216637871249051,
        'qr': -6.208569778003091,
        'qs': -5.801973630468985,
        'qt': -6.308589085831087,
        'qu': -2.8310863186315194,
        'qv': -6.647072060983158,
        'qw': -7.237232274923797,
        'qx': -7.247422881803921,
        'qy': -10.0,
        'qz': -10.0,
        'ra': -2.163908267779491,
        'rb': -3.573289945747152,
        'rc': -2.915829107796379,
        'rd': -2.7228117973295296,
        're': -1.7318145701601841,
        'rf': -3.491330049062086,
        'rg': -3.000985009769788,
        'rh': -3.820690103094241,
        'ri': -2.138096048668838,
        'rj': -5.2571280166389815,
        'rk': -3.0130745113695943,
        'rl': -3.0641669644345075,
        'rm': -2.7566322000820507,
        'rn': -2.794901105845725,
        'ro': -2.138630233628682,
        'rp': -3.3806985115972097,
        'rq': -5.000679089953354,
        'rr': -2.918137840663854,
        'rs': -2.401726931837464,
        'rt': -2.441679813730294,
        'ru': -2.891676012682095,
        'rv': -3.1593713921765554,
        'rw': -3.8942391192336023,
        'rx': -4.931806797966042,
        'ry': -2.606003653631233,
        'rz': -5.1950905137679095,
        'sa': -2.66150875279505,
        'sb': -4.1014790276536965,
        'sc': -2.8103710839852214,
        'sd': -4.279128600292413,
        'se': -2.0305306991476226,
        'sf': -3.7653698299266187,
        'sg': -4.607658553412618,
        'sh': -2.5013586762156548,
        'si': -2.259592112749643,
        'sj': -5.568136956680087,
        'sk': -3.4037912777301296,
        'sl': -3.25273831778867,
        'sm': -3.1857589037290763,
        'sn': -4.037396012051141,
        'so': -2.400409292999347,
        'sp': -2.7183889708322377,
        'sq': -4.128196753605174,
        'sr': -4.222576947332573,
        'ss': -2.392464335403656,
        'st': -1.9773754947831468,
        'su': -2.5069931603585305,
        'sv': -4.90606703920965,
        'sw': -3.6284112725493625,
        'sx': -6.747963157788898,
        'sy': -3.2453099144828115,
        'sz': -5.602559631523034,
        'ta': -2.275817496814983,
        'tb': -4.594398479151824,
        'tc': -3.5827561851966534,
        'td': -4.88743446412571,
        'te': -1.9190599408632092,
        'tf': -4.247091911671585,
        'tg': -4.705725221589991,
        'th': -1.449013408773307,
        'ti': -1.8720602093250045,
        'tj': -5.949184778024266,
        'tk': -5.333523337215767,
        'tl': -3.0067878896273927,
        'tm': -3.577096967647343,
        'tn': -3.9995376465569077,
        'to': -1.9824380910337431,
        'tp': -4.367091088246212,
        'tq': -6.049244955369915,
        'tr': -2.3707737626383385,
        'ts': -2.4717413910772974,
        'tt': -2.7678089621682562,
        'tu': -2.593618716161753,
        'tv': -4.934247199012132,
        'tw': -3.0842191642998364,
        'tx': -5.92789669498788,
        'ty': -2.64344431896216,
        'tz': -4.414657224287228,
        'ua': -2.865398202677351,
        'ub': -3.0526626887758117,
        'uc': -2.726646195741196,
        'ud': -3.0390467418089853,
        'ue': -2.831265848555652,
        'uf': -3.7320711113883878,
        'ug': -2.8931037325660305,
        'uh': -4.971671752770931,
        'ui': -2.995019890020054,
        'uj': -5.28739317438822,
        'uk': -4.336855912971723,
        'ul': -2.4611379709719414,
        'um': -2.858918464909151,
        'un': -2.4040487279173344,
        'uo': -3.972375624660128,
        'up': -2.866421231312593,
        'uq': -5.590715010425874,
        'ur': -2.2654019430633774,
        'us': -2.342698314979266,
        'ut': -2.3923827973316807,
        'uu': -5.107638411894739,
        'uv': -4.535048863092271,
        'uw': -5.556740366327395,
        'ux': -4.405078621355358,
        'uy': -4.340340260799976,
        'uz': -4.718819549366344,
        'va': -2.853933779548295,
        'vb': -6.05295016628065,
        'vc': -5.632575960514301,
        'vd': -5.524352505055799,
        've': -2.0833983816938844,
        'vf': -6.259776673915574,
        'vg': -5.978866152694709,
        'vh': -6.020270897403646,
        'vi': -2.569369768148087,
        'vj': -6.59023672765209,
        'vk': -6.921865503992905,
        'vl': -5.3849529719859754,
        'vm': -5.948012817020335,
        'vn': -5.814937477552239,
        'vo': -3.1480865147970962,
        'vp': -5.709041958705207,
        'vq': -7.1221112866215135,
        'vr': -5.057478463044229,
        'vs': -5.23898989857728,
        'vt': -5.659072959628603,
        'vu': -4.655117512001526,
        'vv': -6.031469928694747,
        'vw': -6.579683255012601,
        'vx': -6.797125596750155,
        'vy': -4.3100500153330135,
        'vz': -6.750195652616059,
        'wa': -2.414159201257363,
        'wb': -4.974103337253095,
        'wc': -5.171254956580529,
        'wd': -4.451208258956919,
        'we': -2.442614041378416,
        'wf': -4.793806185222093,
        'wg': -6.010582999894938,
        'wh': -2.421597560649253,
        'wi': -2.426640145429843,
        'wj': -6.489165942528731,
        'wk': -4.97169225793324,
        'wl': -3.8175518154507873,
        'wm': -4.962603080179702,
        'wn': -3.1024410988929785,
        'wo': -2.6541279207434574,
        'wp': -5.128338999341575,
        'wq': -10.0,
        'wr': -3.511997287579058,
        'ws': -3.454889511358748,
        'wt': -4.18432713665237,
        'wu': -5.157904397816212,
        'wv': -6.860110281705221,
        'ww': -5.582280959890872,
        'wx': -7.272265525295624,
        'wy': -4.615338254051918,
        'wz': -10.0,
        'xa': -3.5286928994656455,
        'xb': -6.114794651094795,
        'xc': -3.57741394297699,
        'xd': -7.224208555445288,
        'xe': -3.661651887848588,
        'xf': -4.731079457528576,
        'xg': -6.715759016354562,
        'xh': -4.379720933790749,
        'xi': -3.40430192604359,
        'xj': -6.741713395689289,
        'xk': -7.001096931389237,
        'xl': -5.226746517167218,
        'xm': -5.6326832445864,
        'xn': -6.242398337426817,
        'xo': -4.568828603072591,
        'xp': -3.174808736626274,
        'xq': -5.5350329757871926,
        'xr': -6.49239410079481,
        'xs': -6.193782539149014,
        'xt': -3.331050379588835,
        'xu': -4.321383977801424,
        'xv': -4.709229153968336,
        'xw': -5.651372233568942,
        'xx': -4.552195078440781,
        'xy': -4.588986451310203,
        'xz': -7.314997722457417,
        'ya': -3.8022835342200265,
        'yb': -4.366620313274909,
        'yc': -3.8696479880752337,
        'yd': -4.166341418343512,
        'ye': -3.033067510252263,
        'yf': -5.122906985217471,
        'yg': -4.586265179528648,
        'yh': -5.283385726772215,
        'yi': -3.5403101600278997,
        'yj': -6.700975834997984,
        'yk': -5.482060687654972,
        'yl': -3.8310179344785773,
        'ym': -3.625712174865852,
        'yn': -3.8789597934393525,
        'yo': -2.8241937022250414,
        'yp': -3.6035508880371916,
        'yq': -6.86486958256353,
        'yr': -4.108374106310939,
        'ys': -3.013979920968542,
        'yt': -3.777702302016642,
        'yu': -4.876905018403649,
        'yv': -5.7412867666924505,
        'yw': -4.472152469625221,
        'yx': -5.825792140661269,
        'yy': -6.1506861800773915,
        'yz': -4.741793680720587,
        'za': -3.603736793509444,
        'zb': -5.682432173262262,
        'zc': -6.127813094670284,
        'zd': -6.299435832647946,
        'ze': -3.3033591554448085,
        'zf': -6.666015830056445,
        'zg': -5.775643462822719,
        'zh': -5.176438930064484,
        'zi': -3.9165888229615278,
        'zj': -6.9601979466894575,
        'zk': -6.492811648855657,
        'zl': -4.900497020890091,
        'zm': -5.7768437209771175,
        'zn': -5.816676009520905,
        'zo': -4.143813955050393,
        'zp': -6.316069183680191,
        'zq': -6.489709281607672,
        'zr': -5.724243266426349,
        'zs': -5.526129719078985,
        'zt': -5.628857341840978,
        'zu': -4.667059680389949,
        'zv': -5.7856769587984145,
        'zw': -5.652286919093769,
        'zx': -7.415873601649189,
        'zy': -4.627550675547285,
        'zz': -4.575062993442338
    }
    text = text.lower()
    text = text.split()
    for x in range(0, len(text)):
        word = text[x]
        for character in word:
            if character not in alphabet:
                word = word.replace(character, "")
                text.pop(x)
                text.insert(x, word)
    every_bigram = []
    for x in range(0, (len(text))):
        word = text[x]
        for y in range(0, (len(word) - 1)):
            first = word[y]
            second = word[y + 1]
            bigram = first + second
            every_bigram.append(bigram)
    fitness = 0
    for bigram in every_bigram:
        key = bigram
        value = all_bigram_freq.get(key)
        fitness += float(value)
    return(fitness)

# Creates a key based on bigram analysis
def bigram_analysis(parent_key, original_ciphertext):

    # cleans up the parent_key
    parent_key = parent_key.lower()
    best_fitness_key = parent_key
    key_listed = list(best_fitness_key)
    # empty lists to hold all the parent keys
    # (the lists are used to determine when the fitness cannot be improved anymore)
    key_one = []
    key_two = []
    # lists can't be empty, so the key is added to list one,
    # and a place holder is added to list two
    key_one.append(best_fitness_key)
    key_two.append("A" * len(best_fitness_key))

    while key_one[-1] != key_two[-1]:
        key_two.append(best_fitness_key)
        for x in range(0, len(key_listed)):
            key_listed = list(best_fitness_key)
            character_position = alphabet.index(key_listed[x])
            for y in range(0, 27):
                new_character = alphabet[(character_position + (y)) % 26]
                key_listed[x] = new_character
                trial_key = "".join(key_listed)
                # print(trial_key)
                best_result = decrypt_vigenere(original_ciphertext, best_fitness_key)
                best_fitness = bigram_fitness(best_result)
                plaintext_result = decrypt_vigenere(original_ciphertext, trial_key)
                fitness = bigram_fitness(plaintext_result)
                # print(fitness)
                if fitness > best_fitness:
                    # print("THE BEST KEY HAS BEEN CHANGED! IT IS NOW " + trial_key)
                    # print("The new best fitness is " + str(fitness))
                    # print("The best plaintext is now: " + plaintext_result)
                    # print(key_one) #
                    # print(key_two) # 
                    best_fitness_key = trial_key
                    key_one.append(best_fitness_key)
                    if len(key_one) > 5:
                        for x in range(0, 3):
                            key_one.pop(x)
                    if len(key_two) > 5:
                        for x in range(0, 3):
                            key_two.pop(x)
            # sleep(3) # 
        # print(best_fitness_key) # 
    return best_fitness_key


## INTERACTIVE FUNCTIONS ##
# Asks to go back to introduction or to quit
def introduction():
    answer = input("""Use the numbers below to specify what you'd like to do!
    1. Encrypt a message
    2. Decrypt a message
    3. Decrypt a message without the key!
    Your answer: """)
    print("\n")
    if answer == "1":
        plaintext = get_text()
        key = input("Enter the key you want to use to encrypt this message: ")
        encrypted = encrypt_vigenere(plaintext, key)
        print(encrypted)
        print("\n")
        end_card()
    elif answer == "2":
        ciphertext = get_text()
        key = input("Enter the key you want to use to decrypt this message: ")
        decrypted = decrypt_vigenere(ciphertext, key)
        print(decrypted)
        print("\n")
        end_card()
    elif answer == "3":
        ciphertext = get_text()
        key_lengths, raw_ciphertext = find_key_lengths(ciphertext)
        chosen_key = show_key_lengths(key_lengths, raw_ciphertext)
        final_key = transition_change_key(chosen_key, ciphertext, key_lengths)
        decrypted = decrypt_vigenere(ciphertext, final_key)
        print(decrypted)
        print( "\n")
        end_card()
    else:
        print("Sorry, that wasn't a valid option. Please try again! \n")
        introduction

def transition_change_key(key, original_ciphertext, five_most_likely_key_lengths):
    print("You have the following key now:  " + key.upper())
    answer = input("""You may choose to do the following:
    1. Keep the key
    2. Edit the key
    3. Pick a different key length
    4. Use bigram analysis to improve the key
    Your answer: """)
    print("\n")
    if answer == "1":
        print("Your key is " + key.upper())
        return key
    elif answer == "2":
        key = input("Enter the key you would like to use: ") 
        key = transition_change_key(key, original_ciphertext, five_most_likely_key_lengths)
        return key
    elif answer == "3":
        key = show_key_lengths(five_most_likely_key_lengths, original_ciphertext)
        key = transition_change_key(key, original_ciphertext, five_most_likely_key_lengths)
        return key
    elif answer == "4":
        key = bigram_analysis(key, original_ciphertext)
        key = transition_change_key(key, original_ciphertext, five_most_likely_key_lengths)
        return key
    else:
        print("Sorry, that wasn't a valid option. Please try again! \n")
        key = transition_change_key(key, original_ciphertext, five_most_likely_key_lengths)
        return key

def end_card():
    answer = input("""What would you like to do now?
    1. Go back to main menu
    2. Quit
    Your answer: """)
    print("\n")
    if answer == "1":
        introduction()
    elif answer == "2":
        quit()
    else:
        print("Sorry, that wasn't a valid option. Please try again! \n")
        end_card()


introduction()
