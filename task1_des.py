#Amanda Illona Farrel
#5025221056
#Keamanan Informasi B
#Task 1 DES Algorithm

def initial_permutation(block):
    # Tabel permutasi awal
    ip = [58, 50, 42, 34, 26, 18, 10, 2,
          60, 52, 44, 36, 28, 20, 12, 4,
          62, 54, 46, 38, 30, 22, 14, 6,
          64, 56, 48, 40, 32, 24, 16, 8,
          57, 49, 41, 33, 25, 17, 9, 1,
          59, 51, 43, 35, 27, 19, 11, 3,
          61, 53, 45, 37, 29, 21, 13, 5,
          63, 55, 47, 39, 31, 23, 15, 7]
    # Mengembalikan blok yang sudah dipermutasi
    return ''.join([block[i-1] for i in ip])

def final_permutation(block):
    # Tabel permutasi akhir
    fp = [40, 8, 48, 16, 56, 24, 64, 32,
          39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30,
          37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28,
          35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18, 58, 26,
          33, 1, 41, 9, 49, 17, 57, 25]
    # Mengembalikan blok yang sudah dipermutasi
    return ''.join([block[i-1] for i in fp])

# Tabel ekspansi
EXPANSION_TABLE = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
                   12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23,
                   24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

# Tabel S-Box
S_BOX = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
    [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
    [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
    [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
]

def expand(block):
    # Mengembalikan blok yang sudah diekspansi
    return ''.join([block[i-1] for i in EXPANSION_TABLE])

def s_box_substitution(expanded_half_block):
    # Memastikan kita memproses dalam potongan 6 bit
    substituted = ""
    for i in range(0, len(expanded_half_block) - 5, 6):  # Memastikan potongan adalah 6 bit
        row = int(expanded_half_block[i] + expanded_half_block[i + 5], 2)
        col = int(expanded_half_block[i + 1:i + 5], 2)
        substituted += bin(S_BOX[row][col])[2:].zfill(4)
    return substituted

def feistel_function(right, key):
    # Ekspansi blok kanan
    expanded_right = expand(right)
    # XOR dengan kunci
    xored = bin(int(expanded_right, 2) ^ int(key, 2))[2:].zfill(48)
    # Substitusi dengan S-Box
    substituted = s_box_substitution(xored)
    return substituted

def rotate_key(key, round_number):
    # Rotasi kunci berdasarkan nomor ronde
    return key[round_number:] + key[:round_number]

def des_encrypt_block(block, key):
    # Permutasi awal
    block = initial_permutation(block)
    left, right = block[:32], block[32:]
    
    for round_number in range(16):
        temp = right
        round_key = rotate_key(key, round_number)
        # Fungsi Feistel dan XOR dengan bagian kiri
        right = bin(int(left, 2) ^ int(feistel_function(right, round_key), 2))[2:].zfill(32)
        left = temp
    
    # Permutasi akhir
    block = final_permutation(right + left)
    return block

def des_decrypt_block(block, key):
    # Permutasi awal
    block = initial_permutation(block)
    left, right = block[:32], block[32:]
    
    for round_number in range(15, -1, -1):
        temp = left
        round_key = rotate_key(key, round_number)
        # Fungsi Feistel dan XOR dengan bagian kanan
        left = bin(int(right, 2) ^ int(feistel_function(left, round_key), 2))[2:].zfill(32)
        right = temp
    
    # Permutasi akhir
    block = final_permutation(left + right)
    return block

def pad(text):
    # Menambahkan padding hingga panjang teks kelipatan 8
    while len(text) % 8 != 0:
        text += ' '
    return text

def unpad(text):
    # Menghapus padding
    return text.rstrip()

def encrypt(text, key):
    # Mengubah teks dan kunci menjadi biner
    text_bin = ''.join(format(ord(c), '08b') for c in pad(text))
    key_bin = ''.join(format(ord(c), '08b') for c in key)
    
    encrypted_bin = ''
    for i in range(0, len(text_bin), 64):
        block = text_bin[i:i+64].ljust(64, '0')
        # Enkripsi blok
        encrypted_bin += des_encrypt_block(block, key_bin)
    
    # Mengubah biner terenkripsi menjadi heksadesimal
    encrypted_text = ''.join(format(int(encrypted_bin[i:i+4], 2), 'x') for i in range(0, len(encrypted_bin), 4))
    return encrypted_text

def decrypt(encrypted_text, key):
    # Mengubah teks terenkripsi dari heksadesimal ke biner
    encrypted_bin = ''.join(format(int(c, 16), '04b') for c in encrypted_text)
    key_bin = ''.join(format(ord(c), '08b') for c in key)
    
    decrypted_bin = ''
    for i in range(0, len(encrypted_bin), 64):
        block = encrypted_bin[i:i+64].ljust(64, '0')
        # Dekripsi blok
        decrypted_bin += des_decrypt_block(block, key_bin)
    
    # Mengubah biner terdekripsi menjadi teks
    decrypted_text = ''.join(chr(int(decrypted_bin[i:i+8], 2)) for i in range(0, len(decrypted_bin), 8))
    return unpad(decrypted_text)

# Contoh penggunaan
text = "amandail"
key = "12345678"

encrypted_text = encrypt(text, key)
decrypted_text = decrypt(encrypted_text, key)

print(f"Text: {text}")
print(f"Key: {key}")
print(f"Encrypted Text: {encrypted_text}")
print(f"Decrypted Text: {decrypted_text}")
