import hashlib
import binascii
import random
import numpy as np
import time

def hash_and_split_key(input_key: str):
    # Step 1: Hash the input key using SHA-512 to generate a 512-bit hash
    sha512_hash = hashlib.sha512(input_key.encode()).hexdigest()
    
    # Step 2: Split the 512-bit hash (hexadecimal string) into 4 equal parts
    # SHA-512 hash is 128 hexadecimal characters long (each hex character is 4 bits)
    part_length = len(sha512_hash) // 4
    
    part1 = sha512_hash[:part_length]
    part2 = sha512_hash[part_length:2*part_length]
    part3 = sha512_hash[2*part_length:3*part_length]
    part4 = sha512_hash[3*part_length:]
    
    # Return the 4 parts
    return part1, part2, part3, part4

# Example usage:
# input_key = "ark"
# parts = hash_and_split_key(input_key)
# print("Part 1:", parts[0])
# print("Part 2:", parts[1])
# print("Part 3:", parts[2])
# print("Part 4:", parts[3])


# PKCS#7 Padding function
def pkcs7_pad(data: bytes, block_size: int = 16):
    # Calculate padding length needed to reach multiple of block size
    pad_length = block_size - (len(data) % block_size)
    # Add padding bytes, each of them equal to the pad_length
    padding = bytes([pad_length] * pad_length)
    return data + padding

# Function to convert input to hex and apply PKCS#7 padding
def process_input(input_data, block_size: int = 16):
    # Convert input data into bytes if it's not already
    if isinstance(input_data, str):
        # If input is a string (text or emojis), encode it using UTF-8
        input_bytes = input_data.encode('utf-8')
    elif isinstance(input_data, bytes):
        # If input is already bytes (e.g., binary file data), use it as is
        input_bytes = input_data
    else:
        raise ValueError("Unsupported input format. Provide either a string or bytes.")

    # Apply PKCS#7 padding to make sure the length is a multiple of block size (16 bytes)
    padded_bytes = pkcs7_pad(input_bytes, block_size)

    # Convert padded bytes to hexadecimal string representation
    hex_string = binascii.hexlify(padded_bytes).decode('utf-8')

    return hex_string

# Example usage:
# For string input with emojis
# input_str = "ark"
# processed_str = process_input(input_str)
# print("Processed Hex String:", processed_str)



# Function to remove PKCS#7 padding
def pkcs7_unpad(padded_data: bytes, block_size: int = 16):
    # The padding length is stored in the value of the last byte
    pad_length = padded_data[-1]
    # Ensure the padding length is valid and then remove it
    if pad_length > block_size or pad_length <= 0:
        print(pad_length)
        raise ValueError("Invalid padding detected.")
    # Check that the padding is valid (all padding bytes should be the same)
    if padded_data[-pad_length:] != bytes([pad_length] * pad_length):
        raise ValueError("Invalid padding detected.")
    # Return the original data without the padding
    return padded_data[:-pad_length]

# Function to reverse the hexadecimal representation and return original data
def reverse_process(hex_data: str, block_size: int = 16):
    # Convert the hex string back to bytes
    padded_bytes = binascii.unhexlify(hex_data)
    
    # Remove PKCS#7 padding
    original_bytes = pkcs7_unpad(padded_bytes, block_size)
    
    try:
        # Attempt to decode as UTF-8 string (for string data)
        original_str = original_bytes.decode('utf-8')
        return original_str
    except UnicodeDecodeError:
        # If decoding fails, return the raw bytes (for binary data)
        return original_bytes

# Example usage:
# reversed_str = reverse_process(processed_str)
# print("Reversed String:", reversed_str)



# Function to generate a 16x16 substitution matrix from a 512-bit key
def generate_substitution_matrix(key_512: str):
    # Ensure the input key is 512 bits (128 hex characters)
    if len(key_512) != 128:
        raise ValueError("The input key must be a 512-bit hexadecimal string.")
    
    # Convert the 512-bit key (hex string) into bytes
    key_bytes = bytes.fromhex(key_512)
    
    # Use the key to seed the random number generator for reproducibility
    seed = int.from_bytes(key_bytes, byteorder='big')
    random.seed(seed)
    
    # Generate a list of values from 0x00 to 0xff (0 to 255 in decimal)
    substitution_values = list(range(256))
    
    # Shuffle the values using the seeded random generator
    random.shuffle(substitution_values)
    
    # Create a 16x16 matrix from the shuffled values in hexadecimal format
    substitution_matrix = [[format(value, '02x') for value in substitution_values[i:i + 16]] 
                           for i in range(0, 256, 16)]
    
    return substitution_matrix

# Function to print the substitution matrix in hexadecimal format
# def print_matrix(matrix):
#     for row in matrix:
#         print(" ".join(f"{val:02x}" for val in row))

# Example usage:
# key_512 = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6'  # Example key
# key_512 = os.urandom(64).hex()  # Generate a valid 512-bit key for testing
# print(f"Generated key: {key_512}")

# substitution_matrix = generate_substitution_matrix(key_512)
# print("Substitution Matrix:")
# print_matrix(substitution_matrix)

def hex_to_matrix_blocks(hex_string: str):
    # Check if the input string length is valid
    if len(hex_string) % 32 != 0:
        raise ValueError("Input hexadecimal string length must be a multiple of 32 characters (128 bits).")
    
    # Calculate the number of rows
    num_rows = len(hex_string) // 32
    
    # Initialize the result matrix
    matrix = []
    
    # Iterate through the hex string and create matrix rows
    for i in range(num_rows):
        start = i * 32
        end = start + 32
        row = hex_string[start:end]
        # Split the row into 16 pairs of characters (bytes)
        matrix_row = [row[j:j+2] for j in range(0, 32, 2)]
        matrix.append(matrix_row)
    
    return matrix

# Function to print the matrix blocks in a readable format
# def print_matrix(matrix):
#     for block in matrix:
#         print("Matrix block:")
#         for row in block:
#             print(" ".join(row))
#         print()  # Separate blocks for clarity

# Example usage
# hex_string = '0123456789abcdef0123456789abcdeff123456789abcdef0123456789abcdef' * 4  # 512-bit string (128 hex characters)
# matrix_blocks = hex_to_matrix_blocks(hex_string)

# # Print the result
# print_matrix(matrix_blocks)

def substitute_matrix(input_matrix, substitution_matrix):
    # Ensure the substitution matrix is 16x16
    if len(substitution_matrix) != 16 or any(len(row) != 16 for row in substitution_matrix):
        raise ValueError("The substitution matrix must be 16x16.")
    
    # Create a new matrix to store the substituted values
    substituted_matrix = []
    
    # Iterate over each row of the input matrix
    for row in input_matrix:
        new_row = []
        for element in row:
            # Convert the hex element to an integer to find its row and column
            index = int(element, 16)  # Convert hex to integer
            row_index = index // 16    # Determine the row in substitution matrix
            col_index = index % 16     # Determine the column in substitution matrix
            
            # Get the substitute value from the substitution matrix
            new_value = substitution_matrix[row_index][col_index]
            new_row.append(new_value)  # Add the substituted value to the new row
        
        substituted_matrix.append(new_row)  # Add the new row to the substituted matrix
    
    return substituted_matrix

# Function to print the matrix blocks in a readable format
# def print_matrix(matrix):
#     for row in matrix:
#         print(" ".join(row))
#     print()  # Separate blocks for clarity

# # Example usage
# input_matrix = [
#     ['2a', '3b', '4c', '5d', '6e', '7f', '8a', '9b', 'aa', 'bb', 'cc', 'dd', 'ee', 'ff', '00', '01'],
#     ['12', '23', '34', '45', '56', '67', '78', '89', '9a', 'ab', 'bc', 'cd', 'de', 'ef', '10', '21']
# ]

# substitution_matrix = generate_substitution_matrix(hashlib.sha512('ark'.encode()).hexdigest())
# # Substitute the input matrix using the substitution matrix
# substituted_matrix = substitute_matrix(input_matrix, substitution_matrix)

# # Print the result
# print("Substituted Matrix:")
# print_matrix(substituted_matrix)

def reverse_substitute_matrix(input_matrix, substitution_matrix):
    # Ensure the substitution matrix is 16x16
    if len(substitution_matrix) != 16 or any(len(row) != 16 for row in substitution_matrix):
        raise ValueError("The substitution matrix must be 16x16.")
    
    # Create a new matrix to store the reverse substituted values
    reverse_substituted_matrix = []
    
    # Create a reverse mapping from the substitution matrix
    reverse_mapping = {}
    for row in range(16):
        for col in range(16):
            original_value = substitution_matrix[row][col]
            reverse_mapping[original_value] = f'{row:01x}' + f'{col:01x}'  # store reverse mapping as single bytes
    
    # Iterate over each row of the input matrix
    for row in input_matrix:
        new_row = []
        for element in row:
            # Use the reverse mapping to find the original value
            new_value = reverse_mapping.get(element, element)  # Default to element if not found
            new_row.append(new_value.zfill(2))  # Ensure the output is two characters (1 byte)
        
        reverse_substituted_matrix.append(new_row)  # Add the new row to the reverse substituted matrix
    
    return reverse_substituted_matrix

# Example usage of reverse substitution
# Assume input_matrix is the result of a previous substitution operation
# input_matrix = substituted_matrix

# # Use the same substitution matrix as defined earlier
# substitution_matrix = generate_substitution_matrix(hashlib.sha512('ark'.encode()).hexdigest())

# # Reverse substitute the input matrix using the substitution matrix
# reversed_matrix = reverse_substitute_matrix(input_matrix, substitution_matrix)

# # Print the result
# print("Reversed Substituted Matrix:")
# print_matrix(reversed_matrix)

def calculate_pivots(matrix):
    pivots = []
    for row in matrix:
        # Convert the first element from hex string to integer for the initial pivot
        pivot = int(row[0], 16)
        for element in row[1:]:
            pivot ^= int(element, 16)  # Convert each hex string to integer and XOR
        pivots.append(pivot)
    return pivots

def three_param_cascading_xor(matrix, pivots, byte_str):
    byte_val = int(byte_str, 16)  # Convert the 2-character hex string to an integer
    result_matrix = []
    
    for i, row in enumerate(matrix):
        pivot = pivots[i]
        result_row = []
        
        # Start cascading XOR
        first_xor = int(row[0], 16) ^ pivot ^ byte_val
        result_row.append(first_xor)
        
        # Continue cascading XOR for the rest of the row
        for j in range(1, len(row)):
            next_xor = int(row[j], 16) ^ pivot ^ result_row[-1]
            result_row.append(next_xor)
        
        result_matrix.append(result_row)
    
    return np.array(result_matrix)

def rev_calculate_pivots(input_matrix, byte_str):
    if len(byte_str) < 2:
        raise ValueError("byte_str must be 2 characters long (1 byte).")

    # Convert the byte_str to an integer
    key_byte_int = int(byte_str, 16)
    
    pivots = []
    
    for row in input_matrix:
        # Convert each element to int for XOR operations
        row_ints = [int(byte, 16) for byte in row]
        
        # Create the right-shifted version of the row with the left-most byte as key_byte
        right_shifted = [key_byte_int] + row_ints[:-1]  # Right-shift and add key_byte on the left
        
        # XOR the row with the right-shifted version
        xor_result = [r ^ rs for r, rs in zip(row_ints, right_shifted)]
        
        # Calculate the pivot by XORing all the values in xor_result
        pivot = 0
        for val in xor_result:
            pivot ^= val
        
        # Store the pivot as a hexadecimal string
        pivots.append(pivot)
    
    return pivots

def reverse_3_parameter_cascading_xor(input_matrix, key, pivots):
    original_matrix = []
    
    # Ensure the key is 2 characters long (1 byte)
    key_byte = int(key, 16)  # Fixed to 'ac'
    
    # Iterate over each row of the input matrix
    for row_idx, row in enumerate(input_matrix):
        pivot = pivots[row_idx]  # Get the pivot for the current row
        
        # Step 1: XOR the first byte of the row with the key_byte
        leftmost_byte = int(row[0], 16)  # Convert the first element to an integer
        shifted_row = [key_byte] + [int(row[i], 16) for i in range(len(row) - 1)]  # 1-byte shift to the right
        
        # XOR each byte in the shifted row with the corresponding original row byte
        xored_row = [leftmost_byte ^ shifted_row[0]] + [
            int(row[i], 16) ^ shifted_row[i] for i in range(1, len(row))
        ]
        
        # Step 2: XOR all bytes in the result to calculate pivot
        calculated_pivot = 0
        for byte in xored_row:
            calculated_pivot ^= byte
        
        # Compare calculated pivot with provided pivot
        if calculated_pivot != pivot:
            raise ValueError(f"Calculated pivot {calculated_pivot} does not match provided pivot {pivot}.")
        
        # Step 3: XOR each byte in the row with the pivot
        original_row = [(byte ^ pivot) & 0xff for byte in xored_row]  # XOR and ensure 1-byte result
        
        # Convert the row back to hex format (2 characters per element)
        original_matrix.append([f'{byte:02x}' for byte in original_row])
    
    return original_matrix

# Example usage
# input_matrix = [
#     ['80', '89', 'd1', 'cf']
# ]

# byte_str = "ac"  # The 1 byte (13th and 14th characters of the key)

# # Calculate the pivots
# pivots = rev_calculate_pivots(input_matrix, byte_str)

# # Perform the reverse 3-parameter cascading XOR
# reversed_matrix = reverse_3_parameter_cascading_xor(input_matrix, byte_str, pivots)

# # Print results
# print("Pivots:", pivots)
# print("Reversed Matrix:")
# for row in reversed_matrix:
#     print(row)

def hex_to_matrix(hex_string):
    if len(hex_string) != 32:
        raise ValueError("The input hex string must be 128 bits (32 hex characters).")
    
    # Split the hex string into 1-byte (2 characters) chunks
    matrix = [hex_string[i:i+2] for i in range(0, len(hex_string), 2)]
    
    return matrix

# Example usage:
# hex_string = "00112233445566778899aabbccddeeff"
# matrix = hex_to_matrix(hex_string)
# print(matrix)

def xor_matrices(nx16_matrix, matrix_1x16):
    # Ensure the 1x16 matrix is exactly 16 elements long
    if len(matrix_1x16) != 16:
        raise ValueError("The 1x16 matrix must contain 16 elements.")
    
    # Convert the 1x16 matrix elements from hex to integers for XOR operation
    key_ints = [int(byte, 16) for byte in matrix_1x16]
    
    # Initialize an empty matrix to store the XORed result
    result_matrix = []
    
    # Iterate over each row of the nx16 matrix
    for row in nx16_matrix:
        if len(row) != 16:
            raise ValueError("Each row of the nx16 matrix must contain 16 elements.")
        
        # Convert the row elements from hex to integers
        row_ints = [int(byte, 16) for byte in row]
        
        # Perform XOR between the current row and the 1x16 matrix
        xor_row = [r ^ k for r, k in zip(row_ints, key_ints)]
        
        # Convert the XOR result back to 2-character hex strings
        xor_row_hex = [f'{x:02x}' for x in xor_row]
        
        # Append the XORed row to the result matrix
        result_matrix.append(xor_row_hex)
    
    return result_matrix

# Example usage:
# nx16_matrix = [
#     ['00', '11', '22', '33', '44', '55', '66', '77', '88', '99', 'aa', 'bb', 'cc', 'dd', 'ee', 'ff'],
#     ['ff', 'ee', 'dd', 'cc', 'bb', 'aa', '99', '88', '77', '66', '55', '44', '33', '22', '11', '00']
# ]
# matrix_1x16 = ['ac', 'ac', 'ac', 'ac', 'ac', 'ac', 'ac', 'ac', 'ac', 'ac', 'ac', 'ac', 'ac', 'ac', 'ac', 'ac']

# result = xor_matrices(nx16_matrix, matrix_1x16)
# print(result)

def matrix_to_string(matrix):
    # Check if the matrix is a NumPy array and convert to a list if so
    if isinstance(matrix, np.ndarray):
        matrix = matrix.tolist()
    
    # Check if the matrix is non-empty and has the correct dimensions
    if not matrix or len(matrix[0]) != 16:
        raise ValueError("Input matrix must be non-empty and each row must have exactly 16 elements.")
    
    # Concatenate each element in the matrix
    result = ''.join(''.join(row) for row in matrix)
    return result



def encrypt(input_string, key):
    parts=hash_and_split_key(key)
    hex_string = process_input(input_string)
    # print('PS: ',hex_string)
    substitution_matrix = generate_substitution_matrix(parts[0]+parts[1]+parts[2]+parts[3])
    matrix_blocks = hex_to_matrix_blocks(hex_string)
    # print(matrix_blocks)
    substituted_matrix = substitute_matrix(matrix_blocks, substitution_matrix)
    # print('Substituted: ',matrix_to_string(substituted_matrix))
    pivots = calculate_pivots(substituted_matrix)
    byte_str = parts[2][12:14]
    result = three_param_cascading_xor(substituted_matrix, pivots, byte_str)
    hex_result = np.vectorize(lambda x: hex(x)[2:].zfill(2))(result)
    # print('Cascading XOR: ',matrix_to_string(hex_result))
    matrix_1x16 = hex_to_matrix(parts[1])
    result = xor_matrices(hex_result, matrix_1x16)
    cipher=matrix_to_string(result)
    return cipher

test_string='Hello, 世界! 🌍✨ Bienvenido al mundo de la criptografía y el cifrado! 🔒💻 让我们开始探索: @OpenAI, #AI #MachineLearning. 你准备好迎接挑战了吗？ 🚀🎉 Где ты, моя звезда? 🌟⭐ Собираешься изучить этот код? これはテストです。 🔑🔐 هل أنت جاهز لاستكشاف عمق المعرفة؟ 🧠📚 Ahora, resuelve este acertijo: 🤔💡 ¿Qué se obtiene si cruzamos un pez con una computadora? 🐟💻 ¡Una red de datos! 🌐🖥️ そして、旅を楽しんでください！ 🏞️🎮 هنا يوجد سرّ آخر لاكتشافه... 💫🕵️‍♂️ ¿Puedes encontrar todas las claves ocultas? 🕵️‍♀️🔍 #Criptografía #Seguridad 🚨🛡️ #Cybersecurity #Hacking 🤖👾 अब यह आपकी यात्रा का समय है! 🛤️🌌 आप इस पहेली को सुलझा सकते हैं? 🧩🔐 ¡Buena suerte! 🍀🔥'
# print(len(test_string))  # Length before any operations

start_time = time.time()
cipher = encrypt(test_string, 'ark')
end_time = time.time()
elapsed_time = end_time - start_time

milliseconds = elapsed_time * 1000
print(f"Elapsed time: {milliseconds:.2f} milliseconds")
print(cipher)


def decrypt(cipher_string, key):
    parts=hash_and_split_key(key)
    matrix_blocks = hex_to_matrix_blocks(cipher_string)
    substitution_matrix = generate_substitution_matrix(parts[0]+parts[1]+parts[2]+parts[3])
    matrix_1x16 = hex_to_matrix(parts[1])
    xor_results = xor_matrices(matrix_blocks, matrix_1x16)
    byte_str = parts[2][12:14]
    pivots = rev_calculate_pivots(xor_results, byte_str)
    reversed_matrix = reverse_3_parameter_cascading_xor(xor_results, byte_str, pivots)
    reversed_substituted_matrix = reverse_substitute_matrix(reversed_matrix, substitution_matrix)
    unprocessed_string=matrix_to_string(reversed_substituted_matrix)
    # print('UPS: ',unprocessed_string)
    original = reverse_process(unprocessed_string)
    return original

start_time = time.time()
plaintext=decrypt(cipher, 'ark')
end_time = time.time()
elapsed_time = end_time - start_time

milliseconds = elapsed_time * 1000
print(f"Elapsed time: {milliseconds:.2f} milliseconds")
print(plaintext)
# print(len(plaintext))  # Length after operations
