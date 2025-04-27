import argparse


# Return contents of any file type as bytes
def read_file(path: str) -> bytes:
    try:
        with open(path, "rb") as file:
            return file.read()
    except FileNotFoundError:
        print(f"Error: File not found at path '{path}'")
        raise
    except PermissionError:
        print(f"Error: Permission denied for file '{path}'")
        raise
    except Exception as e:
        print(f"Error reading file '{path}': {e}")
        raise


# Plaintext getters
def get_plaintext_key(path: str) -> str:
    return read_file(path).decode("utf-8").upper()


def get_plaintext_message(path: str) -> str:
    return read_file(path).decode("utf-8").upper()


def get_plaintext_shift_values(plaintext_key: str) -> list[int]:
    return [
        (ord(char.upper()) - ord("A")) % 26 for char in plaintext_key if char.isalpha()
    ]


# Binary getters
def get_binary_key(path: str) -> bytes:
    return read_file(path)


def get_binary_message(path: str) -> bytes:
    return read_file(path)


def get_binary_shift_values(binary_key: bytes) -> list[int]:
    return [byte for byte in binary_key]


# Plaintext padding
def pad_block(block: list[str], dimension: int) -> list[str]:
    block_size = dimension * dimension
    padding_needed = block_size - len(block)

    block.append("X")
    block.extend(["Y"] * (padding_needed - 1))
    return block


# Binary padding
def pad_binary_block(binary_block: bytearray, dimension: int) -> bytearray:
    block_size = dimension * dimension
    padding_needed = block_size - len(binary_block)

    binary_block.append(0)
    binary_block.extend([0xFF] * (padding_needed - 1))
    return binary_block


# Plaintext Vignere
def perform_vigenere_on_plaintext(
    plaintext_shift_values: list[int], block: list[str]
) -> list[str]:
    print("Performing vigenere on plaintext...")
    shifted_text = []

    shift_len = len(plaintext_shift_values)

    for i, char in enumerate(block):
        if char.isalpha():
            shift = plaintext_shift_values[i % shift_len]
            shifted_char = chr(((ord(char.upper()) - ord("A") + shift) % 26) + ord("A"))
            shifted_text.append(shifted_char)
        else:
            shifted_text.append(char)

    return shifted_text


# Binary vignere
def perform_vigenere_on_binary(
    binary_shift_values: list[int], binary_block: bytearray
) -> bytearray:
    print("Performing vigenere on binary...")
    shifted_binary = bytearray()

    shift_len = len(binary_shift_values)

    for i, byte in enumerate(binary_block):
        shift = binary_shift_values[i % shift_len]
        shifted_byte = (byte + shift) % 256
        shifted_binary.append(shifted_byte)

    return shifted_binary


# Plaintext columnar transposition
def perform_columnar_on_plaintext(
    vigenere_result: list[str], dimension: int
) -> list[str]:
    print("Performing columnar transposition on plaintext...")
    transposed_text = []

    rows = [
        vigenere_result[i : i + dimension]
        for i in range(0, len(vigenere_result), dimension)
    ]

    for col in range(dimension):
        for row in rows:
            transposed_text.append(row[col])

    return transposed_text


# Binary columnar transposition
def perform_columnar_on_binary(
    binary_vigenere_result: bytearray, dimension: int
) -> bytearray:
    print("Performing columnar transposition on binary...")
    transposed_binary = bytearray()

    rows = [
        binary_vigenere_result[i : i + dimension]
        for i in range(0, len(binary_vigenere_result), dimension)
    ]

    for col in range(dimension):
        for row in rows:
            if col < len(row):
                transposed_binary.append(row[col])

    return transposed_binary


# Plaintext encryption
def encrypt_plaintext(
    key_file_path: str, input_file_path: str, dimension: int, rounds: int
) -> str:
    print("Encrypting message...")
    key = get_plaintext_key(key_file_path)
    print(f"Key: {key}")
    message = get_plaintext_message(input_file_path)
    print(f"Message: {message}")
    block_size = dimension * dimension

    if len(message) < block_size:
        raise ValueError(
            f"Message must contain at least {block_size} characters because the dimension is {dimension}."
        )
    block = []
    blocks = []
    cipher_text_blocks = []
    cipher_text = ""

    list_message = list(message)
    print(f"List message: {list_message}")

    for char in list_message:
        block.append(char)
        if len(block) == block_size:
            blocks.append(block)
            block = []

    print(f"Blocks: {blocks}")

    if block:
        pad_block(block, dimension)
        blocks.append(block)

    if len(blocks) > 0 and len(blocks[-1]) == block_size:
        padding_block = ["X"] + ["Y"] * (block_size - 1)
        blocks.append(padding_block)

    for block in blocks:
        for r in range(rounds):
            print(f"Round {r + 1}...")
            if len(block) < block_size:
                pad_block(block, dimension)
            vigenere_result = perform_vigenere_on_plaintext(
                get_plaintext_shift_values(key), block
            )
            columnar_result = perform_columnar_on_plaintext(vigenere_result, dimension)
            print(f"Result after round {r + 1}: {columnar_result}")

            block = columnar_result
        cipher_text_blocks.append("".join(block))

    print(f"Result after all blocks and rounds: {cipher_text_blocks}")

    cipher_text = "".join(cipher_text_blocks)

    return cipher_text


# Output plaintext
def write_plaintext_file(path: str, contents: str) -> None:
    try:
        with open(path, "w") as file:
            file.write(contents)
    except PermissionError:
        print(f"Error: Cannot write to '{path}' — permission denied.")
        raise
    except Exception as e:
        print(f"Error writing to file '{path}': {e}")
        raise


# Binary encryption
def encrypt_binary(
    binary_key_path: str, input_path: str, dimension: int, rounds: int
) -> bytes:
    print("Encrypting binary...")
    binary_key = get_binary_key(binary_key_path)
    print(f"Binary key: {binary_key}")
    binary_message = get_binary_message(input_path)
    print(f"Binary message: {binary_message}")

    block_size = dimension * dimension

    if len(binary_message) < block_size:
        raise ValueError(
            f"The binary message must be at least {block_size} bytes because the dimension is {dimension}."
        )

    binary_block = bytearray()
    binary_blocks = []
    binary_cipher_blocks = []

    print(f"Binary list message: {binary_message}")

    for byte in binary_message:
        binary_block.append(byte)
        if len(binary_block) == block_size:
            binary_blocks.append(binary_block)
            binary_block = bytearray()

    print(f"Binary blocks: {binary_blocks}")

    if binary_block:
        pad_binary_block(binary_block, dimension)
        binary_blocks.append(binary_block)

    if len(binary_blocks) > 0 and len(binary_blocks[-1]) == block_size:
        binary_padding_block = bytearray([0] + [255] * (block_size - 1))
        binary_blocks.append(binary_padding_block)

    for binary_block in binary_blocks:
        for r in range(rounds):
            print(f"Round {r + 1}...")
            if len(binary_block) < block_size:
                pad_binary_block(binary_block, dimension)
            binary_vigenere_result = perform_vigenere_on_binary(
                get_binary_shift_values(binary_key), binary_block
            )
            binary_columnar_result = perform_columnar_on_binary(
                binary_vigenere_result, dimension
            )
            print(f"Result after round {r + 1}: {binary_columnar_result}")

            binary_block = binary_columnar_result
        binary_cipher_blocks.append(bytes(binary_block))

    print(f"Result after all blocks and rounds: {binary_cipher_blocks}")

    binary_cipher = b"".join(binary_cipher_blocks)
    print(f"Binary cipher: {binary_cipher}")
    hex_binary_cipher = binary_cipher.hex()
    print(f"Hex binary cipher: {hex_binary_cipher}")
    return binary_cipher


# Output binary
def write_binary_file(path: str, contents: bytes) -> None:
    try:
        with open(path, "wb") as file:
            file.write(contents)
    except PermissionError:
        print(f"Error: Cannot write to '{path}' — permission denied.")
        raise
    except Exception as e:
        print(f"Error writing to file '{path}': {e}")
        raise


# Decryption
# Plaintext
def reverse_plaintext_columnar(
    plaintext_cipher_block: list[str], dimension: int
) -> list[str]:
    print("Reversing columnar transposition on plaintext...")
    num_rows = len(plaintext_cipher_block) // dimension

    vigenere_result = [""] * len(plaintext_cipher_block)

    idx = 0
    for col in range(dimension):
        for row in range(num_rows):
            vigenere_result[row * dimension + col] = plaintext_cipher_block[idx]
            idx += 1

    print(vigenere_result)
    return vigenere_result


def reverse_plaintext_vigenere(
    plaintext_shift_values: list[int], reverse_transposition: list[str]
) -> list[str]:
    print("Reversing vignere on plaintext...")
    reverse_vigenere = []

    shift_len = len(plaintext_shift_values)

    for i, char in enumerate(reverse_transposition):
        if char.isalpha():
            shift = plaintext_shift_values[i % shift_len]
            if char.isupper():
                shifted_char = chr(((ord(char) - ord("A") - shift) % 26) + ord("A"))
                print(f"Shifted char: {shifted_char}")
                reverse_vigenere.append(shifted_char)
            else:
                shifted_char = chr(((ord(char) - ord("a") - shift) % 26) + ord("a"))
                reverse_vigenere.append(shifted_char)
        else:
            reverse_vigenere.append(char)

    print(f"Reverse vigenere: {reverse_vigenere}")

    return reverse_vigenere


def remove_plaintext_padding(block: list[str]) -> list[str]:
    print("Removing plaintext padding...")

    if not block:
        return block

    if block[0] == "X" and block[-1] == "Y":
        return []

    else:
        try:
            x_index = block.index("X")
            return block[:x_index]
        except ValueError:
            return block


# Binary
def reverse_columnar_on_binary():
    print("Reversing columnar transposition on binary...")


def reverse_vigenere_on_binary():
    print("Reversing vignere on binary...")


def remove_binary_padding():
    print("Removing binary padding...")


# Plaintext decryption
def decrypt_plaintext(key_file, input_file, dimension, rounds) -> str:
    print("Decrypting plaintext...")
    decrypted_message = ""
    plaintext_key = get_plaintext_key(key_file)
    print(f"Plaintext key: {plaintext_key}")
    plaintext_cipher = get_plaintext_message(input_file)
    print(f"Plaintext cipher: {plaintext_cipher}")

    block_size = dimension * dimension

    block = []
    blocks = []

    for char in plaintext_cipher:
        block.append(char)
        if len(block) == block_size:
            blocks.append(block)
            block = []

    for idx, block in enumerate(blocks):
        for r in range(rounds):
            print(f"Round: {r + 1}")
            reverse_transposition = reverse_plaintext_columnar(block, dimension)
            print(f"Reverse transposition: {reverse_transposition}")
            reverse_vigenere = reverse_plaintext_vigenere(
                get_plaintext_shift_values(plaintext_key), reverse_transposition
            )
            print(f"Reversed vigenere: {reverse_vigenere}")

            block = reverse_vigenere

        if idx == len(blocks) - 1:
            block = remove_plaintext_padding(block)
            print(f"Block after padding removal: {block}")

        decrypted_message += "".join(block)
        print(f"Decrypted message: {decrypted_message}")

    return decrypted_message


# Binary Decryption
def decrypt_binary(key_file, input_file, dimension, rounds) -> bytes:
    print("Decrypting binary...")
    message = ""
    return message


# Configure argument parser for product cipher CLI
def get_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Product cipher: encode or decode")

    parser.add_argument(
        "operation",
        choices=["encode", "decode"],
        help="Choose whether to encode (encrypt) or decode (decrypt)",
    )
    parser.add_argument("key_file", help="Path to the key file")
    parser.add_argument("input_file", help="Path to the input file")
    parser.add_argument("output_file", help="Path to the output file")
    parser.add_argument(
        "dimension", type=int, help="Columnar dimensions (ie. 4 -> 4x4 grid)"
    )
    parser.add_argument(
        "rounds", type=int, help="Number of rounds for multi-round product cipher"
    )

    return parser


def main():
    parser = get_parser()
    args = parser.parse_args()

    try:
        # Encryption
        if args.operation == "encode":
            # Binary input file
            if args.input_file.endswith(".bin"):
                cipher_text = encrypt_binary(
                    args.key_file, args.input_file, args.dimension, args.rounds
                )
                write_binary_file(args.output_file, cipher_text)

            # Plaintext input file
            else:
                cipher_text = encrypt_plaintext(
                    args.key_file, args.input_file, args.dimension, args.rounds
                )
                write_plaintext_file(args.output_file, cipher_text)

            print(
                f"Your message has been successfully encrypted. The ciphertext can be found in {args.output_file}."
            )
        # Decryption
        elif args.operation == "decode":
            # Binary input file
            if args.input_file.endswith(".bin"):
                message = decrypt_binary(
                    args.key_file, args.input_file, args.dimension, args.rounds
                )
                write_binary_file(args.output_file, message)

            # Plaintext input file
            else:
                cipher_text = decrypt_plaintext(
                    args.key_file, args.input_file, args.dimension, args.rounds
                )
                write_plaintext_file(args.output_file, cipher_text)

            print(
                f"This ciphertext has been successfully decrypted. The message can be found in {args.output_file}."
            )

    except Exception as e:
        print(f"There was an error during the {args.operation} operation: {e}")


if __name__ == "__main__":
    main()
