import argparse


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


def pad_block(block: list[str], chars_in_block: int) -> list[str]:
    padding_needed = chars_in_block - len(block)

    block.append("X")
    block.extend(["Y"] * (padding_needed - 1))
    return block


# Plaintext Vignere
def perform_vignere_on_plaintext(
    plaintext_shift_values: list[int], block: list[str]
) -> list[str]:
    print("Performing vignere on plaintext...")
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
def perform_vignere_on_binary(
    binary_shift_values: bytes, binary_message: bytes
) -> bytes:
    print("Performing vignere on binary...")
    shifted_message = bytearray()

    shift_len = len(binary_shift_values)

    for i, byte in enumerate(binary_message):
        shift = binary_shift_values[i % shift_len]
        shifted_byte = (byte + shift) % 256
        shifted_message.append(shifted_byte)

    return bytes(shifted_message)


def split_plaintext_into_blocks(shifted_plaintext: str, dimension) -> list[list[str]]:
    print("Splitting plaintext into blocks...")
    blocks = []
    block = []
    block_size = dimension * dimension

    for char in shifted_plaintext:
        block.append(char)
        if len(block) == block_size:
            blocks.append(block)
            block = []

    return blocks


def split_binary_into_blocks(shifted_binary: bytes, dimension) -> list[list[bytes]]:
    print("Splitting binary into blocks...")
    blocks = []
    block = []
    bytes_in_block = dimension * dimension

    for i in range(0, len(shifted_binary), bytes_in_block):
        blocks.append(shifted_binary[i : i + bytes_in_block])

    if len(blocks[-1]) < bytes_in_block:
        padding_needed = bytes_in_block - len(blocks[-1])

        blocks[-1].extend([0x58] + [0x59] * (padding_needed - 1))

    while len(blocks) < dimension:
        padding_block = [0x58] + [0x59] * (bytes_in_block - 1)
        blocks.append(padding_block)

    return blocks


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
def perform_columnar_on_binary(blocks: list[list[bytes]], dimension: int) -> bytes:
    print("Performing columnar transposition on binary...")
    transposed_binary = bytearray()

    for col in range(dimension):
        for block in blocks:
            transposed_binary.extend(block[col])

    return bytes(transposed_binary)


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
        pad_block(block)
        blocks.append(block)

    if len(blocks) > 0 and len(blocks[-1]) == block_size:
        padding_block = ["X"] + ["Y"] * (block_size - 1)
        blocks.append(padding_block)

    for block in blocks:
        for r in range(rounds):
            print(f"Round {r + 1}...")
            if len(block) < block_size:
                pad_block(block)
            vigenere_result = perform_vignere_on_plaintext(
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


# Binary encryption
def encrypt_binary(
    binary_key_path: str, input_path: str, dimension: int, rounds: int
) -> bytes:
    print("Encrypting binary...")
    binary_key = get_binary_key(binary_key_path)
    binary_message = get_binary_message(input_path)

    shifted_binary = perform_vignere_on_binary(
        get_binary_shift_values(binary_key), binary_message
    )

    for round_num in range(rounds):
        print(f"Round {round_num + 1}...")

        blocks = split_binary_into_blocks(shifted_binary, dimension)

        transposed_binary = perform_columnar_on_binary(blocks, dimension)

        shifted_binary = transposed_binary

    binary_cipher = shifted_binary
    return binary_cipher


# Decryption
# Plaintext
def reverse_columnar(blocks: list[list[int]]) -> str:
    print("Reversing columnar transposition on plaintext...")


def reverse_vignere(shift_values: list[int], cipher_text: str) -> str:
    print("Reversing vignere on plaintext...")


# Binary
def reverse_columnar_on_binary():
    print("Reversing columnar transposition on binary...")


def reverse_vignere_on_binary():
    print("Reversing vignere on binary...")


# Plaintext decryption
def decrypt_plaintext(key_file, input_file, dimension, rounds) -> str:
    print("Decrypting plaintext...")
    message = ""
    return message


# Binary Decryption
def decrypt_binary(key_file, input_file, dimension, rounds) -> str:
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
            if args.input_file.endswith(".bin"):
                message = decrypt_binary(
                    args.key_file, args.input_file, args.dimension, args.rounds
                )
                write_binary_file(args.output_file, message)
            else:
                cipher_text = decrypt_plaintext(
                    args.key_file, args.input_file, args.dimension, args.rounds
                )
                write_plaintext_file(args.output_file, message)

            print(
                f"This ciphertext has been successfully decrypted. The message can be found in {args.output_file}."
            )

    except Exception as e:
        print(f"There was an error during the {args.operation} operation: {e}")


if __name__ == "__main__":
    main()
