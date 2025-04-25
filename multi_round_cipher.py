import argparse


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


def read_file(path: str) -> str:
    try:
        with open(path, "r") as file:
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


def read_binary_file(path: str) -> bytes:
    with open(path, "rb") as file:
        return file.read()


def get_key(path: str) -> str:
    return read_file(path).upper()


def get_key_from_binary(binary_key_path: str) -> str:
    return read_binary_file(binary_key_path)


def get_message(path: str) -> str:
    return read_file(path).upper()


def get_message_from_binary(binary_input_path: str) -> str:
    return read_binary_file(binary_input_path)


def write_file(path: str, contents: str) -> None:
    try:
        with open(path, "w") as file:
            file.write(contents)
    except PermissionError:
        print(f"Error: Cannot write to '{path}' — permission denied.")
        raise
    except Exception as e:
        print(f"Error writing to file '{path}': {e}")
        raise


def get_shift_values(key: str) -> list[int]:
    shift_values = [ord(char) % 26 for char in key]
    return shift_values


def get_binary_shift_values(byte_key: bytes) -> list[int]:
    shift_values = [b % 26 for b in byte_key]
    return shift_values


def add_padding(block: list[str], block_size: int) -> None:
    print("Adding padding...")
    padding_needed = block_size - len(block)

    if padding_needed > 0:
        block.append("X")
        block.extend(["Y"] * (padding_needed - 1))


def remove_padding(blocks: list[list[str]], block_size: int) -> None:
    print("Removing padding...")
    length = len(blocks)

    for block in blocks:
        for i in range(len(block) - 1, -1, -1):
            if block[i] == "X":
                del block[i:]
                break


def create_blocks(contents: str, dimension: int) -> list[list[str]]:
    print("Creating blocks...")
    block_size = dimension * dimension
    blocks = []
    block = []

    for char in contents:
        block.append(char)
        if len(block) == block_size:
            blocks.append(block)
            block = []

    if block:
        add_padding(block, block_size)
        blocks.append(block)

    return blocks


def perform_vignere(shift_values: list[int], message: str) -> str:
    print("Performing vignere...")
    cipher_text = []
    key_length = len(shift_values)

    for i, char in enumerate(message):
        if char.isalpha():
            shift = shift_values[i % key_length]
            encrypted_char = chr((ord(char) - ord("A") + shift) % 26 + ord("A"))
            cipher_text.append(encrypted_char)
        else:
            cipher_text.append(char)

    return "".join(cipher_text)


def perform_vignere_on_binary(shift_values: list[int], message_bytes: bytes) -> bytes:
    print("Performing vignere on binary...")

    vignere_bytes = bytearray()
    shift_len = len(shift_values)

    for i, byte in enumerate(message_bytes):
        shift = shift_values[i % shift_len]
        shifted_byte = (byte + shift) % 256
        vignere_bytes.append(shifted_byte)

    return bytes(vignere_bytes)


def reverse_vignere(shift_values: list[int], cipher_text: str) -> str:
    print("Reversing vignere...")


def perform_columnar(blocks: list[list[str]], dimension: int) -> str:
    print("Performing columnar transposition...")
    encrypted_text = ""

    for block in blocks:
        for col in range(dimension):
            for row in range(dimension):
                index = row * dimension + col
                if index < len(block):
                    encrypted_text += block[index]

    return encrypted_text


def perform_columnar_on_binary(blocks: list[list[int]], dimension: int) -> bytes:
    print("Performing columnar transposition on binary...")
    encrypted_bytes = bytearray()

    for block in blocks:
        for col in range(dimension):
            for row in range(dimension):
                index = row * dimension + col
                if index < len(block):
                    encrypted_bytes.append(block[index])

    return bytes(encrypted_bytes)


def reverse_columnar(blocks: list[list[int]]) -> str:
    print("Reversing columnar transposition...")


def encrypt(key_file_path, input_file_path, dimension, rounds) -> str:
    print("Encrypting message...")
    key = None
    message = None
    key_from_binary = None
    message_from_binary = None
    cipher_text = ""

    try:
        key = get_key(key_file_path)
        message = get_message(input_file_path)
    except:
        key_from_binary = get_key_from_binary(key_file_path)
        message_from_binary = get_message_from_binary(input_file_path)

    for _ in range(rounds):
        if key and message:
            shift_values = get_shift_values(key)
            vignere_cipher = perform_vignere(shift_values, message)
            blocks = create_blocks(vignere_cipher, dimension)
            cipher_text = perform_columnar(blocks, dimension)
            message = cipher_text
        elif key_from_binary and message_from_binary:
            shift_values_from_binary = get_binary_shift_values(key_from_binary)
            vignere_cipher = perform_vignere_on_binary(
                shift_values_from_binary, message_from_binary
            )
            block_size = dimension * dimension
            blocks = [
                list(vignere_cipher[i : i + block_size])
                for i in range(0, len(vignere_cipher), block_size)
            ]
            cipher_text = perform_columnar_on_binary(blocks, dimension)
            message_from_binary = cipher_text
        else:
            raise ValueError("Error: Please provide a valid key and message.")

    return cipher_text


def decrypt(key_file, input_file, dimension, rounds) -> str:
    print("Decrypting text...")
    message = ""
    return message


def main():
    parser = get_parser()
    args = parser.parse_args()

    try:
        if args.operation == "encode":
            cipher_text = encrypt(
                args.key_file, args.input_file, args.dimension, args.rounds
            )

            write_file(args.output_file, cipher_text)
            print(
                f"Your message has been successfully encrypted. The ciphertext can be found in {args.output_file}."
            )

        elif args.operation == "decode":
            message = decrypt(
                args.key_file, args.input_file, args.dimension, args.rounds
            )

            write_file(args.output_file, message)
            print(
                f"This ciphertext has been successfully decrypted. The message can be found in {args.output_file}."
            )
    except Exception as e:
        print(f"There was an error during the {args.operation} operation: {e}")


if __name__ == "__main__":
    main()
