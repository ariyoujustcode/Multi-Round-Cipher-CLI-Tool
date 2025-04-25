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


def get_key(path: str) -> str:
    return read_file(path)


def get_key_from_binary(binary_key_path: str) -> str:
    return read_binary_file(binary_key_path)


def get_message(path: str) -> str:
    return read_file(path)


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


def read_binary_file(path: str) -> bytes:
    with open(path, "rb") as file:
        return file.read()


def get_binary_shift_values(byte_key: bytes) -> list[int]:
    shift_values = [b % 26 for b in byte_key]
    return shift_values


def add_padding(block: list[str], block_size: int) -> None:
    padding_needed = block_size - len(block)

    if padding_needed > 0:
        block.append("X")
        block.extend(["Y"] * (padding_needed - 1))


def create_blocks(contents: str, dimension: int) -> list[list[str]]:
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
    vignere_cipher = ""
    print("performing vignere...")
    return vignere_cipher


def perform_columnar(block: list[int]) -> str:
    encrypted_block = ""
    return encrypted_block


def encrypt(key_file_path, input_file_path, dimension, rounds) -> str:
    cipher_text = ""
    try:
        key = get_key(key_file_path)
        message = get_message(input_file_path)
    except:
        key_from_binary = get_key_from_binary(key_file_path)
        message_from_binary = get_message_from_binary(input_file_path)

    if key:
        shift_values = get_shift_values(key)
    elif key_from_binary:
        shift_values_from_binary = get_binary_shift_values(key_from_binary)
    else:
        print(
            "Error: cannot determine shift values from input key. Accepted keys must be binary or plaintext."
        )

    for round in rounds:
        vignere_cipher = perform_vignere(shift_values, message)
        vignere_block = create_block(vignere_cipher, dimension)

    vignere_padded_block = add_padding(vignere_block)
    columnar_cipher = perform_columnar(vignere_padded_block)


def decrypt(key_file, input_file, dimension, rounds) -> str:
    print("decrypyting...")


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
