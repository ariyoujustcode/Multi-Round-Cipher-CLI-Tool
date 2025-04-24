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
    with open(path, "r") as file:
        return file.read()


def write_file(path: str, contents: str) -> None:
    with open(path, "w") as file:
        file.write(contents)


def get_shift_values(key_file) -> list[int]:
    shift_values = []
    print("Calculating shift values for vignere cipher...")
    return shift_values


def add_padding(vignere_cipher: str) -> str:
    padded_vignere_cipher = ""
    print("Adding padding...")
    return padded_vignere_cipher


def perform_vignere(shift_values: list[int], message: str) -> str:
    vignere_cipher = ""
    print("performing vignere...")
    return vignere_cipher


def create_block(vignere_cipher: str, dimension: int) -> list[int]:
    print("Creating block...")


def perform_columnar(block: list[int]) -> str:
    encrypted_block = ""
    return encrypted_block


def encrypt(key_file_path, input_file_path, output_file, dimension, rounds) -> str:
    key = read_file(key_file_path)
    message = read_file(input_file_path)

    shift_values = get_shift_values(key)

    for round in rounds:
        vignere_cipher = perform_vignere(shift_values, message)
        vignere_block = create_block(vignere_cipher, dimension)

    vignere_padded_block = add_padding(vignere_block)
    columnar_cipher = perform_columnar(vignere_padded_block)

    print("encrypting...")


def decrypt(key_file, input_file, output_file, dimension, rounds) -> str:
    print("decrypyting...")


def main():
    parser = get_parser()
    args = parser.parse_args()


if __name__ == "__main__":
    main()
