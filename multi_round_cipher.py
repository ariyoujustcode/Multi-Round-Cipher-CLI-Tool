import argparse


def encrypt(key_file, input_file, output_file, dimension, rounds):
    print("encrypting")


def decrypt(key_file, input_file, output_file, dimension, rounds):
    print("decrypyting")


def main():
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
        "dimension", type=int, help="Columnar matrix size (e.g., 4 for 4x4 matrix)"
    )
    parser.add_argument(
        "rounds", type=int, help="Number of rounds for encryption/decryption"
    )

    args = parser.parse_args()


if __name__ == "__main__":
    main()
