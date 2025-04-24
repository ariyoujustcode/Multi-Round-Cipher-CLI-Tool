def create_binary_files():
    with open("key_binary.bin", "wb") as key_file:
        key_file.write(b"\xff\x00\x0a")

    with open("input_binary.bin", "wb") as input_file:
        input_file.write(b"\x32\x45\x78\x01\x23")

    print("Binary files created successfully.")


if __name__ == "__main__":
    create_binary_files()
