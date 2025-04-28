# CipherForge: A Multi-Round Cipher CLI Tool

A Python command-line encryption tool implementing a customizable multi-round product cipher with Vigenère encryption and columnar transposition — designed to practice systems programming, file I/O, and network security principles.

## Features
— Multi-round encryption and decryption support
— Dynamic command-line interface for flexible configuration
— Vigenère cipher with full binary and text file compatibility
— Customizable padding schemes and cipher grid dimensions
— Robust file-based input and output handling

## How to Run
1. Clone this repository
2. Make sure you have Python 3 installed
3. Run from the command line:
   python3 multi_round_cipher.py [encode|decode] <key_path> <input_path> <output_path> <dimension> <rounds>

   Example:
   python3 product.py encode ./key.txt ./input.txt ./output.txt 4 2

## Technologies
— Python 3
— Command-line tools (CLI design)
— Cryptography concepts (Vigenère cipher, transposition cipher)

## Notes
This project showcases my ability to build flexible, secure encryption systems from scratch and work with low-level file operations and binary data — part of my focus on Python development and network security.
