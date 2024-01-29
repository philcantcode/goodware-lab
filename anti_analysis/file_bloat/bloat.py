import argparse

def add_null_bytes_to_pe(file_path, output_path, size_in_mb):
    null_bytes = b'\x00' * (size_in_mb * 1024 * 1024)  # size_in_mb MB of null bytes

    with open(file_path, 'rb') as file:
        content = file.read()

    new_content = content + null_bytes

    with open(output_path, 'wb') as file:
        file.write(new_content)

    print(f"Added {size_in_mb}MB of null bytes to {output_path}")

def main():
    parser = argparse.ArgumentParser(description="Add null bytes to a PE file.")
    parser.add_argument("file_path", help="Path to the input PE file")
    parser.add_argument("output_path", help="Path to the output file")
    parser.add_argument("-s", "--size", type=int, default=200, help="Size of null bytes to add in MB (default: 200)")

    args = parser.parse_args()

    add_null_bytes_to_pe(args.file_path, args.output_path, args.size)

if __name__ == "__main__":
    main()
