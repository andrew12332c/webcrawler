import sys


def tokenize(text_file_path):
    """
    Runtime Complexity:
    O(n), where n is the number of characters in the input file.
    Each character is read and processed exactly once.

    Reads a text file and returns a list of tokens.
    A token is a sequence of alphanumeric characters.
    Tokenization is case-insensitive.
    Non-English or problematic characters are safely skipped.
    """
    tokens = []
    current_token = []

    try:
        with open(text_file_path, 'r', encoding='utf-8', errors='ignore') as file:
            while True:
                char = file.read(1)
                if not char:  # End of file
                    break

                try:
                    if char.isalnum():
                        current_token.append(char.lower())
                    else:
                        if current_token:
                            tokens.append(''.join(current_token))
                            current_token = []
                except Exception:
                    # Skip any bad character and continue tokenizing
                    continue

            # Handle last token if file ends with alphanumeric characters
            if current_token:
                tokens.append(''.join(current_token))

    except FileNotFoundError:
        print(f"Error: File '{text_file_path}' not found.")
        sys.exit(1)
    except IOError:
        print(f"Error: Could not read file '{text_file_path}'.")
        sys.exit(1)

    return tokens


def compute_word_frequencies(tokens):
    """
    Runtime Complexity:
    O(m), where m is the number of tokens.
    Each token is processed exactly once.

    Counts the number of occurrences of each token.
    Returns a dictionary mapping token -> frequency.
    """
    frequencies = {}

    for token in tokens:
        if token in frequencies:
            frequencies[token] += 1
        else:
            frequencies[token] = 1

    return frequencies


def print_frequencies(frequencies):
    """
    Runtime Complexity:
    O(k log k), where k is the number of unique tokens.
    Sorting dominates the runtime.

    Prints token frequencies ordered by decreasing frequency.
    Ties are broken alphabetically for deterministic output.
    Output format: <token>\\t<frequency>
    """
    items = list(frequencies.items())

    # Sort by descending frequency, then alphabetically
    items.sort(key=lambda pair: (-pair[1], pair[0]))

    for token, freq in items:
        print(f"{token}\t{freq}")


def main():
    """
    Runtime Complexity:
    Dominated by tokenize() and sorting in print_frequencies().
    Overall complexity: O(n + k log k)
    """
    if len(sys.argv) != 2:
        print("Usage: python partA.py <text_file>")
        sys.exit(1)

    text_file_path = sys.argv[1]

    tokens = tokenize(text_file_path)
    frequencies = compute_word_frequencies(tokens)
    print_frequencies(frequencies)


if __name__ == "__main__":
    main()
