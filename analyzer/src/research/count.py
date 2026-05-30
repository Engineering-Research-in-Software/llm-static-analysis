import json
import sys

def count_entries(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
    
    if not isinstance(data, list):
        raise ValueError("The JSON content is not an array.")
    
    return len(data)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python count_entries.py <path_to_json_file>")
        sys.exit(1)
    
    path = sys.argv[1]
    count = count_entries(path)
    print(f"Number of entries: {count}")