import re
from collections import Counter

def extract_tags(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Extract all tags
    tags = re.findall(r'<(/?\w+).*?>', content)

    # Count occurrences of each tag
    tag_counts = Counter(tags)

    return tag_counts

if __name__ == "__main__":
    file_path = "data/1286.xml"
    tag_counts = extract_tags(file_path)

    print("Tag statistics:")
    for tag, count in tag_counts.items():
        print(f"{tag}: {count}")
