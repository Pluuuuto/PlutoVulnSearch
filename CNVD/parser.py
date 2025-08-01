import os
import re
import html

def parse_vulnerabilities(xml_path):
    with open(xml_path, 'r', encoding='utf-8') as f:
        raw_xml = f.read()

    vulnerabilities = []

    # Extract vulnerability blocks
    vuln_blocks = re.findall(r'<vulnerability>(.*?)</vulnerability>', raw_xml, flags=re.DOTALL)

    for block in vuln_blocks:
        def extract_field(tag):
            match = re.search(rf'<{tag}>(.*?)</{tag}>', block, flags=re.DOTALL)
            return html.unescape(match.group(1).strip()) if match else None

        def extract_products():
            products_block = re.search(r'<products>(.*?)</products>', block, flags=re.DOTALL)
            if products_block:
                product_matches = re.findall(r'<product>(.*?)</product>', products_block.group(1), flags=re.DOTALL)
                return [html.unescape(product.strip()) for product in product_matches]
            return []

        def extract_cve_number():
            cve_number_block = re.search(r'<cveNumber>(.*?)</cveNumber>', block, flags=re.DOTALL)
            return html.unescape(cve_number_block.group(1).strip()) if cve_number_block else None

        def extract_cve_url():
            cve_url_block = re.search(r'<cveUrl>(.*?)</cveUrl>', block, flags=re.DOTALL)
            return html.unescape(cve_url_block.group(1).strip()) if cve_url_block else None

        vulnerabilities.append({
            'cnvd_number': extract_field('number'),
            'title': extract_field('title'),
            'severity': extract_field('serverity'),
            'products': extract_products(),
            'cveNumber': extract_cve_number(),
            'cveUrl': extract_cve_url(),
            'is_Event': extract_field('isEvent'),
            'submit_time': extract_field('submitTime'),
            'open_time': extract_field('openTime'),
            'reference_link': extract_field('referenceLink'),
            'discoverer_name': extract_field('discovererName'),
            'formal_way': extract_field('formalWay'),
            'description': extract_field('description'),
            'patch_name': extract_field('patchName'),
            'patch_description': extract_field('patchDescription')
        })

    return vulnerabilities

# Example usage
if __name__ == "__main__":
    data_dir = "data"
    xml_files = [f for f in os.listdir(data_dir) if f.endswith('.xml')]

    for xml_file in xml_files:
        xml_path = os.path.join(data_dir, xml_file)
        vulnerabilities = parse_vulnerabilities(xml_path)
        print(f"Parsed {len(vulnerabilities)} vulnerabilities from {xml_file}")