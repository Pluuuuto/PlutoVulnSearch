import re

def parse_vulnerabilities(xml_path):
    with open(xml_path, 'r', encoding='utf-8') as f:
        raw_xml = f.read()

    # 提取所有 entry 块
    entry_blocks = re.findall(r'<entry>(.*?)</entry>', raw_xml, flags=re.DOTALL)

    data = []

    for block in entry_blocks:
        def extract_field(tag):
            match = re.search(rf'<{tag}>(.*?)</{tag}>', block, flags=re.DOTALL)
            return match.group(1).strip() if match else ''

        # 嵌套字段提取（手动提）
        other_id_block = re.search(r'<other-id>(.*?)</other-id>', block, flags=re.DOTALL)
        other_id = other_id_block.group(1) if other_id_block else ''

        def extract_other_id(tag):
            match = re.search(rf'<{tag}>(.*?)</{tag}>', other_id, flags=re.DOTALL)
            return match.group(1).strip() if match else ''

        data.append({
            'name': extract_field('name'),
            'vuln_id': extract_field('vuln-id'),
            'published': extract_field('published'),
            'modified': extract_field('modified'),
            'source': extract_field('source'),
            'severity': extract_field('severity'),
            'vuln_type': extract_field('vuln-type'),
            'vuln_descript': extract_field('vuln-descript'),
            'cve_id': extract_other_id('cve-id'),
            'bugtraq_id': extract_other_id('bugtraq-id'),
            'vuln_solution': extract_field('vuln-solution')
        })

    return data
