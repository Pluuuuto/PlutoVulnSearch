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

        # 嵌套字段提取
        other_id_block = re.search(r'<other-id>(.*?)</other-id>', block, flags=re.DOTALL)
        other_id = other_id_block.group(1) if other_id_block else ''

        def extract_other_id(tag):
            match = re.search(rf'<{tag}>(.*?)</{tag}>', other_id, flags=re.DOTALL)
            return match.group(1).strip() if match else ''

        vuln_descript = extract_field('vuln-descript')

        # 新增：从描述中提取产品及版本号的简易逻辑
        def extract_products(text):
            # 示例模式：ProductName Version / ProductName <=1.0 / ProductName <1.0.2a
            product_matches = re.findall(r'\b([A-Za-z0-9\.\-\+\/_ ]+?)[ ]+(v?[\d]+(?:\.[\d\w]+)*)\b', text)
            # 返回唯一产品+版本拼接
            return list(set([f"{name.strip()} {ver.strip()}" for name, ver in product_matches]))

        products = extract_products(vuln_descript)

        data.append({
            'name': extract_field('name'),
            'vuln_id': extract_field('vuln-id'),
            'published': extract_field('published'),
            'modified': extract_field('modified'),
            'source': extract_field('source'),
            'severity': extract_field('severity'),
            'vuln_type': extract_field('vuln-type'),
            'vuln_descript': vuln_descript,
            'products': ', '.join(products),  # 👈 新字段
            'cve_id': extract_other_id('cve-id'),
            'bugtraq_id': extract_other_id('bugtraq-id'),
            'vuln_solution': extract_field('vuln-solution')
        })

    return data
