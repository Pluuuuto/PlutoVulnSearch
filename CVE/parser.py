import json
import re

def parse_vulnerabilities(json_path):
    with open(json_path, 'r', encoding='utf-8') as f:
        raw_json = json.load(f)

    data = []

    # Extract relevant fields from the JSON structure
    cve_metadata = raw_json.get('cveMetadata', {})
    containers = raw_json.get('containers', {}).get('cna', {})

    cve_id = cve_metadata.get('cveId', '未知 CVE ID')
    published_date = cve_metadata.get('datePublished', '未知发布日期')

    # Extract affected products
    affected = containers.get('affected', [])
    products = []
    for item in affected:
        vendor = item.get('vendor', '未知厂商')
        if vendor == 'n/a':
            vendor = '未知厂商'
        product = item.get('product', item.get('packageName', '未知产品'))
        if product == 'n/a':
            product = '未知产品'
        versions = item.get('versions', [])
        if not versions:
            products.append(f"{vendor} {product} 未知版本")
        else:
            for version in versions:
                status = version.get('status')
                if status == 'affected':
                    version_number = version.get('version')
                    if version_number == 'n/a':
                        version_number = '未知版本'
                    less_than = version.get('lessThan')
                    less_than_equal = version.get('lessThanOrEqual')
                    if less_than:
                        products.append(f"{vendor} {product} < {less_than}")
                    elif less_than_equal:
                        products.append(f"{vendor} {product} <= {less_than_equal}")
                    else:
                        products.append(f"{vendor} {product} {version_number}")

    # Extract references (solutions)
    references = containers.get('references', [])
    solutions = [ref.get('url', '') for ref in references]

    # Extract CVSS scores (all versions)
    metrics = containers.get('metrics', [])
    cvss_score = 0.0  # Default to 0.0
    for metric in metrics:
        for key, value in metric.items():
            if re.match(r'cvssV\d_\d', key) and isinstance(value, dict):
                base_score = value.get('baseScore')
                if base_score is not None:
                    cvss_score = base_score  # Use the first valid score (latest version)
                    break
        if cvss_score != 0.0:
            break

    # Extract vulnerability description
    descriptions = containers.get('descriptions', [])
    vuln_description = ''
    for desc in descriptions:
        if desc.get('lang', '') == 'en':
            vuln_description = desc.get('value', '')
            break

    data.append({
        'cve_id': cve_id,
        'published_date': published_date,
        'affected_products': ' || '.join(products),
        'solution': ' || '.join(solutions),
        'cvss_score': cvss_score,
        'vuln_description': vuln_description
    })

    return data
