from llm_version_ranges import call_llm, items_to_intervals, interval_to_text
import json

samples = [
    "Apache Tomcat prior to 8.5.73",
    "MySQL Server >= 5.7.31",
    "nginx <= 1.20.1",
    "PHP > 7.3.0",
    "Apache Tomcat 8.0.0 to 8.5.99",
    "Python 3.6.0 through 3.6.15",
    "Oracle WebLogic Server 12.1.3.0 - 12.2.1.4",
    "Windows Server 2016 version 10.0.14393 to 10.0.19044",
    "Apache Tomcat 8.x",
    "nginx 1.18.x",
    "PHP 7.x before 7.4.0",
    "Apache Tomcat 8.0.53, 8.5.23, 9.0.1 affected",
    "OpenSSL 1.0.2g, 1.1.1k",
    "Apache Tomcat prior to 8.5.73 and Jetty 9.4.x",
    "MySQL 5.7.x, 8.0.23",
    "OpenSSL versions before 1.0.2n",
    "LibreOffice after 6.4.3",
    "Tomcat 8.0.0至8.5.99版本受影响",
    "nginx 小于 1.20.0",
    "Windows 版本大于等于 10.0.14393 且小于 10.0.19044",
    "Java SE 8u121 and 8u131",
    "Red Hat Enterprise Linux 7.9 (kernel-3.10.0-1160)",
    "JBoss EAP 7.2.5.GA"
]

for s in samples:
    print("="*60)
    print("原始:", s)
    resp = call_llm(s)
    print("LLM JSON:", json.dumps(resp, ensure_ascii=False, indent=2))
    for p in resp.get("products", []):
        iv = items_to_intervals(p.get("items", []))
        print("产品:", p.get("product_id"))
        print("区间:", iv)
        print("区间文本:", interval_to_text(iv))
