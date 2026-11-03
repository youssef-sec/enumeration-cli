from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from ctf_enum.config import validate_target, validate_ports, load_config
from ctf_enum.scanner_nmap import parse_nmap_xml, open_tcp_ports
from ctf_enum.scanner_web import same_origin_url, parse_gobuster_text, parse_webanalyze_json, web_services
from ctf_enum.vuln_lookup import cves_from_nmap, technologies_from_scan, RCE_RE
from ctf_enum.report import build_markdown

SAMPLE_XML = '''<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV">
<host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="80"><state state="open"/>
<service name="http" product="Apache httpd" version="2.4.49"><cpe>cpe:/a:apache:http_server:2.4.49</cpe></service>
<script id="vulners" output="examples"><table key="cpe"><table><elem key="id">CVE-2021-41773</elem><elem key="cvss">7.5</elem></table></table></script>
</port><port protocol="tcp" portid="443"><state state="closed"/></port></ports>
</host></nmaprun>
'''

class CoreTests(unittest.TestCase):
    def test_nmap_xml(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "nmap.xml"
            path.write_text(SAMPLE_XML)
            result = parse_nmap_xml(path)
            self.assertEqual(open_tcp_ports(result), [80])
            self.assertEqual(result['hosts'][0]['ports'][0]['service']['cpes'], ['cpe:/a:apache:http_server:2.4.49'])
            self.assertEqual(result['hosts'][0]['ports'][0]['scripts'][0]['cves'], ['CVE-2021-41773'])
            self.assertEqual(cves_from_nmap(result)[0]['id'], 'CVE-2021-41773')
            self.assertEqual(web_services(result)[0]['port'], 80)

    def test_input_validation(self):
        self.assertEqual(validate_target('10.10.10.10'), '10.10.10.10')
        self.assertEqual(validate_target('2001:db8::10'), '2001:db8::10')
        self.assertEqual(validate_target('orion.htb'), 'orion.htb')
        for bad in ['https://example.com', '-iL', 'bad host', '127.0.0.1; touch /tmp/x']:
            with self.assertRaises(ValueError): validate_target(bad)
        self.assertEqual(validate_ports('22,80,8000-8080'), '22,80,8000-8080')
        for bad in ['0', '65536', '80-1', '80;sh', '']:
            with self.assertRaises(ValueError): validate_ports(bad)

    def test_web_scope_and_parsing(self):
        origin = 'http://192.0.2.10:8080'
        self.assertEqual(same_origin_url(origin, '/admin'), origin + '/admin')
        self.assertIsNone(same_origin_url(origin, '//evil.example/login'))
        self.assertIsNone(same_origin_url(origin, 'http://127.0.0.1:8080/login'))
        self.assertEqual(same_origin_url('http://example.test:80', 'http://example.test/login'), 'http://example.test/login')
        self.assertEqual(len(parse_gobuster_text('/admin (Status: 301) [Size: 0]\n', origin)), 1)
        raw, tech = parse_webanalyze_json('{"host":"x", "matches":[{"app_name":"Django","version":"4.2"}]}')
        self.assertEqual(tech[0]['version'], '4.2')
        self.assertEqual(raw['host'], 'x')
        self.assertFalse(bool(RCE_RE.search('Remote File Inclusion')))
        self.assertTrue(bool(RCE_RE.search('Remote Code Execution')))

    def test_technology_inventory_and_report(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'nmap.xml'; path.write_text(SAMPLE_XML)
            parsed = parse_nmap_xml(path)
            web = [{'port': 80, 'homepage_fingerprint': {'technologies': [{'name': 'Flask', 'version': '2.0'}]}, 'login_candidates': [{'url': 'http://x/login', 'fingerprint': {'technologies': [{'name': 'Django', 'version': '3.2'}]}}]}]
            names = {t['name'] for t in technologies_from_scan(parsed, web)}
            self.assertEqual(names, {'Apache httpd', 'Flask', 'Django'})
            md = build_markdown('192.0.2.10', {'parsed': parsed}, {'parsed': parsed}, [], {'findings': [], 'rce_candidates': []}, [])
            self.assertIn('Apache httpd', md)

    def test_config(self):
        p = Path(__file__).resolve().parent.parent / 'config.toml'
        self.assertGreater(load_config(p).min_rate, 0)

if __name__ == '__main__':
    unittest.main()
