"""End-to-end smoke test using fake executables. Never sends network traffic."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from test_core import SAMPLE_XML

ROOT = Path(__file__).resolve().parent.parent

class IntegrationTests(unittest.TestCase):
    def test_full_run_mocked_tools(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            bin_dir = root / 'bin'; bin_dir.mkdir()
            xml = root / 'sample.xml'; xml.write_text(SAMPLE_XML)
            script = bin_dir / 'nmap'
            script.write_text(f'''#!/usr/bin/env python3
import sys, shutil
args=sys.argv[1:]
shutil.copyfile({str(xml)!r}, args[args.index('-oX')+1])
''')
            # Avoid any tool installation dependency; emulate CLI outputs.
            gob = bin_dir / 'gobuster'
            gob.write_text('''#!/usr/bin/env python3
import sys
out=sys.argv[sys.argv.index('-o')+1]
open(out,'w').write('/login (Status: 200) [Size: 200]\\n')
''')
            wa = bin_dir / 'webanalyze'
            wa.write_text('''#!/usr/bin/env python3
import json,sys
url=sys.argv[sys.argv.index('-host')+1]
print(json.dumps({'host':url,'matches':[{'app_name':'Django' if 'login' in url else 'Apache','version':'3.2' if 'login' in url else '2.4'}]}))
''')
            ss = bin_dir / 'searchsploit'
            ss.write_text('''#!/usr/bin/env python3
import json
print(json.dumps({'RESULTS_EXPLOIT':[{'Title':'Apache 2.4 - Remote Code Execution','EDB-ID':'12345','Path':'linux/webapps/12345.py'}]}))
''')
            for exe in bin_dir.iterdir(): exe.chmod(0o755)
            wordlist = root / 'common.txt'; wordlist.write_text('login\nadmin\n')
            tech = root / 'technologies.json'; tech.write_text('{}')
            config = root / 'config.toml'
            config.write_text(f'''[paths]
wordlist = "{wordlist}"
webanalyze_apps = "{tech}"
[web]
http_timeout=1
gobuster_timeout=5
max_concurrency=1
[scan]
nmap_timeout=15
command_timeout=15
''')
            output = root / 'out'
            env = os.environ.copy(); env['PATH'] = str(bin_dir) + os.pathsep + env.get('PATH', '')
            cmd = [sys.executable, '-m', 'ctf_enum', '192.0.2.10', '--ports', '80', '--config', str(config), '--output', str(output), '--authorized']
            result = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, env=env, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr + (output / '01_nmap_discovery.json').read_text())
            self.assertTrue((output / 'report.json').is_file())
            report = json.loads((output / 'report.json').read_text())
            self.assertEqual(report['phase1']['status'], 'complete')
            self.assertEqual(report['phase2']['parsed']['hosts'][0]['ports'][0]['scripts'][0]['cves'], ['CVE-2021-41773'])
            self.assertEqual(report['web'][0]['gobuster']['paths'][0]['path'], '/login')
            self.assertEqual(report['web'][0]['login_candidates'][0]['fingerprint']['technologies'][0]['name'], 'Django')
            self.assertGreater(len(report['vulnerabilities']['rce_candidates']), 0)
            resumed = subprocess.run(cmd + ['--resume'], cwd=ROOT, capture_output=True, text=True, env=env, timeout=20)
            self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)

if __name__ == '__main__':
    unittest.main()
