"""Proposed rule boundaries; synthetic strings, no process execution."""
import re
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class H03TelemetryScope(unittest.TestCase):
    def test_only_two_exact_probe_paths(self):
        root = ET.parse(ROOT / 'config/h03-benign-process-telemetry.xml').getroot()
        self.assertEqual(root.tag, 'group')
        self.assertEqual(len(root.findall('rule')), 1)
        rule = root.find('rule')
        self.assertEqual(rule.attrib, {'id': '110150', 'level': '3'})
        self.assertEqual(rule.findtext('if_group'), 'sysmon_event1')
        self.assertIsNone(rule.find('mitre'))
        fields = {field.attrib['name']: field.text for field in rule.findall('field')}
        self.assertEqual(len(fields), 3)
        self.assertEqual(fields['win.system.providerName'], '^Microsoft-Windows-Sysmon$')
        self.assertEqual(fields['win.system.eventID'], '^1$')
        pattern = re.compile(fields['win.eventdata.image'])
        for name in ('Benign', 'Negative'):
            path = fr'C:\SecurityLab\H03\H03-{name}Probe.exe'
            self.assertIsNotNone(pattern.fullmatch(path))
            self.assertIsNotNone(pattern.fullmatch(path.replace('\\', '\\\\')))
        for path in (
            r'C:\SecurityLab\H03\sub\H03-BenignProbe.exe',
            r'C:\SecurityLab\H03\H03-BenignProbe.exe.bak',
            r'C:\SecurityLab\H03\Other.exe',
            r'C:\Elsewhere\H03-BenignProbe.exe',
            r'D:\SecurityLab\H03\H03-BenignProbe.exe',
            r'C:\SecurityLab\H030\H03-BenignProbe.exe',
        ):
            with self.subTest(path=path):
                self.assertIsNone(pattern.fullmatch(path))


if __name__ == '__main__':
    unittest.main()
