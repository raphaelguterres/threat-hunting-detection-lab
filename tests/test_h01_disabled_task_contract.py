"""Guard the disabled, triggerless H01 task and the one-shot approval boundary."""
import re
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NS = {'t': 'http://schemas.microsoft.com/windows/2004/02/mit/task'}


def validate_template(content):
    root = ET.fromstring(content)
    if root.tag != '{'+NS['t']+'}Task':
        raise ValueError('task root required')
    if len(root.find('t:Triggers', NS)) != 0:
        raise ValueError('no trigger permitted')
    for field in ('Enabled', 'AllowStartOnDemand', 'WakeToRun'):
        if root.findtext('t:Settings/t:'+field, namespaces=NS) != 'false':
            raise ValueError('disabled non-demand task required')
    if root.findtext('t:Principals/t:Principal/t:RunLevel', namespaces=NS) != 'LeastPrivilege':
        raise ValueError('least privilege required')
    actions = root.find('t:Actions', NS)
    if len(actions) != 1 or actions[0].tag != '{'+NS['t']+'}Exec':
        raise ValueError('one inert action required')
    if actions[0].findtext('t:Command', namespaces=NS) != r'C:\Windows\System32\cmd.exe' or actions[0].findtext('t:Arguments', namespaces=NS) != '/c exit 0':
        raise ValueError('inert action only')


class H01DisabledTaskContract(unittest.TestCase):
    def setUp(self):
        self.content = (ROOT / 'config/h01-disabled-task-template.xml').read_text(encoding='utf-8')

    def test_template_is_disabled_triggerless_and_inert(self):
        validate_template(self.content)

    def test_enabled_task_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_template(self.content.replace('<Enabled>false</Enabled>', '<Enabled>true</Enabled>'))

    def test_registration_trigger_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_template(self.content.replace('<Triggers />', '<Triggers><RegistrationTrigger /></Triggers>'))

    def test_demand_start_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_template(self.content.replace('<AllowStartOnDemand>false', '<AllowStartOnDemand>true'))

    def test_unreviewed_action_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_template(self.content.replace('/c exit 0', '/c unexpected-command'))

    def test_create_only_registration_and_no_run_or_enable_calls(self):
        text = (ROOT / 'scripts/M1_H01_DISABLED_TASK_PAYLOAD.ps1').read_text(encoding='utf-8')
        self.assertIn('.RegisterTaskDefinition($manifest.task_name,$definition,2,$identity.Name,$null,3,$null)', text)
        self.assertNotRegex(text, r'(?i)\.(?:Run|RunEx)\s*\(')
        self.assertNotRegex(text, r'(?i)\.Enabled\s*=\s*\$true')
        self.assertNotRegex(text, r'(?i)(?:Set-ExecutionPolicy|auditpol[^\r\n]*/set)')
        self.assertIn('$folder.DeleteTask($manifest.task_name,0)', text)

    def test_controller_keeps_execution_policy_and_one_shot_boundary(self):
        text = (ROOT / 'scripts/M1_H01_ENCODED_CONTROLLER.ps1').read_text(encoding='utf-8')
        self.assertNotRegex(text, r'(?i)-ExecutionPolicy\s+Bypass|Set-ExecutionPolicy')
        self.assertIn('[IO.FileMode]::CreateNew', text)
        self.assertIn("$approval.scope -cne 'one_disabled_h01_task_no_action'", text)
        self.assertIn('-NoProfile -NonInteractive -EncodedCommand $encoded', text)
