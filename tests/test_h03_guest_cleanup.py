"""Exercise the actual PowerShell finalizer against disposable local fixtures."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == 'nt' and shutil.which('powershell.exe'), 'Windows PowerShell required')
class GuestCleanup(unittest.TestCase):
    def test_removes_only_owned_hash_and_preserves_unrelated_content(self):
        script = r'''
param([string]$Source,[string]$Work)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'ParseFailed'}
$hashFunction=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Hash'},$true)
Invoke-Expression $hashFunction.Extent.Text
$mainTry=$ast.Find({param($node) $node -is [Management.Automation.Language.TryStatementAst] -and $node.Finally -and $node.Finally.Extent.Text.Contains('$cleanup=$true')},$true)
if(-not $mainTry){throw 'FinalizerMissing'}
function Publish([string]$name,$value) {}
function Get-Service { [pscustomobject]@{Status='Running'} }
$owned=Join-Path $Work 'owned-probe.fixture'
$other=Join-Path $Work 'unrelated.fixture'
[IO.File]::WriteAllText($owned,'own-version-one')
[IO.File]::WriteAllText($other,'unrelated-content')
$config=Join-Path $Work 'config.fixture'
[IO.File]::WriteAllText($config,'unchanged-fixture-config')
$configHash=Hash $config
$manifest=[pscustomobject]@{session='synthetic-cleanup-session';sha256_v1=(Hash $owned);sha256_v2=('b'*64)}
$created=@($owned,$other)
$EvidenceDirectory=$Work
$body=$mainTry.Finally.Extent.Text
& ([scriptblock]::Create($body.Substring(1,$body.Length-2)))
if([IO.File]::Exists($owned)){throw 'OwnedFileNotRemoved'}
if(-not [IO.File]::Exists($other) -or [IO.File]::ReadAllText($other) -cne 'unrelated-content'){throw 'UnrelatedFileChanged'}
$result=Get-Content -Raw -LiteralPath (Join-Path $Work 'cleanup.json') | ConvertFrom-Json
if($result.cleanup_pass -ne $false -or $result.remaining_test_files -ne 1 -or $result.config_unchanged -ne $true){throw 'IncorrectCleanupReceipt'}
Write-Output 'ACTUAL_FINALIZER_BOUNDARIES=PASS'
'''
        with tempfile.TemporaryDirectory(prefix='h03-cleanup-test-') as temporary:
            directory = Path(temporary)
            runner = directory / 'run.ps1'
            runner.write_text(script, encoding='utf-8')
            result = subprocess.run(
                ['powershell.exe', '-NoProfile', '-File', str(runner),
                 '-Source', str(ROOT / 'scripts/M1_H03_CONTROLLED_BINARY_TEST.ps1'),
                 '-Work', str(directory)],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode and ('AuthorizationManager' in result.stderr or 'UnauthorizedAccess' in result.stderr):
                self.skipTest('Host policy blocks temporary PowerShell scripts; policy preserved')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('ACTUAL_FINALIZER_BOUNDARIES=PASS', result.stdout)
