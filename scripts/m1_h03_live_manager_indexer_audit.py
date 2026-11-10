"""Read-only H03 audit, run inside Manager with a private base64 manifest argument.

Prints pseudonymous correlation records and aggregate checks, never raw sources.
No configuration writes, process execution on agents, or synthetic event injection.
"""
import base64
import collections
import datetime
import hashlib
import json
import os
import re
import ssl
import sys
import urllib.request


def run(expected, private_export=False):
    def stamp(value):
        return datetime.datetime.strptime(value, '%Y-%m-%dT%H:%M:%S.%f%z')
    begin = datetime.datetime.strptime(expected['audit_after_utc'], '%Y-%m-%dT%H:%M:%SZ')
    begin = begin.replace(tzinfo=datetime.timezone.utc)
    paths = {'positive': r'c:\securitylab\h03\h03-benignprobe.exe',
             'negative': r'c:\securitylab\h03\h03-negativeprobe.exe'}
    def role(event):
        sc = event.get('syscheck', {})
        win = event.get('data', {}).get('win', {})
        path = sc.get('path') or win.get('eventdata', {}).get('image', '')
        for name, value in paths.items():
            canonical = re.sub(r'\\+', lambda match: '\\', path.replace('/', '\\')).casefold()
            if canonical == value:
                return name
        return None
    manager = []
    invalid = 0
    with open('/var/ossec/logs/alerts/alerts.json', encoding='utf-8') as handle:
        for line in handle:
            try:
                event = json.loads(line)
            except ValueError:
                invalid += 1
                continue
            if event.get('agent', {}).get('id') == '004' and role(event) and stamp(event['timestamp']) >= begin:
                manager.append(event)
    query = {'size': 1000, 'track_total_hits': True, 'query': {'bool': {'filter': [
        {'term': {'agent.id': '004'}}, {'range': {'timestamp': {'gte': expected['audit_after_utc']}}}],
        'should': [{'exists': {'field': 'syscheck.path'}}, {'term': {'data.win.system.eventID': '1'}}],
        'minimum_should_match': 1}}, 'sort': [{'timestamp': 'asc'}]}
    context = ssl.create_default_context(cafile=os.environ['SSL_CERTIFICATE_AUTHORITIES'])
    request = urllib.request.Request(os.environ['INDEXER_URL'].strip().strip('"\'').rstrip('/') + '/wazuh-alerts-*/_search',
                                     data=json.dumps(query).encode(), method='POST')
    token = base64.b64encode((os.environ['INDEXER_USERNAME'] + ':' + os.environ['INDEXER_PASSWORD']).encode()).decode()
    request.add_header('Authorization', 'Basic ' + token)
    request.add_header('Content-Type', 'application/json')
    with urllib.request.urlopen(request, context=context, timeout=20) as response:
        result = json.load(response)
    total = result['hits']['total']
    complete = not result.get('timed_out') and result.get('_shards', {}).get('failed') == 0 and total.get('relation') == 'eq' and total['value'] <= 1000
    indexer = [hit['_source'] for hit in result['hits']['hits'] if role(hit['_source'])]
    def fingerprint(event):
        return json.dumps({key: event.get(key) for key in ('id','timestamp','agent','rule','syscheck','data')}, sort_keys=True)
    left = collections.Counter(fingerprint(event) for event in manager)
    right = collections.Counter(fingerprint(event) for event in indexer)
    exact = complete and left == right
    sha1, sha2 = expected['sha256_v1'], expected['sha256_v2']
    baseline = [event for event in indexer if role(event) == 'positive' and event.get('syscheck', {}).get('event') == 'added' and event['syscheck'].get('sha256_after') == sha1]
    modified = [event for event in indexer if role(event) == 'positive' and event.get('syscheck', {}).get('event') == 'modified' and event['syscheck'].get('sha256_before') == sha1 and event['syscheck'].get('sha256_after') == sha2]
    executions = []
    normalized = []
    def alias(value): return hashlib.sha256(value.encode()).hexdigest()[:24]
    def normalize(event, kind, source, actor):
        if not actor or not event.get('id'):
            raise ValueError('MissingSourceIdentity')
        return {'timestamp': event['timestamp'], 'kind': kind, 'source': source,
                'event_ref': 'evt-' + alias(event['id']), 'asset_key': 'agent-004',
                'actor_key': 'actor-' + alias(actor.casefold()),
                'object_key': 'artifact-' + alias(paths[role(event)])}
    for event in modified:
        normalized.append(normalize(event, 'file_change', 'wazuh_fim', event['syscheck'].get('uname_after')))
    for event in indexer:
        win = event.get('data', {}).get('win', {})
        data = win.get('eventdata', {})
        if str(win.get('system', {}).get('eventID')) != '1':
            continue
        hashes = data.get('hashes', '')
        hash_match = bool(re.search(r'(?:^|[,;])SHA256=' + re.escape(sha2) + r'(?:[,;]|$)', hashes, re.I))
        executions.append({'role': role(event), 'record_id': str(win['system'].get('eventRecordID', '')),
                           'process_guid': data.get('processGuid'), 'timestamp': event['timestamp'],
                           'native_system_time': win['system'].get('systemTime'), 'sha256_v2_match': hash_match,
                           'rule_id': event.get('rule', {}).get('id')})
        if hash_match:
            normalized.append(normalize(event, 'file_execution', 'sysmon_eid1', data.get('user')))
    outcome = {'query_complete': complete, 'manager_events': len(manager), 'indexer_events': len(indexer),
            'manager_indexer_exact': exact, 'baseline_ok': exact and len(baseline) == 1,
            'modified_ok': exact and len(modified) == 1, 'invalid_manager_json_lines': invalid,
            'negative_modified_events': sum(role(event) == 'negative' and event.get('syscheck', {}).get('event') == 'modified' for event in indexer),
            'executions': executions, 'normalized': normalized, 'discover_verified': False}
    if private_export:
        outcome['private_sources'] = {'manager': manager, 'indexer': indexer}
    return outcome


if __name__ == '__main__':
    try:
        expected = json.loads(base64.b64decode(sys.argv[1]))
        print(json.dumps(run(expected, private_export='--private-export' in sys.argv[2:])))
    except Exception as error:
        print(json.dumps({'audit_failed': True, 'error_type': type(error).__name__, 'http_status': getattr(error, 'code', None)}))
        raise SystemExit(2)
