"""
ForensiQ AI - MITRE ATT&CK Matrix Correlation
Maps timeline events and extracted artifacts to ATT&CK tactics & techniques.
"""

from typing import List, Dict, Any

MITRE_TACTICS = [
    {'id': 'TA0001', 'name': 'Initial Access'},
    {'id': 'TA0002', 'name': 'Execution'},
    {'id': 'TA0003', 'name': 'Persistence'},
    {'id': 'TA0004', 'name': 'Privilege Escalation'},
    {'id': 'TA0005', 'name': 'Defense Evasion'},
    {'id': 'TA0006', 'name': 'Credential Access'},
    {'id': 'TA0007', 'name': 'Discovery'},
    {'id': 'TA0008', 'name': 'Lateral Movement'},
    {'id': 'TA0009', 'name': 'Collection'},
    {'id': 'TA0011', 'name': 'Command and Control'},
    {'id': 'TA0010', 'name': 'Exfiltration'},
    {'id': 'TA0040', 'name': 'Impact'},
]


def map_events_to_mitre(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Groups observed events under standardized MITRE Enterprise Tactics."""
    tactic_dict: Dict[str, Dict[str, Any]] = {
        t['id']: {'id': t['id'], 'name': t['name'], 'techniques': {}}
        for t in MITRE_TACTICS
    }

    for evt in events:
        tactic_str = evt.get('mitre_tactic', '')
        tech_id = evt.get('mitre_id', '')
        tech_name = evt.get('mitre_technique', '')

        if not tactic_str or not tech_id:
            continue

        # Extract tactic ID (e.g. TA0040)
        t_id = 'TA0002'
        for t in MITRE_TACTICS:
            if t['id'] in tactic_str:
                t_id = t['id']
                break

        group = tactic_dict[t_id]
        if tech_id not in group['techniques']:
            group['techniques'][tech_id] = {
                'id': tech_id,
                'name': tech_name,
                'tactic': tactic_str,
                'count': 1,
                'event_ids': [evt['id']],
                'severity': evt.get('severity', 'LOW')
            }
        else:
            group['techniques'][tech_id]['count'] += 1
            group['techniques'][tech_id]['event_ids'].append(evt['id'])

    result = []
    for t in MITRE_TACTICS:
        g = tactic_dict[t['id']]
        result.append({
            'id': g['id'],
            'name': g['name'],
            'techniques': list(g['techniques'].values())
        })
    return result
