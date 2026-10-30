"""One inspection entry point for agents and the CLI."""
import json
from datetime import datetime, timezone
from .decode import decode
from .policy import PolicyEngine

def dumps(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)

def date(value):
    if value is None:
        return 'unspecified'
    try:
        return datetime.fromtimestamp(value, timezone.utc).isoformat().replace('+00:00', 'Z')
    except (OverflowError, OSError, ValueError):
        return f'epoch {value}'

def summarize(d):
    if d['type'] == 'eip7702':
        chain = 'any chain' if d['chain_id'] == 0 else f"chain {d['chain_id']}"
        if d['action'] == 'clear_delegation':
            return f"Clears this EOA's code delegation on {chain}."
        return f"Delegates this EOA's execution to contract {d['target']} on {chain}. Delegation persists until changed or cleared."
    if d['type'] == 'raw_calldata':
        hint = ', '.join(d['candidates']) or 'unknown selector'
        return f"Contract call {d['selector']}: candidate {hint}. Arguments: {dumps(d.get('arguments', {}))}. Target: {d.get('target', 'unspecified')}; native value (wei): {d.get('value', 'unspecified')}. Nested calls and actual behavior are unverified."
    lines = []
    for a in d['allowances']:
        amount = 'UNLIMITED' if a['unlimited'] else str(a['amount'])
        lines.append(f"This signature lets {d['spender']} move up to {amount} raw units of token {a['token']}.")
        if d['type'] == 'eip2612':
            lines.append('The resulting allowance has no automatic expiry; the deadline only limits permit submission.')
        elif d['action'] == 'allowance':
            lines.append('Allowance expires at the submission block timestamp (expiration=0).' if a['expiration'] == 0 else f"Allowance expires {date(a['expiration'])}.")
        else:
            lines.append('One-time signature transfer; the spender can select the recipient. Supplied transfer details are unsigned context.')
    lines.append(f"Signature submission deadline: {date(d['deadline'])}.")
    return ' '.join(lines)

def explain(payload, *, type, policy=None, now=None):
    engine = policy if isinstance(policy, PolicyEngine) else PolicyEngine(policy)
    try:
        decoded = decode(payload, type)
    except (ValueError, KeyError, TypeError, OverflowError) as exc:
        reason = {'verdict': 'DENY', 'code': 'INVALID_PAYLOAD', 'message': 'Malformed or unsupported payload: ' + str(exc)}
        return {'decoded': None, 'verdict': 'DENY', 'reasons': [reason],
                'summary': 'DENY [INVALID_PAYLOAD]: ' + reason['message']}
    result = engine.evaluate(decoded, now=now)
    result['decoded'] = decoded
    codes = ', '.join(x['code'] for x in result['reasons'])
    result['summary'] = result['verdict'] + (f' [{codes}]' if codes else '') + ': ' + summarize(decoded)
    if result['reasons']:
        result['summary'] += ' ' + ' '.join(x['message'] for x in result['reasons'])
    result['summary'] += ' Inspection only: signature, domain schema, and on-chain state are not verified.'
    return result
