"""Strict, deterministic input normalization. No signature verification."""
import json
import re

MAX256 = (1 << 256) - 1
ZERO = '0x' + '0' * 40

def _reject_duplicate_keys(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError(f'duplicate JSON key: {key}')
        seen[key] = value
    return seen

def strict_json(text):
    """json.loads that rejects duplicate object keys at every nesting level."""
    return json.loads(text, object_pairs_hook=_reject_duplicate_keys)

def obj(value):
    if isinstance(value, (bytes, str)):
        value = strict_json(value)
    if not isinstance(value, dict):
        raise ValueError('payload must be a JSON object')
    return value

def uint(value, bits=256):
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError('expected unsigned integer')
    try:
        n = int(value, 16 if value.startswith('0x') else 10) if isinstance(value, str) else value
    except ValueError as exc:
        raise ValueError('invalid unsigned integer') from exc
    if not 0 <= n < 1 << bits:
        raise ValueError(f'integer outside uint{bits}')
    return n

def address(value):
    if not isinstance(value, str) or not re.fullmatch(r'0x[0-9a-fA-F]{40}', value):
        raise ValueError('expected 20-byte 0x address')
    return value.lower()

def message(value):
    p = obj(value)
    m = obj(p['message']) if 'message' in p else p
    d = obj(p.get('domain', {}))
    context = {}
    if 'chainId' in d:
        context['chain_id'] = uint(d['chainId'])
    if 'verifyingContract' in d:
        context['verifying_contract'] = address(d['verifyingContract'])
    return p, m, context
