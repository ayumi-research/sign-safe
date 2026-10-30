"""Offline selector hints. Never establishes actual contract semantics."""
import json
from pathlib import Path
from .common import obj, address, uint

SELECTORS = json.loads(Path(__file__).with_name('selectors.json').read_text())

def decode(payload):
    context = {}
    if isinstance(payload, dict):
        p = obj(payload)
        payload = p['data']
        if 'to' in p:
            context['target'] = address(p['to'])
        if 'value' in p:
            context['value'] = uint(p['value'])
    if isinstance(payload, str):
        if not payload.startswith('0x') or len(payload) % 2:
            raise ValueError('calldata must be even-length 0x hex')
        try:
            payload = bytes.fromhex(payload[2:])
        except ValueError as exc:
            raise ValueError('invalid calldata hex') from exc
    if not isinstance(payload, bytes):
        raise ValueError('calldata must be bytes, hex, or a transaction object')
    selector = '0x' + payload[:4].hex() if len(payload) >= 4 else None
    candidates = SELECTORS.get(selector, [])
    result = dict(context, type='raw_calldata', action='contract_call', selector=selector,
                  candidates=candidates, data='0x'+payload.hex(), fully_decoded=False)
    # Only decode exact static layouts for common high-risk calls.
    types = {'0x095ea7b3': ('spender', 'amount'), '0xa9059cbb': ('recipient', 'amount'),
             '0x23b872dd': ('from', 'recipient', 'amount'),
             '0xa22cb465': ('operator', 'approved')}.get(selector)
    if types:
        if len(payload) != 4 + 32 * len(types):
            raise ValueError('invalid static ABI argument length')
        args = {}
        for i, name in enumerate(types):
            word = payload[4+32*i:36+32*i]
            n = int.from_bytes(word, 'big')
            if name in ('amount', 'approved'):
                if name == 'approved' and n not in (0, 1):
                    raise ValueError('invalid ABI boolean')
                args[name] = bool(n) if name == 'approved' else n
            else:
                if any(word[:12]):
                    raise ValueError('noncanonical ABI address')
                args[name] = '0x'+word[12:].hex()
        result['arguments'] = args
    return result
