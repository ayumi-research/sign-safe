"""Authorization inspection; canonical EIP-7702 tuple order is chain_id, address, nonce, y_parity, r, s."""
import json
from .common import obj, strict_json, uint, address, ZERO

_FIELDS = ('chain_id', 'address', 'nonce', 'y_parity', 'r', 's')

def decode(payload):
    if isinstance(payload, (str, bytes)):
        payload = strict_json(payload)
    if isinstance(payload, (list, tuple)):
        if len(payload) == 6:
            payload = dict(zip(_FIELDS, payload))
        elif len(payload) == 3:  # unsigned intent: chain_id, address, nonce
            payload = dict(zip(('chain_id', 'address', 'nonce'), payload))
        else:
            raise ValueError('authorization requires 6 fields (or 3 for an unsigned intent)')
    p = obj(payload)
    result = {'type': 'eip7702', 'chain_id': uint(p['chain_id']),
              'target': address(p['address']), 'nonce': uint(p['nonce'], 64)}
    sig_fields = [k for k in ('y_parity', 'r', 's') if k in p]
    if len(sig_fields) == 3:
        result['y_parity'] = uint(p['y_parity'], 1)
        result['r'] = uint(p['r'])
        result['s'] = uint(p['s'])
    elif sig_fields:
        raise ValueError('authorization requires none or all of y_parity, r, s (partial signatures are rejected)')
    if result['nonce'] == (1 << 64) - 1:
        raise ValueError('authorization nonce must be below uint64 maximum')
    result['action'] = 'clear_delegation' if result['target'] == ZERO else 'delegate_code'
    return result
