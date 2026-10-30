"""Permit2 allowance and signature-transfer typed messages."""
from .common import message, address, uint

def decode(payload):
    p, m, context = message(payload)
    kind = p.get('primaryType', p.get('kind', 'PermitSingle'))
    allowed = ('PermitSingle', 'PermitBatch', 'PermitTransferFrom', 'PermitBatchTransferFrom')
    if kind not in allowed:
        raise ValueError('unsupported Permit2 type (witness permits require a dedicated decoder)')
    transfer = kind in allowed[2:]
    batch = kind in (allowed[1], allowed[3])
    details = m['permitted' if transfer else 'details']
    if batch:
        if not isinstance(details, list) or not details:
            raise ValueError('batch must contain at least one permission')
    else:
        details = [details]
    allowances = []
    for d in details:
        bits = 256 if transfer else 160
        amount = uint(d['amount'], bits)
        item = {'token': address(d['token']), 'amount': amount,
                'unlimited': amount == (1 << bits) - 1,
                'expiration': None if transfer else uint(d['expiration'], 48)}
        if not transfer:
            item['nonce'] = uint(d['nonce'], 48)
        allowances.append(item)
    field = 'deadline' if transfer else 'sigDeadline'
    result = dict(context, type='permit2', kind=kind,
                  action='signature_transfer' if transfer else 'allowance',
                  spender=address(m['spender']), allowances=allowances,
                  deadline=uint(m[field]) if m.get(field) is not None else None)
    if transfer:
        result['nonce'] = uint(m['nonce'])
        result['recipient_bound_by_signature'] = False
        if 'transferDetails' in p:
            td = p['transferDetails'] if batch else [p['transferDetails']]
            if not isinstance(td, list) or len(td) != len(allowances):
                raise ValueError('transfer details length mismatch')
            result['unsigned_transfer_details'] = []
            for d, a in zip(td, allowances):
                amount = uint(d['requestedAmount'])
                if amount > a['amount']:
                    raise ValueError('requested amount exceeds permission')
                result['unsigned_transfer_details'].append({'to': address(d['to']), 'requested_amount': amount})
    return result
