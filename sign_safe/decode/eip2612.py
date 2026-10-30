"""ERC-2612: deadline limits submission, NOT lifetime of the resulting allowance."""
from .common import message, address, uint, MAX256

def decode(payload):
    p, m, context = message(payload)
    token = context.get('verifying_contract') or address(p['token'])
    amount = uint(m['value'])
    return dict(context, type='eip2612', action='allowance', owner=address(m['owner']),
                spender=address(m['spender']), nonce=uint(m['nonce']),
                deadline=uint(m['deadline']) if m.get('deadline') is not None else None,
                allowances=[{'token': token, 'amount': amount, 'unlimited': amount == MAX256,
                             'expiration': None}])
