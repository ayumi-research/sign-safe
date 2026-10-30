"""Typed decoder dispatcher."""
from . import eip7702, eip2612, permit2, raw_calldata

DECODERS = {'eip7702': eip7702.decode, 'eip2612': eip2612.decode,
            'permit2': permit2.decode, 'raw_calldata': raw_calldata.decode}

def decode(payload, type):
    if type not in DECODERS:
        raise ValueError('unsupported payload type: ' + str(type))
    return DECODERS[type](payload)
