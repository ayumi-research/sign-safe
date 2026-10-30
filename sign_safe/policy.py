"""Deterministic policy. DENY dominates CONFIRM; allowlists never override denies."""
import copy
import json
from .decode.common import address, strict_json, uint, MAX256

DEFAULTS = {
    'known_targets': [], 'known_spenders': [], 'denied_addresses': [],
    'allowed_chain_ids': [], 'allow_any_chain': False,
    'max_deadline': 4102444800, 'max_validity_seconds': 2592000,
    'max_amount': None, 'confirm_unknown_spenders': True,
}

def load_policy(text):
    """JSON or deliberately small YAML subset: flat keys and scalar/list values."""
    try:
        result = strict_json(text)
    except json.JSONDecodeError:
        result = {}
        active = None
        def scalar(s):
            s = s.strip()
            if s.startswith('0x'):
                return s
            try:
                return json.loads(s)
            except json.JSONDecodeError:
                if len(s) >= 2 and s[0] == s[-1] == "'":
                    return s[1:-1]
                raise ValueError('YAML values must be JSON scalars/lists or quoted strings')
        for line in text.splitlines():
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            if line.startswith('  - ') and active:
                result[active].append(scalar(line[4:]))
                continue
            if line[:1].isspace() or ':' not in line:
                raise ValueError('unsupported YAML syntax')
            key, value = line.split(':', 1)
            key = key.strip()
            if key in result:
                raise ValueError('duplicate policy key')
            active = key if not value.strip() else None
            result[key] = [] if active else scalar(value)
    if not isinstance(result, dict):
        raise ValueError('policy must be an object')
    return result

class PolicyEngine:
    def __init__(self, rules=None):
        rules = {} if rules is None else rules
        if not isinstance(rules, dict) or set(rules) - set(DEFAULTS):
            raise ValueError('unknown policy keys or non-object policy')
        self.rules = copy.deepcopy(DEFAULTS)
        self.rules.update(copy.deepcopy(rules))
        for key in ('known_targets', 'known_spenders', 'denied_addresses'):
            if not isinstance(self.rules[key], list):
                raise ValueError(key + ' must be a list')
            self.rules[key] = [address(a) for a in self.rules[key]]
        if not isinstance(self.rules['allowed_chain_ids'], list):
            raise ValueError('allowed_chain_ids must be a list')
        self.rules['allowed_chain_ids'] = [uint(n) for n in self.rules['allowed_chain_ids']]
        for key in ('allow_any_chain', 'confirm_unknown_spenders'):
            if not isinstance(self.rules[key], bool):
                raise ValueError(key + ' must be boolean')
        for key in ('max_deadline', 'max_validity_seconds', 'max_amount'):
            if self.rules[key] is not None:
                self.rules[key] = uint(self.rules[key])
        if self.rules['max_deadline'] is None or self.rules['max_validity_seconds'] is None:
            raise ValueError('deadline caps must be integers')

    def evaluate(self, decoded, *, now=None):
        """Evaluate a decoder result. Pass trusted epoch seconds for relative expiry checks."""
        r = self.rules
        reasons = []
        if now is not None:
            now = uint(now)
        def add(verdict, code, message):
            reasons.append({'verdict': verdict, 'code': code, 'message': message})
        chain = decoded.get('chain_id')
        if r['allowed_chain_ids'] and chain not in r['allowed_chain_ids']:
            add('DENY', 'CHAIN_NOT_ALLOWED', 'Chain is missing or outside the configured chain list.')
        addresses = [decoded.get(k) for k in ('target', 'spender', 'owner', 'verifying_contract')]
        addresses += [a['token'] for a in decoded.get('allowances', [])]
        addresses += [v for k, v in decoded.get('arguments', {}).items() if k in ('spender', 'recipient', 'operator', 'from')]
        addresses += [d['to'] for d in decoded.get('unsigned_transfer_details', [])]
        if any(a in r['denied_addresses'] for a in addresses if a):
            add('DENY', 'ADDRESS_DENIED', 'Payload contains an explicitly denied address.')
        kind = decoded.get('type')
        if kind == 'eip7702':
            if chain == 0 and not r['allow_any_chain']:
                add('DENY', 'ANY_CHAIN_DELEGATION', 'Authorization is valid on any chain.')
            if decoded['action'] == 'delegate_code' and decoded['target'] not in r['known_targets']:
                add('DENY', 'UNKNOWN_DELEGATE', 'Code delegation target is not trusted.')
        elif kind in ('eip2612', 'permit2'):
            spender = decoded['spender']
            unknown = spender not in r['known_spenders']
            if unknown and r['confirm_unknown_spenders']:
                add('CONFIRM', 'UNKNOWN_SPENDER', 'Spender is not on the trusted list.')
            deadline = decoded.get('deadline')
            if deadline is None or deadline == MAX256 or deadline > r['max_deadline']:
                add('DENY', 'UNCAPPED_DEADLINE', 'Permit submission deadline is missing or exceeds the configured cap.')
            elif now is not None:
                if deadline < now:
                    add('DENY', 'EXPIRED_PERMIT', 'Permit submission deadline has passed.')
                elif deadline - now > r['max_validity_seconds']:
                    add('DENY', 'DEADLINE_TOO_FAR', 'Permit submission window exceeds the configured duration.')
            for a in decoded['allowances']:
                if a['unlimited'] and unknown:
                    add('DENY', 'UNLIMITED_UNKNOWN_SPENDER', 'Unlimited token permission to an unknown spender.')
                if r['max_amount'] is not None and a['amount'] > r['max_amount']:
                    add('DENY', 'AMOUNT_EXCEEDED', 'Token amount exceeds the configured raw-unit cap.')
                expiration = a['expiration']
                if kind == 'permit2' and decoded['action'] == 'allowance':
                    if expiration > r['max_deadline'] or expiration == (1 << 48) - 1:
                        add('DENY', 'UNCAPPED_ALLOWANCE_EXPIRATION', 'Permit2 allowance expiration exceeds the cap.')
                    elif now is not None and expiration != 0:
                        if expiration < now:
                            add('DENY', 'EXPIRED_ALLOWANCE', 'Permit2 allowance has expired.')
                        elif expiration - now > r['max_validity_seconds']:
                            add('DENY', 'ALLOWANCE_TOO_LONG', 'Allowance lifetime exceeds the duration cap.')
            if decoded['action'] == 'signature_transfer':
                add('CONFIRM', 'UNBOUND_RECIPIENT', 'Standard Permit2 signature transfers do not bind the recipient.')
        elif kind == 'raw_calldata':
            add('CONFIRM', 'CALLDATA_UNVERIFIED', 'Selector hints cannot prove contract behavior; review the full transaction.')
            args = decoded.get('arguments', {})
            spender = args.get('spender', args.get('operator'))
            if (args.get('amount') == MAX256 or args.get('approved') is True) and spender not in r['known_spenders'] and spender:
                add('DENY', 'UNLIMITED_UNKNOWN_SPENDER', 'Unlimited or all-token approval to an unknown spender.')
            if r['max_amount'] is not None and args.get('amount', 0) > r['max_amount']:
                add('DENY', 'AMOUNT_EXCEEDED', 'Call amount exceeds raw-unit cap.')
        else:
            add('DENY', 'UNSUPPORTED_PAYLOAD', 'No policy handler for this payload.')
        reasons = sorted({(x['verdict'], x['code'], x['message']): x for x in reasons}.values(), key=lambda x: x['code'])
        verdict = 'DENY' if any(x['verdict'] == 'DENY' for x in reasons) else 'CONFIRM' if reasons else 'ALLOW'
        return {'verdict': verdict, 'reasons': reasons}
