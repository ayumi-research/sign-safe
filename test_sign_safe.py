"""Offline behavior and adversarial regression tests: python3 -m unittest -v."""
import copy
import json
import subprocess
import sys
import unittest
from pathlib import Path
from sign_safe import decode, explain, dumps, PolicyEngine, load_policy
from sign_safe.decode.common import MAX256
from sign_safe.decode.raw_calldata import SELECTORS

FIXTURES = Path(__file__).parent / 'sign_safe' / 'fixtures'
A, B, T = ['0x' + x * 40 for x in ('1', '2', '3')]

def fixture(name):
    return json.loads((FIXTURES / (name + '.json')).read_text())

class Tests(unittest.TestCase):
    def permit(self, **changes):
        p = fixture('eip2612')['payload']
        p.update(changes)
        return p

    def result(self, p=None, type='eip2612', policy=None, now=None):
        return explain(self.permit() if p is None else p, type=type, policy=policy, now=now)

    def has(self, result, verdict, code=None):
        self.assertEqual(result['verdict'], verdict)
        if code:
            self.assertIn(code, [r['code'] for r in result['reasons']])
        for r in result['reasons']:
            self.assertTrue(r['code'])

    def test_unknown_spender_confirms(self):
        self.has(self.result(), 'CONFIRM', 'UNKNOWN_SPENDER')

    def test_known_spender_allows(self):
        self.has(self.result(policy={'known_spenders':[B]}), 'ALLOW')

    def test_unknown_delegate_denied(self):
        self.has(self.result(fixture('eip7702')['payload'], 'eip7702'), 'DENY', 'UNKNOWN_DELEGATE')

    def test_known_delegate_allows(self):
        self.has(self.result(fixture('eip7702')['payload'], 'eip7702', {'known_targets':[B]}), 'ALLOW')

    def test_any_chain_denied(self):
        p = fixture('eip7702')['payload']; p[0] = 0
        self.has(self.result(p, 'eip7702', {'known_targets':[B]}), 'DENY', 'ANY_CHAIN_DELEGATION')

    def test_any_chain_explicit_allow(self):
        p = fixture('eip7702')['payload']; p[0] = 0
        self.has(self.result(p, 'eip7702', {'known_targets':[B], 'allow_any_chain':True}), 'ALLOW')

    def test_clear_delegation(self):
        p = fixture('eip7702')['payload']; p[1] = '0x'+'0'*40
        r = self.result(p, 'eip7702')
        self.has(r, 'ALLOW'); self.assertIn('Clears', r['summary'])

    def test_unlimited_unknown(self):
        self.has(self.result(self.permit(value=MAX256)), 'DENY', 'UNLIMITED_UNKNOWN_SPENDER')

    def test_unlimited_known(self):
        self.has(self.result(self.permit(value=MAX256), policy={'known_spenders':[B]}), 'ALLOW')

    def test_missing_deadline(self):
        p = self.permit(); del p['deadline']
        self.has(self.result(p), 'DENY', 'UNCAPPED_DEADLINE')

    def test_unlimited_deadline(self):
        self.has(self.result(self.permit(deadline=MAX256)), 'DENY', 'UNCAPPED_DEADLINE')

    def test_deadline_cap(self):
        self.has(self.result(policy={'max_deadline':100}), 'DENY', 'UNCAPPED_DEADLINE')

    def test_relative_cap(self):
        self.has(self.result(now=1), 'DENY', 'DEADLINE_TOO_FAR')

    def test_expired(self):
        self.has(self.result(now=2000000001), 'DENY', 'EXPIRED_PERMIT')

    def test_deadline_equality(self):
        self.has(self.result(now=2000000000,policy={'known_spenders':[B]}), 'ALLOW')

    def test_amount_cap(self):
        self.has(self.result(policy={'max_amount':99}), 'DENY', 'AMOUNT_EXCEEDED')

    def test_deny_precedence(self):
        self.has(self.result(policy={'known_spenders':[B], 'denied_addresses':[B]}), 'DENY', 'ADDRESS_DENIED')

    def test_chain_requires_context(self):
        self.has(self.result(policy={'allowed_chain_ids':[1]}), 'DENY', 'CHAIN_NOT_ALLOWED')

    def test_typed_message(self):
        p = {'domain':{'chainId':'0x1','verifyingContract':T}, 'message':self.permit()}
        del p['message']['token']
        r = self.result(p,policy={'allowed_chain_ids':[1],'known_spenders':[B]})
        self.has(r,'ALLOW'); self.assertEqual(r['decoded']['chain_id'],1)

    def test_permit2_unlimited(self):
        p=fixture('permit2_single')['payload']; p['details']['amount']=(1<<160)-1
        self.has(self.result(p,'permit2'),'DENY','UNLIMITED_UNKNOWN_SPENDER')

    def test_permit2_expiration_cap(self):
        p=fixture('permit2_single')['payload']; p['details']['expiration']=(1<<48)-1
        self.has(self.result(p,'permit2'),'DENY','UNCAPPED_ALLOWANCE_EXPIRATION')

    def test_permit2_batch_later_item(self):
        p=fixture('permit2_batch')['payload']; p['details'][1]['amount']=(1<<160)-1
        self.has(self.result(p,'permit2'),'DENY','UNLIMITED_UNKNOWN_SPENDER')

    def test_signature_transfer_confirm(self):
        self.has(self.result(fixture('permit2_transfer')['payload'],'permit2',{'known_spenders':[B]}),'CONFIRM','UNBOUND_RECIPIENT')

    def test_invalid_requested_amount(self):
        p=fixture('permit2_transfer')['payload']; p['transferDetails']['requestedAmount']=101
        self.has(self.result(p,'permit2'),'DENY','INVALID_PAYLOAD')

    def test_witness_rejected(self):
        p=fixture('permit2_transfer')['payload']; p['primaryType']='PermitWitnessTransferFrom'
        self.has(self.result(p,'permit2'),'DENY','INVALID_PAYLOAD')

    def test_bad_inputs(self):
        for value in (True, -1, 1.5, 'oops', 1<<256):
            with self.subTest(value=value):
                self.has(self.result(self.permit(value=value)),'DENY','INVALID_PAYLOAD')

    def test_bad_address(self):
        self.has(self.result(self.permit(spender='0x1234')),'DENY','INVALID_PAYLOAD')

    def test_json_bytes(self):
        self.assertEqual(decode(json.dumps(self.permit()).encode(),'eip2612'),decode(self.permit(),'eip2612'))

    def test_calldata_bytes(self):
        f=fixture('raw_calldata')
        self.assertEqual(decode(bytes.fromhex(f['payload']['data'][2:]),'raw_calldata')['arguments'],f['expected']['arguments'])

    def test_selector_table(self):
        self.assertGreaterEqual(len(SELECTORS),100)
        self.assertEqual(SELECTORS['0xa9059cbb'],['transfer(address,uint256)'])
        self.assertEqual(SELECTORS['0x70a08231'],['balanceOf(address)'])
        self.assertEqual(SELECTORS['0x42842e0e'],['safeTransferFrom(address,address,uint256)'])

    def test_raw_unknown_confirm(self):
        self.has(self.result('0xdeadbeef','raw_calldata'),'CONFIRM','CALLDATA_UNVERIFIED')

    def test_raw_known_confirm(self):
        self.has(self.result(fixture('raw_calldata')['payload'],'raw_calldata'),'CONFIRM','CALLDATA_UNVERIFIED')

    def test_raw_unlimited_deny(self):
        p=fixture('raw_calldata')['payload']; p['data']=p['data'][:-64]+'f'*64
        self.has(self.result(p,'raw_calldata'),'DENY','UNLIMITED_UNKNOWN_SPENDER')

    def test_raw_approval_for_all(self):
        p='0xa22cb465'+'00'*12+B[2:]+format(1,'064x')
        self.has(self.result(p,'raw_calldata'),'DENY','UNLIMITED_UNKNOWN_SPENDER')

    def test_malformed_calldata(self):
        for p in ('0x1','0xzz','0x095ea7b3','0xa22cb465'+'00'*12+B[2:]+format(2,'064x')):
            self.has(self.result(p,'raw_calldata'),'DENY','INVALID_PAYLOAD')

    def test_yaml(self):
        rules=load_policy((FIXTURES/'policy.yaml').read_text())
        self.assertEqual(rules['known_spenders'],[B]); PolicyEngine(rules)
        self.assertEqual(load_policy(dumps(rules)),rules)

    def test_bad_policy(self):
        for rules in ({'typo':True},{'known_spenders':B},{'allow_any_chain':'false'},{'max_deadline':None}):
            with self.assertRaises(ValueError): PolicyEngine(rules)
        with self.assertRaises(ValueError): load_policy('a: 1\na: 2')
        with self.assertRaises(ValueError): load_policy('known_spenders: &anchor []')

    def test_deterministic_and_no_mutation(self):
        p=self.permit(); original=copy.deepcopy(p)
        r=self.result(p); self.assertEqual(dumps(r),dumps(self.result(p))); self.assertEqual(p,original)
        self.assertEqual(dumps({'z':1,'a':2}),'{"a":2,"z":1}')

    def test_explanation_semantics(self):
        r=self.result(); self.assertIn('no automatic expiry',r['summary']); self.assertIn('raw units',r['summary'])
        self.assertIn('2033-05-18T03:33:20Z',r['summary'])

    def test_cli_allow(self):
        p=subprocess.run([sys.executable,'-m','sign_safe','explain','--type','permit2','--payload',str(FIXTURES/'payload.json'),'--policy',str(FIXTURES/'policy.yaml')],capture_output=True,text=True)
        self.assertEqual(p.returncode,0,p.stderr); self.assertEqual(json.loads(p.stdout)['verdict'],'ALLOW')
        self.assertEqual(p.stdout.strip(),dumps(json.loads(p.stdout)))

    def test_cli_confirm(self):
        p=subprocess.run([sys.executable,'-m','sign_safe','explain','--type','permit2','--payload',str(FIXTURES/'payload.json')],capture_output=True,text=True)
        self.assertEqual(p.returncode,3); self.assertEqual(json.loads(p.stdout)['verdict'],'CONFIRM')

    def test_duplicate_json_keys_rejected(self):
        for text in ('{"max_amount":1,"max_amount":1000}', '{"a":{"value":1,"value":2}}'):
            with self.assertRaises(ValueError):
                load_policy(text)
        with self.assertRaises(ValueError):
            decode('{"chain_id":1,"chain_id":2,"address":"%s","nonce":1}' % B, 'eip7702')

    def test_partial_authorization_signature_rejected(self):
        base = {'chain_id': 1, 'address': B, 'nonce': 7}
        for partial in ({'y_parity': 0}, {'r': 1}, {'s': 2}, {'r': 1, 's': 2}, {'y_parity': 0, 's': 2}):
            with self.assertRaises(ValueError):
                decode({**base, **partial}, 'eip7702')
        # none or all is fine
        decode(base, 'eip7702')
        decode({**base, 'y_parity': 0, 'r': 1, 's': 2}, 'eip7702')

    def test_denylisted_transfer_recipient_denied(self):
        f = fixture('permit2_transfer')['payload']
        to = f['transferDetails']['to']
        self.has(explain(f, type='permit2', policy=PolicyEngine({'denied_addresses': [to]})), 'DENY', 'ADDRESS_DENIED')
        # sanity: without the deny rule it must NOT deny on that address
        r = explain(f, type='permit2', policy=PolicyEngine({}))
        self.assertNotIn('ADDRESS_DENIED', [x['code'] for x in r['reasons']])

    def test_cli_error(self):
        p=subprocess.run([sys.executable,'-m','sign_safe','explain','--type','permit2','--payload',str(FIXTURES/'missing.json')],capture_output=True,text=True)
        self.assertEqual(p.returncode,2); self.assertEqual(json.loads(p.stdout)['reasons'][0]['code'],'INVALID_INPUT')

# Each synthetic fixture has an independently specified exact expected decode.
def fixture_test(name):
    def test(self):
        f = fixture(name)
        self.assertEqual(decode(f['payload'], f['type']), f['expected'])
    return test
for name in ('eip7702','eip2612','permit2_single','permit2_batch','permit2_transfer','permit2_transfer_batch','raw_calldata'):
    setattr(Tests,'test_fixture_'+name,fixture_test(name))

if __name__=='__main__': unittest.main()
