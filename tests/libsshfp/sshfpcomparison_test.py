import unittest
import json

from libsshfp import SSHFP, SSHFPDomain, SSHFPComparison

class SSHFPDomainComparisonTest(unittest.TestCase):
	def test_to_json(self):
		sshfp1 = SSHFP(algo=SSHFP.ALGO_RSA, ftype=SSHFP.TYPE_SHA1, fingerprint="66b4b3d36098ec5231fcce828a8bf6ad3252fd71", domain="foobar.org", timestamp=1337)
		sshfp2 = SSHFP(algo=SSHFP.ALGO_ECDSA, ftype=SSHFP.TYPE_SHA256, fingerprint="66b4b3d36098ec5231fcce828a8bf6ad3252fd7131fcce828a8bf6ad3252fd71", domain="foobar.org", timestamp=1337)

		comparison = SSHFPComparison(domain="foobar.org", dns_sshfp=sshfp1, server_sshfp=sshfp2, errors=["Some Error"], is_authentic=True)

		j = json.loads(comparison.to_json())

		self.assertEqual(j['domain'], "foobar.org")
		self.assertEqual(len(j['errors']), 1)
		self.assertEqual(j['errors'][0], "Some Error")
		self.assertEqual(j['is_authentic'], True)
		self.assertEqual(j['dns']['algo'], SSHFP.algo_to_str(1))
		self.assertEqual(j['dns']['type'], SSHFP.type_to_str(1))
		self.assertEqual(j['dns']['fingerprint'], "66b4b3d36098ec5231fcce828a8bf6ad3252fd71")
		self.assertEqual(j['dns']['domain'], "foobar.org")
		self.assertEqual(j['dns']['timestamp'], 1337)
		self.assertEqual(j['server']['algo'], SSHFP.algo_to_str(3))
		self.assertEqual(j['server']['type'], SSHFP.type_to_str(2))
		self.assertEqual(j['server']['fingerprint'], "66b4b3d36098ec5231fcce828a8bf6ad3252fd7131fcce828a8bf6ad3252fd71")
		self.assertEqual(j['server']['domain'], "foobar.org")
		self.assertEqual(j['server']['timestamp'], 1337)
