import unittest
import json

from libsshfp import SSHFP, SSHFPDomain

class SSHFPDomainTest(unittest.TestCase):
	def test_from_dict(self):
		for a in [0,1,2,3,4,6]:
			for t in [1,2]:
				if t == 1:
					h = "66b4b3d36098ec5231fcce828a8bf6ad3252fd71"
				elif t == 2:
					h = "66b4b3d36098ec5231fcce828a8bf6ad3252fd7131fcce828a8bf6ad3252fd71"
				sshfp_dict = {
					'algo': a,
					'type': t,
					'fingerprint': h
				}

				sshfpd_dict = {
					'domain': 'foobar.org',
					'timestamp': 1337,
					'records': [sshfp_dict]
				}
				
				sshfpd_obj = SSHFPDomain.from_dict(sshfpd_dict)

				self.assertEqual(sshfpd_obj.domain, 'foobar.org')
				self.assertEqual(sshfpd_obj.timestamp, 1337)

				self.assertEqual(len(sshfpd_obj.records), 1)

				self.assertEqual(sshfpd_obj.records[0].algo, a)
				self.assertEqual(sshfpd_obj.records[0].type, t)
				self.assertEqual(sshfpd_obj.records[0].fingerprint, h)
				self.assertEqual(sshfpd_obj.records[0].domain, None)
				self.assertEqual(sshfpd_obj.records[0].timestamp, 0)

		self.assertRaises(Exception, SSHFPDomain.from_dict, {})

	def test_from_json(self):
		for a in [0,1,2,3,4,6]:
			for t in [1,2]:
				if t == 1:
					h = "66b4b3d36098ec5231fcce828a8bf6ad3252fd71"
				elif t == 2:
					h = "66b4b3d36098ec5231fcce828a8bf6ad3252fd7131fcce828a8bf6ad3252fd71"
				sshfp_dict = {
					'algo': a,
					'type': t,
					'fingerprint': h
				}

				sshfpd_dict = {
					'domain': 'foobar.org',
					'timestamp': 1337,
					'records': [sshfp_dict]
				}
				
				sshfpd_obj = SSHFPDomain.from_json(json.dumps(sshfpd_dict))

				self.assertEqual(sshfpd_obj.domain, 'foobar.org')
				self.assertEqual(sshfpd_obj.timestamp, 1337)

				self.assertEqual(len(sshfpd_obj.records), 1)

				self.assertEqual(sshfpd_obj.records[0].algo, a)
				self.assertEqual(sshfpd_obj.records[0].type, t)
				self.assertEqual(sshfpd_obj.records[0].fingerprint, h)
				self.assertEqual(sshfpd_obj.records[0].domain, None)
				self.assertEqual(sshfpd_obj.records[0].timestamp, 0)

		self.assertRaises(Exception, SSHFPDomain.from_dict, "")

	def test_to_json(self):
		for a in [0,1,2,3,4,6]:
			for t in [1,2]:
				if t == 1:
					h = "66b4b3d36098ec5231fcce828a8bf6ad3252fd71"
				elif t == 2:
					h = "66b4b3d36098ec5231fcce828a8bf6ad3252fd7131fcce828a8bf6ad3252fd71"
				sshfp_dict = {
					'algo': a,
					'type': t,
					'fingerprint': h
				}

				sshfpd_dict = {
					'domain': 'foobar.org',
					'timestamp': 1337,
					'records': [sshfp_dict]
				}
				
				sshfpd_obj = SSHFPDomain.from_dict(sshfpd_dict)

				j = json.loads(sshfpd_obj.to_json())

				self.assertEqual(j['domain'], 'foobar.org')
				self.assertEqual(j['timestamp'], 1337)

				self.assertEqual(len(j['records']), 1)

				self.assertEqual(j['records'][0]['algo'], SSHFP.algo_to_str(a))
				self.assertEqual(j['records'][0]['type'], SSHFP.type_to_str(t))
				self.assertEqual(j['records'][0]['fingerprint'], h)
				self.assertEqual(j['records'][0]['domain'], None)
				self.assertEqual(j['records'][0]['timestamp'], 0)

	def test_to_dict(self):
		for a in [0,1,2,3,4,6]:
			for t in [1,2]:
				if t == 1:
					h = "66b4b3d36098ec5231fcce828a8bf6ad3252fd71"
				elif t == 2:
					h = "66b4b3d36098ec5231fcce828a8bf6ad3252fd7131fcce828a8bf6ad3252fd71"
				sshfp_dict = {
					'algo': a,
					'type': t,
					'fingerprint': h
				}

				sshfpd_dict = {
					'domain': 'foobar.org',
					'timestamp': 1337,
					'records': [sshfp_dict]
				}
				
				sshfpd_obj = SSHFPDomain.from_dict(sshfpd_dict)

				d = sshfpd_obj.to_dict()

				self.assertEqual(d['domain'], 'foobar.org')
				self.assertEqual(d['timestamp'], 1337)

				self.assertEqual(len(d['records']), 1)

				self.assertEqual(d['records'][0].algo, a)
				self.assertEqual(d['records'][0].type, t)
				self.assertEqual(d['records'][0].fingerprint, h)
				self.assertEqual(d['records'][0].domain, None)
				self.assertEqual(d['records'][0].timestamp, 0)
