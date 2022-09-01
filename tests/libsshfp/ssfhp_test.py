import unittest
import json

from libsshfp import SSHFP

class SSHFPTest(unittest.TestCase):

	def test_constants(self):
		self.assertEqual(getattr(SSHFP, "ALGO_RESERVED"), 0)
		self.assertEqual(getattr(SSHFP, "ALGO_RSA"), 1)
		self.assertEqual(getattr(SSHFP, "ALGO_DSA"), 2)
		self.assertEqual(getattr(SSHFP, "ALGO_ECDSA"), 3)
		self.assertEqual(getattr(SSHFP, "ALGO_ED25519"), 4)
		self.assertEqual(getattr(SSHFP, "ALGO_ED448"), 6)
		self.assertEqual(getattr(SSHFP, "TYPE_RESERVED"), 0)
		self.assertEqual(getattr(SSHFP, "TYPE_SHA1"), 1)
		self.assertEqual(getattr(SSHFP, "TYPE_SHA256"), 2)

	def test_algo_to_id(self):
		self.assertEqual(SSHFP.algo_to_id("RESERVED"), 0)
		self.assertEqual(SSHFP.algo_to_id("RSA"), 1)
		self.assertEqual(SSHFP.algo_to_id("DSA"), 2)
		self.assertEqual(SSHFP.algo_to_id("ECDSA"), 3)
		self.assertEqual(SSHFP.algo_to_id("ED25519"), 4)
		self.assertEqual(SSHFP.algo_to_id("ED448"), 6)

		self.assertRaises(Exception, SSHFP.algo_to_id, "foobar")
		self.assertRaises(Exception, SSHFP.algo_to_id, "")

	def test_algo_to_str(self):
		self.assertEqual(SSHFP.algo_to_str(0), "RESERVED")
		self.assertEqual(SSHFP.algo_to_str(1), "RSA")
		self.assertEqual(SSHFP.algo_to_str(2), "DSA")
		self.assertEqual(SSHFP.algo_to_str(3), "ECDSA")
		self.assertEqual(SSHFP.algo_to_str(4), "ED25519")
		self.assertEqual(SSHFP.algo_to_str(6), "ED448")

		self.assertRaises(Exception, SSHFP.algo_to_str, -1)
		self.assertRaises(Exception, SSHFP.algo_to_str, 5)
		self.assertRaises(Exception, SSHFP.algo_to_str, 7)

	def test_type_to_str(self):
		self.assertEqual(SSHFP.type_to_str(0), "RESERVED")
		self.assertEqual(SSHFP.type_to_str(1), "SHA1")
		self.assertEqual(SSHFP.type_to_str(2), "SHA256")

		self.assertRaises(Exception, SSHFP.type_to_str, -1)
		self.assertRaises(Exception, SSHFP.type_to_str, 3)

	def test_type_to_id(self):
		self.assertEqual(SSHFP.type_to_id("RESERVED"), 0)
		self.assertEqual(SSHFP.type_to_id("SHA1"), 1)
		self.assertEqual(SSHFP.type_to_id("SHA256"), 2)

		self.assertRaises(Exception, SSHFP.type_to_id, "foobar")
		self.assertRaises(Exception, SSHFP.type_to_id, "")

	def test_from_string(self):
		for a in [0,1,2,3,4,6]:
			for t in [1,2]:
				if t == 1:
					h = "66b4b3d36098ec5231fcce828a8bf6ad3252fd71"
				elif t == 2:
					h = "66b4b3d36098ec5231fcce828a8bf6ad3252fd7131fcce828a8bf6ad3252fd71"
				sshfp = f"{a} {t} {h}"
				sshfp_obj = SSHFP.from_string(sshfp)
				self.assertEqual(sshfp_obj.algo, a)
				self.assertEqual(sshfp_obj.type, t)
				self.assertEqual(sshfp_obj.fingerprint, h)
				self.assertEqual(sshfp_obj.domain, None)
				self.assertEqual(sshfp_obj.timestamp, None)

		# invalid algos
		for a in [-1,5,7]:
			for t in [1,2]:
				if t == 1:
					h = "66b4b3d36098ec5231fcce828a8bf6ad3252fd71"
				elif t == 2:
					h = "66b4b3d36098ec5231fcce828a8bf6ad3252fd7131fcce828a8bf6ad3252fd71"
				sshfp = f"{a} {t} {h}"
				self.assertRaises(Exception, SSHFP.from_string, sshfp)

		# invalid types
		for a in [0,1,2,3,4,6]:
			for t in [-1,3]:
				for h in ["66b4b3d36098ec5231fcce828a8bf6ad3252fd71", "66b4b3d36098ec5231fcce828a8bf6ad3252fd7131fcce828a8bf6ad3252fd71"]:
				
					sshfp = f"{a} {t} {h}"
					self.assertRaises(Exception, SSHFP.from_string, sshfp)

		# invalid hashes
		for a in [0,1,2,3,4,6]:
			for t in [0,1,2]:
				for h in ["asdasd", "66b4b3d36098ec5231fcce828a8bf6ad3252fd71123", "66b4b3d36098ec5231fcce828a8bf6ad3252fd7131fcce828a8bf6ad3252fd71qweq"]:
					sshfp = f"{a} {t} {h}"
					self.assertRaises(Exception, SSHFP.from_string, sshfp)

		self.assertRaises(Exception, SSHFP.from_string, "sshfp")
		self.assertRaises(Exception, SSHFP.from_string, "")



	def test_from_dict(self):
		for a in [0,1,2,3,4,6]:
			for t in [1,2]:
				if t == 1:
					h = "66b4b3d36098ec5231fcce828a8bf6ad3252fd71"
				elif t == 2:
					h = "66b4b3d36098ec5231fcce828a8bf6ad3252fd7131fcce828a8bf6ad3252fd71"
				d = {
					'algo': a,
					'type': t,
					'fingerprint': h
				}
				sshfp_obj = SSHFP.from_dict(d)
				self.assertEqual(sshfp_obj.algo, a)
				self.assertEqual(sshfp_obj.type, t)
				self.assertEqual(sshfp_obj.fingerprint, h)
				self.assertEqual(sshfp_obj.domain, None)
				self.assertEqual(sshfp_obj.timestamp, 0)

				# test optional args
				d = {
					'algo': a,
					'type': t,
					'fingerprint': h,
					'domain': 'foobar.org',
					'timestamp': 1337
				}
				sshfp_obj = SSHFP.from_dict(d)
				self.assertEqual(sshfp_obj.algo, a)
				self.assertEqual(sshfp_obj.type, t)
				self.assertEqual(sshfp_obj.fingerprint, h)
				self.assertEqual(sshfp_obj.domain, 'foobar.org')
				self.assertEqual(sshfp_obj.timestamp, 1337)

		# invalid algos
		for a in [-1,5,7]:
			for t in [1,2]:
				if t == 1:
					h = "66b4b3d36098ec5231fcce828a8bf6ad3252fd71"
				elif t == 2:
					h = "66b4b3d36098ec5231fcce828a8bf6ad3252fd7131fcce828a8bf6ad3252fd71"
				d = {
					'algo': a,
					'type': t,
					'fingerprint': h
				}
				self.assertRaises(Exception, SSHFP.from_dict, d)

		# invalid types
		for a in [0,1,2,3,4,6]:
			for t in [-1,0,3]:
				for h in ["66b4b3d36098ec5231fcce828a8bf6ad3252fd71", "66b4b3d36098ec5231fcce828a8bf6ad3252fd7131fcce828a8bf6ad3252fd71"]:
					d = {
						'algo': a,
						'type': t,
						'fingerprint': h
					}
					self.assertRaises(Exception, SSHFP.from_dict, d)

		# invalid hashes
		for a in [0,1,2,3,4,6]:
			for t in [0,1,2]:
				for h in ["asdasd", "66b4b3d36098ec5231fcce828a8bf6ad3252fd71123", "66b4b3d36098ec5231fcce828a8bf6ad3252fd7131fcce828a8bf6ad3252fd71qweq"]:
					d = {
						'algo': a,
						'type': t,
						'fingerprint': h
					}
					self.assertRaises(Exception, SSHFP.from_dict, d)

		self.assertRaises(Exception, SSHFP.from_dict, {})


	def test_from_json(self):
		for a in [0,1,2,3,4,6]:
			for t in [1,2]:
				if t == 1:
					h = "66b4b3d36098ec5231fcce828a8bf6ad3252fd71"
				elif t == 2:
					h = "66b4b3d36098ec5231fcce828a8bf6ad3252fd7131fcce828a8bf6ad3252fd71"
				d = {
					'algo': a,
					'type': t,
					'fingerprint': h
				}
				j = json.dumps(d)
				sshfp_obj = SSHFP.from_json(j)
				self.assertEqual(sshfp_obj.algo, a)
				self.assertEqual(sshfp_obj.type, t)
				self.assertEqual(sshfp_obj.fingerprint, h)
				self.assertEqual(sshfp_obj.domain, None)
				self.assertEqual(sshfp_obj.timestamp, 0)

				# test optional args
				d = {
					'algo': a,
					'type': t,
					'fingerprint': h,
					'domain': 'foobar.org',
					'timestamp': 1337
				}
				j = json.dumps(d)
				sshfp_obj = SSHFP.from_json(j)
				self.assertEqual(sshfp_obj.algo, a)
				self.assertEqual(sshfp_obj.type, t)
				self.assertEqual(sshfp_obj.fingerprint, h)
				self.assertEqual(sshfp_obj.domain, 'foobar.org')
				self.assertEqual(sshfp_obj.timestamp, 1337)

		# invalid algos
		for a in [-1,5,7]:
			for t in [1,2]:
				if t == 1:
					h = "66b4b3d36098ec5231fcce828a8bf6ad3252fd71"
				elif t == 2:
					h = "66b4b3d36098ec5231fcce828a8bf6ad3252fd7131fcce828a8bf6ad3252fd71"
				d = {
					'algo': a,
					'type': t,
					'fingerprint': h
				}
				j = json.dumps(d)
				self.assertRaises(Exception, SSHFP.from_json, j)

		# invalid types
		for a in [0,1,2,3,4,6]:
			for t in [-1,3]:
				for h in ["66b4b3d36098ec5231fcce828a8bf6ad3252fd71", "66b4b3d36098ec5231fcce828a8bf6ad3252fd7131fcce828a8bf6ad3252fd71"]:
					d = {
						'algo': a,
						'type': t,
						'fingerprint': h
					}
					j = json.dumps(d)
					self.assertRaises(Exception, SSHFP.from_json, j)

		# invalid hashes
		for a in [0,1,2,3,4,6]:
			for t in [0,1,2]:
				for h in ["asdasd", "66b4b3d36098ec5231fcce828a8bf6ad3252fd71123", "66b4b3d36098ec5231fcce828a8bf6ad3252fd7131fcce828a8bf6ad3252fd71qweq"]:
					d = {
						'algo': a,
						'type': t,
						'fingerprint': h
					}
					j = json.dumps(d)
					self.assertRaises(Exception, SSHFP.from_json, j)

		self.assertRaises(Exception, SSHFP.from_json, "")

	def test_to_json(self):
		for a in [0,1,2,3,4,6]:
			for t in [1,2]:
				if t == 1:
					h = "66b4b3d36098ec5231fcce828a8bf6ad3252fd71"
				elif t == 2:
					h = "66b4b3d36098ec5231fcce828a8bf6ad3252fd7131fcce828a8bf6ad3252fd71"
				sshfp = f"{a} {t} {h}"
				sshfp_obj = SSHFP.from_string(sshfp)

				j = json.loads(sshfp_obj.to_json())
				self.assertEqual(j['algo'], SSHFP.algo_to_str(a))
				self.assertEqual(j['type'], SSHFP.type_to_str(t))
				self.assertEqual(j['fingerprint'], h)
				self.assertEqual(j['domain'], None)
				self.assertEqual(j['timestamp'], None)

				sshfp_obj.domain = 'foobar.org'
				sshfp_obj.timestamp = 1337


				j = json.loads(sshfp_obj.to_json())
				self.assertEqual(j['algo'], SSHFP.algo_to_str(a))
				self.assertEqual(j['type'], SSHFP.type_to_str(t))
				self.assertEqual(j['fingerprint'], h)
				self.assertEqual(j['domain'], 'foobar.org')
				self.assertEqual(j['timestamp'], 1337)

	def test_to_dict(self):
		for a in [0,1,2,3,4,6]:
			for t in [1,2]:
				if t == 1:
					h = "66b4b3d36098ec5231fcce828a8bf6ad3252fd71"
				elif t == 2:
					h = "66b4b3d36098ec5231fcce828a8bf6ad3252fd7131fcce828a8bf6ad3252fd71"
				sshfp = f"{a} {t} {h}"
				sshfp_obj = SSHFP.from_string(sshfp)

				d = sshfp_obj.to_dict()
				self.assertEqual(d['algo'], SSHFP.algo_to_str(a))
				self.assertEqual(d['type'], SSHFP.type_to_str(t))
				self.assertEqual(d['fingerprint'], h)
				self.assertEqual(d['domain'], None)
				self.assertEqual(d['timestamp'], None)

				sshfp_obj.domain = 'foobar.org'
				sshfp_obj.timestamp = 1337


				d = sshfp_obj.to_dict()
				self.assertEqual(d['algo'], SSHFP.algo_to_str(a))
				self.assertEqual(d['type'], SSHFP.type_to_str(t))
				self.assertEqual(d['fingerprint'], h)
				self.assertEqual(d['domain'], 'foobar.org')
				self.assertEqual(d['timestamp'], 1337)

	def test_to_dns(self):
		for a in [0,1,2,3,4,6]:
			for t in [1,2]:
				if t == 1:
					h = "66b4b3d36098ec5231fcce828a8bf6ad3252fd71"
				elif t == 2:
					h = "66b4b3d36098ec5231fcce828a8bf6ad3252fd7131fcce828a8bf6ad3252fd71"
				sshfp = f"{a} {t} {h}"
				sshfp_obj = SSHFP.from_string(sshfp)
				sshfp_obj.domain = 'foobar.org'
				sshfp_obj.timestamp = 1337
				dns = sshfp_obj.to_dns()
				self.assertEqual(dns, f"foobar.org IN SSHFP {a} {t} {h}")

	def test_to_algo_and_type_stringified(self):
		for a in [0,1,2,3,4,6]:
			for t in [1,2]:
				if t == 1:
					h = "66b4b3d36098ec5231fcce828a8bf6ad3252fd71"
				elif t == 2:
					h = "66b4b3d36098ec5231fcce828a8bf6ad3252fd7131fcce828a8bf6ad3252fd71"
				sshfp = f"{a} {t} {h}"
				sshfp_obj = SSHFP.from_string(sshfp)

				astr = sshfp_obj.algo_stringified()
				tstr = sshfp_obj.type_stringified()

				if t == 1:
					self.assertEqual(tstr, "SHA1")
				elif t == 2:
					self.assertEqual(tstr, "SHA256")
				else:
					raise Exception(f"Wrong stringified type: {tstr} != {t} ")

				if a == 0:
					self.assertEqual(astr, "RESERVED")
				elif a == 1:
					self.assertEqual(astr, "RSA")
				elif a == 2:
					self.assertEqual(astr, "DSA")
				elif a == 3:
					self.assertEqual(astr, "ECDSA")
				elif a == 4:
					self.assertEqual(astr, "ED25519")
				elif a == 6:
					self.assertEqual(astr, "ED448")
				else:
					raise Exception(f"Wrong stringified algo: {astr} != {a} ")

