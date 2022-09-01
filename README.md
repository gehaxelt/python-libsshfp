# Python-libsshfp

This is a tiny python library to handle and validate SSHFP DNS records.

It validates SSHFP records against permitted values from RFC 4255, RFC 6594, RFC 7479 and RFC 8709.



# Installation

Use pip to install the package: `pip install libsshfp`.

# Usage

First, find a text-based SSHFP DNS record, i.e. from gnu.org:

```
$> dig SSHFP gnu.org +short
1 1 A2B0FA94793B921FC7A835A313CE8557F8D989E1
```

Then import the library and let it do its magic:
```
>>> from libsshfp import SSHFP
>>> sshfp = SSHFP.from_string("1 1 A2B0FA94793B921FC7A835A313CE8557F8D989E1".lower()) 
>>> sshfp.algo_stringified()
'RSA'
>>> sshfp.type_stringified()
'SHA1'
>>> sshfp.fingerprint
'a2b0fa94793b921fc7a835a313ce8557f8d989e1'

>>> sshfp.to_dict()
{'algo': 'RSA', 'type': 'SHA1', 'fingerprint': 'a2b0fa94793b921fc7a835a313ce8557f8d989e1', 'domain': None, 'timestamp': None}
>>> sshfp.to_json()
'{"algo": "RSA", "type": "SHA1", "fingerprint": "a2b0fa94793b921fc7a835a313ce8557f8d989e1", "domain": null, "timestamp": null}'
```

# TODOS

Contributions are welcome! Feel free to create a merge request :-)

- [ ] Create more documentation
- [ ] Further improve the library (?)