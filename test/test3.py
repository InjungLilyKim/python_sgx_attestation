#!/usr/bin/env python

import requests

# cert and key 
cert = "./tls-cert/prognosticlab-sgx.cert"  
key = "./tls-cert/client.key"  

# intel url
url = "https://test-as.sgx.trustedservices.intel.com/attestation/sgx/v2/report"

# isvEnclaveQuote
f_quote = open("enclave.quote", "r")  
quote = ""
for line in f_quote:
	quote += line
quote = "AgAAAG4NAAAEAAQAAAAAADHBuvEfduuiQ15qcs4wsi+8Zt7gJ+ord2MBMCY2pzbtBAT/BAEBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAJ3fbXHYCcqOjfz/FZ6e0oyAn8CuOz2ye3ZD9uRCL1dwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAX8iaaIJGJf6Wh/zlOxQHOkGcN2P9a0o7KvyqBHr2rigAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqAIAACc06SU1MDjgH3FLjTGK3jdyTFXPmr75wH7mNN7tfD+lAEenr7I5hnH3+pTpqhzo8dxePjUiH+BgLzrn/HUHgGVrtPclMPof1URtjdUnWoX/WDWpjYfksT+oJIEkCSkbac1oJerAYGTOy5MFGM+Hsjg4cojAkWEj6oGYJIs82zXslOSos4e/anHdml0eNemTLkIm6A7JEbvyFv7U7w8QCmTjdVWo9K3vQSwgYeXgqiNNYfjrvdJIAZerMthRA5pRvV9qzVhIDa4dTplY8hRBFJCIbdi6HEi1XcKKKzTTZCzHPkwckirCO1S3ecEh96ydB5f/H9EvTozt3It4g8vZ0/DKfp1ExtDRN1Xh8rry44PpM33E5o5/iCdjbXXb0HjOQHy/hdcWpSI5x8WUeWgBAADBwQcCbv1ZpW2Hb/RhxYXFr/eVYX1dsi6q+8W+/M/I5LfMTMOVyY6CBZeYR6e/uj7ADMESE+ZEyZbuP8mzYY06wEfmrMM86WBflPTZ5ieA6PJxyVX+8Qfj7yqXUoiQNwN5TD5x4Aecxoxwc5tba0JnB/LE9xxO5BSXpIhv0nAqUNrhClAEAZp53XQn5AQNQ4llSvZuMco8TNBXgP7zQxdqJxGMwUysaQBAcei0eFZQ0FrJP10DdUv3s4BwgZQw2wc165Z0JO82yBcbndtpnY8SjfUUeTbOz41tnw357Kx9QLeGQ8g1VFvIFwvUbXkUumng/VPOWBb/U454QXifHfx8TmzRLiWPq3tWUvNYplAVrRotM5fznezaubKSAo2r8mQTcqp2Essx2c7BIVwRYrTbUa8N35gqNeuZ+FsLV/hMKpvlWb7jaHdHSh6GlRdYdCWHvSLk/98vpzOak1fXAL6SBIH5N42Pc5tG8zc1lwL/9671cRuuo8nN"
#print(quote)
f_quote.close()  

# send request to Intel server
headers = {"content-type": "application/json"}
data = {"isvEnclaveQuote": quote}
response = requests.post(url, data=data, headers=headers, cert=(cert, key))

print response.status_code, response.reason
