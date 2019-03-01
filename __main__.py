import requests
import OpenSSL
import hashlib
import json 

from report_utils import decode_response
from sgx_structs._sgx_report_data import SgxReportData 
from sgx_structs._sgx_quote import SgxQuote

url = 'https://test-as.sgx.trustedservices.intel.com:443/attestation/sgx/v2'
myssl = ('./tls-cert/client.crt', './tls-cert/client.key')

enclave_uuid = "10b1e279-0d6f-40a9-ae7f-b04d9ab58f3a"
user_uuid = "90eb5736-42f8-45e7-a736-01f430453311"

user_pub_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyfz21VoHTyk/r4B1lE3G
4lU9wCbFQ9HTGJhe0FxNS3JMkkvm82wcNMvPzaQrAcqafvt47UMfERUgvaSNm0Mk
4ZIQOi2850nJvWAvp2Z0HHR+ESjgTqqkD5luOvNJS8EBLgtVC3Rh/Wc0fVWJG4nk
J6cnS2OM52d3baniJB4cIDAN5IUlaDlSevOo7ZL8Fjo9UykUGVf9iF4lZj7jTGHP
pu3fjJAG+fAWzG9F5HxCGc8QJaIjAM3kdIiDfbvCS/H+d8tX0TWpba78soXXBa1w
Cpz7vEw6MEyMljRa7AYl0vFBwmaZ3syxuHWgIETnLnyXkJx6IIvd2Pfqp4MAZKR6
UwIDAQAB
-----END PUBLIC KEY-----"""

enclave_pub_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtOHM3I3J3XjjlclhiKn3
fAFeBwaGx39zh4rRnAxxKA1J8FB6qCfqTN5yhwAGznAtIjXSz+7iTPWU/lJb3/de
AayqxtG8kO/stzXE3WkGldMXTkawg5AeI4VjAUJ9Swh7JgZQC0zyx98Xvx2IGd84
F43P17skbnv3veoCdq1BPcOFem0e0NDN3ql+ZVdhdfqRA7xVEuY74WcTNeYhPV30
QPl/4Nwmu4G/3T7N/vzzPIEkP/whqSpB79WzumK7MtNlnvLI7ZIZx6aatJpPLgsR
tAUvcjMRqJAtygvdIdoiLKNYcEVhQ6Twd8MhIU3Nw7C0uCFh2tPV5uAWhPPEdqBW
HQIDAQAB
-----END PUBLIC KEY-----"""

sharing_pub_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnlSOMSj1oq3LFdEe7rIj
Pej5ym1OIJuIHc+cns1azhFpIFknxjna+eY4JlSeHORg7hsoFLnNE4SR1oZP0PYN
zL/FyXhbVHqgK2QZSISLwBS3pKrexRKQhwe9zqROF5nBpdUuea2S8nv2EnbhwS63
60qL14oJDprUQZ0MsG6TFE3cP9IDdwvtGSFb98BWwZerfWh78T121rh2jPzOqn2Q
B1yPoExQUI53KR+GDC5OH4C8cT9SBSIJI+A0s/kcIldb2k9LglktOmt5Tq9GO4ie
fBxY+BlZsigCSR/FC+glWXjvji+h+H+zo5sHpC/ls4yuR2oGVXZokCkusiPtDMBj
bQIDAQAB
-----END PUBLIC KEY-----"""

QUOTE = "AgAAAG4NAAAHAAYAAAAAADHBuvEfduuiQ15qcs4wsi9tJUqUyr53Oo0gUUaQXHw6BAT/BAEBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAANaF4Imlw5pbhR3tZqBNOkE65hfDFS4wo7LiucWjybgNAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/+tZG69a3tBRVOwZmdsPPgNsrq6FHIzXiEU+y/2h0/QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABiVrjn9aV61tyhlvEQ8jFSE3FNMtDetMcX1mFxPJqKTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqAIAABK03n39ZJkbqhENjWKXTWDxyLDP/XoFOZDsrMgq8pV/piy0LyOGPkX9Au1D6Ll4U+hEMF/5FcN2R1cjD3ZtzlF5yEKFxtj8JYcOLomvgI934iLAgJWAIWyisKq6pOr+6QbECfyyRJcd7jZ9UYay4Kt9tD2cn2r/BJenyMRqLReFv9wFlkdMKBjWrFVno9BqgOX1K+kE0WCzgo1hBCDwh+KXVUlbCVo83MSw9Jh2erNsxgw6+F+SM7TgWpAlQ6iCdPGnZobnzgHAvaxBen1MSmMvKixlaBmtB+UswJaTA0PfkPQobHJzecKdQkOpC0ZLEGOxzc3bEELP8L5EnhyjagwY5bwr2cjJxyRGGypHN56BqfVaNicGF5TlfcqiFtnDzgHkBNY5eKaF8kqR+mgBAABfQ05OuJEhurhQTay0cdYIJurbmxtBg9RsDm6Sno+Za0yn3x/NsyCn7q8+3QEMc1W2lYc72KiDkoEOEBepXU31ecCYZYaOYzautNGzVyI/qd8Zm35XZkLJ+pXlLiPBFBkUxNWHtu0CY7JCMXhOlEiMD893lGk8a0eKLkq1dyplWxnMXQPbB9+Gyul79cAg+8QTL+b5L6PUzM7NcIqIrj11EkL//exYCUK/4lJv9y0tBhKw3iZoFM5anIVVEwz5baRl6jLr3IQ9K5wfreo6gbj3T83dfVxHL+o7rblh9XsB3cu7hCJlEH/IjaZlBj1yOUtKBNqRbe1aAGBAweVyMhFaYg9cbDSkKyQwAqDySlYzUCJ3VMyrAu7NK+qo6hF0nLuKPNS13Ax6L4L52ekhQgkWQYYtz05YA2mDcMANxzh37tTeiuuodvX9jfjVVN1nsC6djHsJsmtng1ldMyeZJ2JCnVJMu+ChO35xPd3hl4oMtOmxZs1B0azk"

# verify_quote will verify the repoart data
def verify_quote(sgx_quote):

    # Hash user data 
    #hash_input = '{0}{1}{2}{3}{4}'.format(enclave_uuid, enclave_pub_key, user_pub_key, user_uuid, sharing_pub_key).encode()
    hash_input = '{0}{1}{2}{3}{4}'.format(enclave_uuid, enclave_pub_key, user_pub_key, user_uuid, sharing_pub_key).encode('utf8')
    hash_value = hashlib.sha256(hash_input).digest()
    expected_report_data = hash_value + (b'\x00' * (SgxReportData.STRUCT_SIZE - len(hash_value)))

    print(sgx_quote)
    print("")
    print(sgx_quote.report_body.report_data.d.hex())
    print("")
    print(expected_report_data.hex())
    print("")

    # compare report data
    if sgx_quote.report_body.report_data.d != expected_report_data:
        return False

    return True

def main():
    # Send the request to verify the quote to the Intel Server
    body = {'isvEnclaveQuote': QUOTE}
    response = requests.post(url + '/report', json=body, cert=myssl)

    if response.status_code == 400:
        exit()

    # Decode the response from the Intel Server
    report, sig, report_cert, report_ca, sgx_quote = decode_response(response)

    if verify_quote(sgx_quote):
        print('The quote is verified')
    else:
        print("The quote is failed to verify")

if __name__ == "__main__":
	main()

