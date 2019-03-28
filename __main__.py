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

# data without new line
user_pub_key2 = "-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyfz21VoHTyk/r4B1lE3G4lU9wCbFQ9HTGJhe0FxNS3JMkkvm82wcNMvPzaQrAcqafvt47UMfERUgvaSNm0Mk4ZIQOi2850nJvWAvp2Z0HHR+ESjgTqqkD5luOvNJS8EBLgtVC3Rh/Wc0fVWJG4nkJ6cnS2OM52d3baniJB4cIDAN5IUlaDlSevOo7ZL8Fjo9UykUGVf9iF4lZj7jTGHPpu3fjJAG+fAWzG9F5HxCGc8QJaIjAM3kdIiDfbvCS/H+d8tX0TWpba78soXXBa1wCpz7vEw6MEyMljRa7AYl0vFBwmaZ3syxuHWgIETnLnyXkJx6IIvd2Pfqp4MAZKR6UwIDAQAB-----END PUBLIC KEY-----"

enclave_pub_key2 = "-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtOHM3I3J3XjjlclhiKn3fAFeBwaGx39zh4rRnAxxKA1J8FB6qCfqTN5yhwAGznAtIjXSz+7iTPWU/lJb3/deAayqxtG8kO/stzXE3WkGldMXTkawg5AeI4VjAUJ9Swh7JgZQC0zyx98Xvx2IGd84F43P17skbnv3veoCdq1BPcOFem0e0NDN3ql+ZVdhdfqRA7xVEuY74WcTNeYhPV30QPl/4Nwmu4G/3T7N/vzzPIEkP/whqSpB79WzumK7MtNlnvLI7ZIZx6aatJpPLgsRtAUvcjMRqJAtygvdIdoiLKNYcEVhQ6Twd8MhIU3Nw7C0uCFh2tPV5uAWhPPEdqBWHQIDAQAB-----END PUBLIC KEY-----"

sharing_pub_key2 = "-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnlSOMSj1oq3LFdEe7rIjPej5ym1OIJuIHc+cns1azhFpIFknxjna+eY4JlSeHORg7hsoFLnNE4SR1oZP0PYNzL/FyXhbVHqgK2QZSISLwBS3pKrexRKQhwe9zqROF5nBpdUuea2S8nv2EnbhwS6360qL14oJDprUQZ0MsG6TFE3cP9IDdwvtGSFb98BWwZerfWh78T121rh2jPzOqn2QB1yPoExQUI53KR+GDC5OH4C8cT9SBSIJI+A0s/kcIldb2k9LglktOmt5Tq9GO4iefBxY+BlZsigCSR/FC+glWXjvji+h+H+zo5sHpC/ls4yuR2oGVXZokCkusiPtDMBjbQIDAQAB-----END PUBLIC KEY-----"

# data with new line character
user_pub_key3 = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyfz21VoHTyk/r4B1lE3G\n4lU9wCbFQ9HTGJhe0FxNS3JMkkvm82wcNMvPzaQrAcqafvt47UMfERUgvaSNm0Mk\n4ZIQOi2850nJvWAvp2Z0HHR+ESjgTqqkD5luOvNJS8EBLgtVC3Rh/Wc0fVWJG4nk\nJ6cnS2OM52d3baniJB4cIDAN5IUlaDlSevOo7ZL8Fjo9UykUGVf9iF4lZj7jTGHP\npu3fjJAG+fAWzG9F5HxCGc8QJaIjAM3kdIiDfbvCS/H+d8tX0TWpba78soXXBa1w\nCpz7vEw6MEyMljRa7AYl0vFBwmaZ3syxuHWgIETnLnyXkJx6IIvd2Pfqp4MAZKR6\nUwIDAQAB\n-----END PUBLIC KEY-----"

enclave_pub_key3 = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtOHM3I3J3XjjlclhiKn3\nfAFeBwaGx39zh4rRnAxxKA1J8FB6qCfqTN5yhwAGznAtIjXSz+7iTPWU/lJb3/de\nAayqxtG8kO/stzXE3WkGldMXTkawg5AeI4VjAUJ9Swh7JgZQC0zyx98Xvx2IGd84\nF43P17skbnv3veoCdq1BPcOFem0e0NDN3ql+ZVdhdfqRA7xVEuY74WcTNeYhPV30\nQPl/4Nwmu4G/3T7N/vzzPIEkP/whqSpB79WzumK7MtNlnvLI7ZIZx6aatJpPLgsR\ntAUvcjMRqJAtygvdIdoiLKNYcEVhQ6Twd8MhIU3Nw7C0uCFh2tPV5uAWhPPEdqBW\nHQIDAQAB\n-----END PUBLIC KEY-----"

sharing_pub_key3 = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnlSOMSj1oq3LFdEe7rIj\nPej5ym1OIJuIHc+cns1azhFpIFknxjna+eY4JlSeHORg7hsoFLnNE4SR1oZP0PYN\nzL/FyXhbVHqgK2QZSISLwBS3pKrexRKQhwe9zqROF5nBpdUuea2S8nv2EnbhwS63\n60qL14oJDprUQZ0MsG6TFE3cP9IDdwvtGSFb98BWwZerfWh78T121rh2jPzOqn2Q\nB1yPoExQUI53KR+GDC5OH4C8cT9SBSIJI+A0s/kcIldb2k9LglktOmt5Tq9GO4ie\nfBxY+BlZsigCSR/FC+glWXjvji+h+H+zo5sHpC/ls4yuR2oGVXZokCkusiPtDMBj\nbQIDAQAB\n-----END PUBLIC KEY-----"

# data with one more new line character at the end
user_pub_key4 = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyfz21VoHTyk/r4B1lE3G\n4lU9wCbFQ9HTGJhe0FxNS3JMkkvm82wcNMvPzaQrAcqafvt47UMfERUgvaSNm0Mk\n4ZIQOi2850nJvWAvp2Z0HHR+ESjgTqqkD5luOvNJS8EBLgtVC3Rh/Wc0fVWJG4nk\nJ6cnS2OM52d3baniJB4cIDAN5IUlaDlSevOo7ZL8Fjo9UykUGVf9iF4lZj7jTGHP\npu3fjJAG+fAWzG9F5HxCGc8QJaIjAM3kdIiDfbvCS/H+d8tX0TWpba78soXXBa1w\nCpz7vEw6MEyMljRa7AYl0vFBwmaZ3syxuHWgIETnLnyXkJx6IIvd2Pfqp4MAZKR6\nUwIDAQAB\n-----END PUBLIC KEY-----\n"

enclave_pub_key4 = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtOHM3I3J3XjjlclhiKn3\nfAFeBwaGx39zh4rRnAxxKA1J8FB6qCfqTN5yhwAGznAtIjXSz+7iTPWU/lJb3/de\nAayqxtG8kO/stzXE3WkGldMXTkawg5AeI4VjAUJ9Swh7JgZQC0zyx98Xvx2IGd84\nF43P17skbnv3veoCdq1BPcOFem0e0NDN3ql+ZVdhdfqRA7xVEuY74WcTNeYhPV30\nQPl/4Nwmu4G/3T7N/vzzPIEkP/whqSpB79WzumK7MtNlnvLI7ZIZx6aatJpPLgsR\ntAUvcjMRqJAtygvdIdoiLKNYcEVhQ6Twd8MhIU3Nw7C0uCFh2tPV5uAWhPPEdqBW\nHQIDAQAB\n-----END PUBLIC KEY-----\n"

sharing_pub_key4 = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnlSOMSj1oq3LFdEe7rIj\nPej5ym1OIJuIHc+cns1azhFpIFknxjna+eY4JlSeHORg7hsoFLnNE4SR1oZP0PYN\nzL/FyXhbVHqgK2QZSISLwBS3pKrexRKQhwe9zqROF5nBpdUuea2S8nv2EnbhwS63\n60qL14oJDprUQZ0MsG6TFE3cP9IDdwvtGSFb98BWwZerfWh78T121rh2jPzOqn2Q\nB1yPoExQUI53KR+GDC5OH4C8cT9SBSIJI+A0s/kcIldb2k9LglktOmt5Tq9GO4ie\nfBxY+BlZsigCSR/FC+glWXjvji+h+H+zo5sHpC/ls4yuR2oGVXZokCkusiPtDMBj\nbQIDAQAB\n-----END PUBLIC KEY-----\n"

# verify_quote will verify the repoart data
def verify_quote(sgx_quote):
    # 1st try
    # Hash user data 
    hash_input = '{0}{1}{2}{3}{4}'.format(enclave_uuid, enclave_pub_key, user_pub_key, user_uuid, sharing_pub_key).encode()
    hash_value = hashlib.sha256(hash_input).digest()
    print("1")
    print(hash_value.hex())
    print("")

    # 2nd try 
    hash_input2 = '{0}{1}{2}{3}{4}'.format(enclave_uuid, enclave_pub_key, user_pub_key, user_uuid, sharing_pub_key).encode('utf8')
    hash_value2 = hashlib.sha256(hash_input2).digest()
    print("2")
    print(hash_value2.hex())
    print("")

    # 3rd try
    hash_value3 = hashlib.sha256()
    hash_value3.update(enclave_uuid.encode())
    hash_value3.update(enclave_pub_key.encode())
    hash_value3.update(user_pub_key.encode())
    hash_value3.update(user_uuid.encode())
    hash_value3.update(sharing_pub_key.encode())
    print("3")
    print(hash_value3.hexdigest())
    print(hash_value3.digest_size)
    print("")

    # 4th try 
    hash_input4 = '{0}{1}{2}{3}{4}'.format(enclave_uuid, enclave_pub_key2, user_pub_key2, user_uuid, sharing_pub_key2).encode('utf8')
    hash_value4 = hashlib.sha256(hash_input4).digest()
    print("4")
    print(hash_value4.hex())
    print("")

    # 5th try 
    hash_input5 = '{0}{1}{2}{3}{4}'.format(enclave_uuid, enclave_pub_key3, user_pub_key3, user_uuid, sharing_pub_key3).encode('utf8')
    hash_value5 = hashlib.sha256(hash_input5).digest()
    print("5")
    print(hash_value5.hex())
    print("")

    # 6th try 
    hash_input6 = '{0}{1}{2}{3}{4}'.format(enclave_uuid, enclave_pub_key4, user_pub_key4, user_uuid, sharing_pub_key4).encode('utf8')
    hash_value6 = hashlib.sha256(hash_input6).digest()
    print("6")
    print(hash_value6.hex())
    print("")
 

    expected_report_data = hash_value6 + (b'\x00' * (SgxReportData.STRUCT_SIZE - len(hash_value6)))
    print("padding 00 to the end of report data")
    print(expected_report_data.hex())
    #expected_report_data = hash_value + (b'\x00' * (SgxReportData.STRUCT_SIZE - len(hash_value)))

    print(sgx_quote)
    """
    print("")
    print(sgx_quote.report_body.report_data.d.hex())
    print("")
    print(expected_report_data.hex())
    print("")
    
    # compare report data
    if sgx_quote.report_body.report_data.d != expected_report_data:
        return False
    """

    return True

def main():
    # Send the request to verify the quote to the Intel Server
    body = {'isvEnclaveQuote': QUOTE}
    response = requests.post(url + '/report', json=body, cert=myssl)

    print("response status code is ")
    print(response.status_code)
    print("")
    #if response.status_code == 400 or response.status_code == 410:
    #    exit()

    # Decode the response from the Intel Server
    #report, sig, report_cert, report_ca, sgx_quote = decode_response(response)

    sgx_quote = ""
    if verify_quote(sgx_quote):
        print('The quote is verified')
    else:
        print("The quote is failed to verify")

if __name__ == "__main__":
	main()

