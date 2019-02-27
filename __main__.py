from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from report_utils import decode_response

import requests
import cryptography
import OpenSSL

url = 'https://test-as.sgx.trustedservices.intel.com:443/attestation/sgx/v2'
myssl = ('./tls-cert/client.crt', './tls-cert/client.key')

QUOTE = "AgAAAG4NAAAHAAYAAAAAADHBuvEfduuiQ15qcs4wsi9tJUqUyr53Oo0gUUaQXHw6BAT/BAEBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAANaF4Imlw5pbhR3tZqBNOkE65hfDFS4wo7LiucWjybgNAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/+tZG69a3tBRVOwZmdsPPgNsrq6FHIzXiEU+y/2h0/QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABiVrjn9aV61tyhlvEQ8jFSE3FNMtDetMcX1mFxPJqKTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqAIAABK03n39ZJkbqhENjWKXTWDxyLDP/XoFOZDsrMgq8pV/piy0LyOGPkX9Au1D6Ll4U+hEMF/5FcN2R1cjD3ZtzlF5yEKFxtj8JYcOLomvgI934iLAgJWAIWyisKq6pOr+6QbECfyyRJcd7jZ9UYay4Kt9tD2cn2r/BJenyMRqLReFv9wFlkdMKBjWrFVno9BqgOX1K+kE0WCzgo1hBCDwh+KXVUlbCVo83MSw9Jh2erNsxgw6+F+SM7TgWpAlQ6iCdPGnZobnzgHAvaxBen1MSmMvKixlaBmtB+UswJaTA0PfkPQobHJzecKdQkOpC0ZLEGOxzc3bEELP8L5EnhyjagwY5bwr2cjJxyRGGypHN56BqfVaNicGF5TlfcqiFtnDzgHkBNY5eKaF8kqR+mgBAABfQ05OuJEhurhQTay0cdYIJurbmxtBg9RsDm6Sno+Za0yn3x/NsyCn7q8+3QEMc1W2lYc72KiDkoEOEBepXU31ecCYZYaOYzautNGzVyI/qd8Zm35XZkLJ+pXlLiPBFBkUxNWHtu0CY7JCMXhOlEiMD893lGk8a0eKLkq1dyplWxnMXQPbB9+Gyul79cAg+8QTL+b5L6PUzM7NcIqIrj11EkL//exYCUK/4lJv9y0tBhKw3iZoFM5anIVVEwz5baRl6jLr3IQ9K5wfreo6gbj3T83dfVxHL+o7rblh9XsB3cu7hCJlEH/IjaZlBj1yOUtKBNqRbe1aAGBAweVyMhFaYg9cbDSkKyQwAqDySlYzUCJ3VMyrAu7NK+qo6hF0nLuKPNS13Ax6L4L52ekhQgkWQYYtz05YA2mDcMANxzh37tTeiuuodvX9jfjVVN1nsC6djHsJsmtng1ldMyeZJ2JCnVJMu+ChO35xPd3hl4oMtOmxZs1B0azk"

def verify_certs(report, sig, report_cert, report_ca):
    # Load the report_cert into a x509 object
    x509cert = x509.load_pem_x509_certificate(report_cert.encode('ascii'), default_backend())

    # Verify that the signature is correct on the report and is really signed by this x509
    try:
        x509cert.public_key().verify(
            sig,
            report,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    except cryptography.exceptions.InvalidSignature:
        return False

    # Loaded the report_cert into a different crypto library
    x509cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, report_cert.encode('ascii'))

    # Verify that it works here too.
    try:
        OpenSSL.crypto.verify(x509cert, sig, report, 'sha256')

    except OpenSSL.crypto.Error:
        return False

    # Load the publicly known cert from intel and remove the "\n" at the end
    with open("./AttestationReportSigningCACert.pem", "r") as myfile:
        ca_file = ''.join(myfile.readlines())[:-1]

    if ca_file != report_ca:
        return False

    return True

def main():
    # Send the request to verify the quote to the Intel Server
    body = {'isvEnclaveQuote': QUOTE}
    response = requests.post(url + '/report', json=body, cert=myssl)

    #print(response.text)
    #j = json.loads(response.text)
    #responseBody = j['isvEnclaveQuoteBody']
    #print(responseBody)
    #print(response.headers)

    if response.status_code == 400:
        exit()
    # data = dump.dump_all(response)
    # print(data.decode('utf-8'))

    # Decode the response from the Intel Server
    report, sig, report_cert, report_ca = decode_response(response)

    #print(report)

    #print('body of respose: ', report);
    #print(sig);

    """
        Report: *REPORT_JSON*,
        sig: Signature of the whole Report made with the report_cert
        report_cert: *PEM string of the signing certificate*,
        ca_cert: *PEM string of the CA of the signing certificate*,
    """
    if verify_certs(report, sig, report_cert, report_ca):
        print('The quote is verified from Intel Server')
    else:
        print("The quote is failed to verify")

if __name__ == "__main__":
	main()

