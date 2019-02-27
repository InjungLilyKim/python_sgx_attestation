from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from report_utils import decode_response

import requests
import cryptography
import OpenSSL

url = 'https://test-as.sgx.trustedservices.intel.com:443/attestation/sgx/v2'
myssl = ('./client.crt', './client.key')

QUOTE = "AgAAAG4NAAAEAAQAAAAAADHBuvEfduuiQ15qcs4wsi+8Zt7gJ+ord2MBMCY2pzbtBAT/BAEBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAJ3fbXHYCcqOjfz/FZ6e0oyAn8CuOz2ye3ZD9uRCL1dwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAX8iaaIJGJf6Wh/zlOxQHOkGcN2P9a0o7KvyqBHr2rigAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqAIAACc06SU1MDjgH3FLjTGK3jdyTFXPmr75wH7mNN7tfD+lAEenr7I5hnH3+pTpqhzo8dxePjUiH+BgLzrn/HUHgGVrtPclMPof1URtjdUnWoX/WDWpjYfksT+oJIEkCSkbac1oJerAYGTOy5MFGM+Hsjg4cojAkWEj6oGYJIs82zXslOSos4e/anHdml0eNemTLkIm6A7JEbvyFv7U7w8QCmTjdVWo9K3vQSwgYeXgqiNNYfjrvdJIAZerMthRA5pRvV9qzVhIDa4dTplY8hRBFJCIbdi6HEi1XcKKKzTTZCzHPkwckirCO1S3ecEh96ydB5f/H9EvTozt3It4g8vZ0/DKfp1ExtDRN1Xh8rry44PpM33E5o5/iCdjbXXb0HjOQHy/hdcWpSI5x8WUeWgBAADBwQcCbv1ZpW2Hb/RhxYXFr/eVYX1dsi6q+8W+/M/I5LfMTMOVyY6CBZeYR6e/uj7ADMESE+ZEyZbuP8mzYY06wEfmrMM86WBflPTZ5ieA6PJxyVX+8Qfj7yqXUoiQNwN5TD5x4Aecxoxwc5tba0JnB/LE9xxO5BSXpIhv0nAqUNrhClAEAZp53XQn5AQNQ4llSvZuMco8TNBXgP7zQxdqJxGMwUysaQBAcei0eFZQ0FrJP10DdUv3s4BwgZQw2wc165Z0JO82yBcbndtpnY8SjfUUeTbOz41tnw357Kx9QLeGQ8g1VFvIFwvUbXkUumng/VPOWBb/U454QXifHfx8TmzRLiWPq3tWUvNYplAVrRotM5fznezaubKSAo2r8mQTcqp2Essx2c7BIVwRYrTbUa8N35gqNeuZ+FsLV/hMKpvlWb7jaHdHSh6GlRdYdCWHvSLk/98vpzOak1fXAL6SBIH5N42Pc5tG8zc1lwL/9671cRuuo8nN"

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
    body = {'isvEnclaveQuote': QUOTE}
    response = requests.post(url + '/report', json=body, cert=myssl)

    if response.status_code == 400:
        exit()
    # data = dump.dump_all(response)
    # print(data.decode('utf-8'))

    report, sig, report_cert, report_ca = decode_response(response)

    if verify_certs(report, sig, report_cert, report_ca):
        print('it is verified from Intel Server')
    else:
        print("it failed to verify")


main()

# this is an explanation of the variables used:
"""
        { 
        Report: *REPORT_JSON*,
        report_cert: *PEM string of the signing certificate*,
        ca_cert: *PEM string of the CA of the signing certificate*,
        sig: Signature of the whole Report made with the report_cert
        }
"""
