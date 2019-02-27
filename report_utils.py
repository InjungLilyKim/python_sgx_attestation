import urllib.parse
import base64
import hashlib
import json
from sgx_structs._sgx_quote import SgxQuote

from cryptography.hazmat.primitives import hashes

def decode_response(res):
    # the report is the body of the response
    report = res.text.encode('utf-8')
    temp = json.loads (res.text)
    isvEnclaveQuoteBody = temp['isvEnclaveQuoteBody']
    data = base64.b64decode(isvEnclaveQuoteBody)
    sgx_quote = SgxQuote()
    sgx_quote.parse_from_bytes(data)
    print(res.text)
    print('')
    print(sgx_quote)
    print('')

    #print(sgx_quote.report_body.report_data.d.hex())
    #print(sgx_quote.report_body.mr_enclave.m.hex())
    #print(sgx_quote.basename.name.hex())

    # Parse the signature from the header
    sig = res.headers['x-iasreport-signature']
    # Decode it from base64
    sig = base64.b64decode(sig)

    # Parse the certs from the header.
    intelcerts = urllib.parse.unquote(
        res.headers['x-iasreport-signing-certificate'])
    # split into a list of 2 chained certificates.
    intelcerts = intelcerts.split('-----END CERTIFICATE-----')

    # The first one is the one that signed the report
    report_cert = intelcerts[0] + '-----END CERTIFICATE-----'

    # The second one is the CA that signed the first certificate, and it's the one on Intel's website.
    report_ca = intelcerts[1] + '-----END CERTIFICATE-----'
    # Remove the "\n" at the start of the sig
    report_ca = report_ca[1:]


    '''
    # new code
    txn_header = transaction.header
    public_key = txn_header.signer_pubilc_key
    originator_public_key_hash = hashlib.sha256(public_key.encode()).hexdigest()    
    hash_input = '{0}{1}'.format(originator_public_key_hash.upper(),
	signup_info.poet_public_key.upper()).encode()
    hash_value = hashlib.sha256(hash_input).digest()
    expected_report_data = hash_value + (b'\x00' * (sgx_structs.SgxReportData.STRUCT_SIZE - len(hash_value)))

    print (sgx_quote.report_body.report_data.d)
    '''
    return report, sig, report_cert, report_ca

