import socket
from datetime import datetime

from OpenSSL import SSL
import certifi


# def get_pem_certificate(host, port=443, timeout=5):
#     context = ssl.create_default_context()
#     connection = socket.create_connection((host, port))
#     sock = context.wrap_socket(connection, server_hostname=host)
#     sock.settimeout(timeout)
#
#     try:
#         der_cert = sock.getpeercert(True)
#     except Exception as e:
#         print(e)
#         return False
#     finally:
#         sock.close()
#
#     return ssl.DER_cert_to_PEM_cert(der_cert)


def get_chain_from_certificate(hostname, port=443):
    context = SSL.Context(method=SSL.TLSv1_2_METHOD)
    # /etc/pki/tls/certs/ca-bundle.trust.crt --> Fedora Linux (in my case)
    context.load_verify_locations(cafile=certifi.where())

    conn = SSL.Connection(context, socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    conn.settimeout(4)
    conn.connect((hostname, port))
    conn.setblocking(1)
    conn.do_handshake()
    conn.set_tlsext_host_name(hostname.encode())
    list_of_certificate_info = []

    for (idx, cert) in enumerate(conn.get_peer_cert_chain()):
        certificate_info = {
            'subject': cert.get_subject().O,
            'issuer': cert.get_issuer().CN,
            'serialNumber': cert.get_serial_number(),
            'version': cert.get_version(),
            'notBefore': datetime.strptime(cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ'),
            'notAfter': datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ'),
            'signature': cert.get_signature_algorithm(),
            'hasExpired': cert.has_expired()
        }

        list_of_certificate_info.append(certificate_info)

    conn.close()

    return list_of_certificate_info


if __name__ == '__main__':
    chain_certificate = get_chain_from_certificate('e-food.gr')
    entity_certificate = chain_certificate[0]

    last = chain_certificate[-1]

    trusted_ca = last.get('issuer')

    os_root_trusted_ca = open('/etc/pki/tls/certs/ca-bundle.trust.crt', 'rt').read()

    print("Certificate chain: {}".format(chain_certificate))
    if os_root_trusted_ca.find(trusted_ca) != -1:
        print("Root CA: {}".format(trusted_ca))
        print("Entity Certificate: {}".format(entity_certificate.get('issuer')))
        print("Certificate started being valid on: {}".format(entity_certificate.get('notBefore')))
        print("Certificate stops being valid on: {}".format(entity_certificate.get('notAfter')))
        print("Certificate is expired: {}".format(entity_certificate.get('hasExpired')))
        print('Certificate is valid.')
    else:
        print('Certificate does not exist in Trusted CA')
        print('Certificate is invalid')

    # sudo
    # awk - v
    # cmd = 'openssl x509 -noout -subject' '
    # / BEGIN / {close(cmd)};
    # {print | cmd}
    # ' < /etc/pki/tls/certs/ca-bundle.trust.crt

