"""Develop a command line utility to validate certificate"""
import ssl
import sys
import socket
import OpenSSL
from datetime import datetime
import re

class Certificate:
    """In this class we will validate certificate for the given url"""

    def verify_certificate(self):
        """
        In this method we are verifying certifictae is valid or not
        """
        # verify notAfter/notBefore, CA trusted, servername/sni/hostname
        url = sys.argv[1]
        x = re.search("(\w+\.[\w\.]+)", url)
        domain = x.group()
        cert = Certificate.get_certificate(domain)
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        value = x509.has_expired()
        if value:
            print("certificate is expired")
            exit()
        else:
            Certificate.read_certificate(domain)

    def get_certificate(host, port=443, timeout=10):
        """
        In this method we will fetch certificate from domain.
        :param port:
        :param timeout:
        :return:
        """
        context = ssl.create_default_context()
        conn = socket.create_connection((host, port))
        try:
            sock = context.wrap_socket(conn, server_hostname=host)
        except ssl.SSLError as e:
            print("Certificate is not valid", e)
            exit()
        sock.settimeout(timeout)
        try:
            der_cert = sock.getpeercert(True)
        finally:
            sock.close()
        return ssl.DER_cert_to_PEM_cert(der_cert)

    def read_certificate(url):
        """
        In this method we will read issue date and release date of the certificate.
        :param url:
        :return:
        """
        cert = Certificate.get_certificate(url)
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        issue_date = datetime.strptime(x509.get_notBefore().decode("utf-8"), '%Y%m%d%H%M%SZ')
        expiry = datetime.strptime(x509.get_notAfter().decode("utf-8"), '%Y%m%d%H%M%SZ')
        print("Issue date: ", issue_date)
        print("Expiry date:", expiry)
        days = expiry - issue_date
        print("Number of days to revoke the certifictae is: ", days.days)


if __name__ == '__main__':
    cert_obj = Certificate()
    cert_obj.verify_certificate()


