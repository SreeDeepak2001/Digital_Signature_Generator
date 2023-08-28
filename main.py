import subprocess
from datetime import datetime, timedelta
import OpenSSL.crypto as crypto
import os
from cryptography.hazmat.primitives import hashes, serialization
from keeper_secrets_manager_core.utils import generate_password
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import pandas as pd

class DigitalSignGenerator:
    def __init__(self):
        self.user = input('Enter User Name: ')
        with open('flatironssolutions-com.key', 'rb') as f:
            self.private_key_pem = f.read()
        with open('flatironssolutions-com.crt', 'rb') as f:
            self.certificate_pem = f.read()
        self.email = self.getmail(self.user)
        if self.email is not None:
            self.username = self.getusername(self.user)
            if not os.path.exists(self.user):
                os.makedirs(self.user)
            self.password = self.genPassword()
            self.genkey()
            self.genCSR()
            self.genCRT()
            self.createpfxsh()
            print(f"Certificate File Created for {self.user} ")
            subprocess.call(['sh', f'{self.user}/GenPfx_{self.username}.sh'])
            print(f'Digital Signature Created for {self}')
        else:
            print(f'{self.user} is not an Employee.')

    def genkey(self):
        self.pkey = crypto.PKey()
        self.pkey.generate_key(crypto.TYPE_RSA, 2048)
        with open(f'{self.user}/{self.username}private.key', 'wb') as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, self.pkey))
        with open(f'{self.user}/{self.username}public.key', 'wb') as f:
            f.write(crypto.dump_publickey(crypto.FILETYPE_PEM, self.pkey))

    def genCSR(self):
        with open(f'{self.user}/{self.username}public.key', 'rb') as f:
            pubkey = f.read()
        self.csr = crypto.X509Req()
        self.csr.get_subject().C = 'IN'
        self.csr.get_subject().ST = 'TamilNadu'
        self.csr.get_subject().L = 'Chennai'
        self.csr.get_subject().O = 'Flatirons Solutions'
        self.csr.get_subject().CN = self.user
        self.csr.get_subject().emailAddress = self.email
        self.csr.set_pubkey(crypto.load_publickey(crypto.FILETYPE_PEM, pubkey))
        digest = 'sha256'
        self.csr.sign(self.pkey, digest)
        self.csr.verify(pkey=self.pkey)
        self.csr_pem = crypto.dump_certificate_request(crypto.FILETYPE_PEM, self.csr)
        with open(f'{self.user}/{self.username}.csr', 'wb') as f:
            f.write(self.csr_pem)

    def genCRT(self):
        with open(f'{self.user}/{self.username}.csr', 'rb') as f:
            csr = x509.load_pem_x509_csr(f.read())
        with open('flatironssolutions-com.crt', 'rb') as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        with open('flatironssolutions-com.key', 'rb') as f:
            ca_key = load_pem_private_key(f.read(), password=None)
        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(csr.subject)
        cert_builder = cert_builder.not_valid_before(datetime.utcnow())
        cert_builder = cert_builder.not_valid_after(datetime.utcnow() + timedelta(days=365))
        cert_builder = cert_builder.serial_number(x509.random_serial_number())
        cert_builder = cert_builder.public_key(csr.public_key())
        cert_builder = cert_builder.issuer_name(ca_cert.subject)
        if csr.extensions:
            for extension in csr.extensions:
                cert_builder = cert_builder.add_extension(extension.value, extension.critical)
        cert = cert_builder.sign(private_key=ca_key, algorithm=hashes.SHA256(),
                                 backend=default_backend())
        with open(f'{self.user}/{self.username}.crt', 'wb') as f:
            f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))

    def createpfx(self):
        with open(f'{self.user}/{self.username}private.key', 'rb') as f:
            pkey = f.read()
        with open(f'{self.user}/{self.username}.crt', 'rb') as f:
            cert = f.read()
        private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, pkey)
        certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, self.certificate_pem)
        pfx = crypto.PKCS12()
        pfx.set_privatekey(private_key)
        pfx.set_ca_certificates([ca_cert])
        pfx.set_certificate(certificate)
        password = 'password'.encode("utf-8")
        pfx_data = pfx.export(password)
        with open(f'{self.user}/{self.username}.pfx', 'wb') as f:
            f.write(pfx_data)

    def createpfxsh(self):
        cmd = f'openssl pkcs12 -export -out {self.username}.pfx -inkey {self.username}private.key -in {self.username}.crt -passout pass:{self.password}'
        with open(f'{self.user}/GenPfx_{self.username}.sh','w') as f:
            f.write(cmd)

    @staticmethod
    def getmail(user):
        data = pd.read_csv("export-users (2).csv")
        if user in data['User name'].tolist():
            index = data[data['User name'] == user].index
            emails = data["email"].tolist()
            return emails[index[0]]
        else:
            return None

    @staticmethod
    def getusername(user):
        temp = user.replace('.', '').split(" ")
        count = 0
        uname = ""
        n = len(temp)
        for name in temp:
            if count != n - 1:
                uname = uname + name[0]
            else:
                uname = uname+name
            count = count + 1
        return uname.lower()

    def genPassword(self):
        password = generate_password(length=10, special_characters=0)
        with open(f'{self.user}/{self.username}_Password.txt', 'w') as f:
            f.write(password)
        return password

if __name__ == "__main__":
    while True:
        obj = DigitalSignGenerator()
