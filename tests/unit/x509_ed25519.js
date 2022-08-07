var ASSERT = require('assert');
var ED25519 = require('../../lib/ed25519');
var PKI = require('../../lib/pki');

const _PRIVATE_KEY_VALUE = [
    0xf1, 0xe2, 0xdd, 0xf2, 0x0d, 0xb5, 0x1a, 0x47, 0x97, 0xba, 0x53, 0x06, 0x0e, 0x00, 0x9f, 0xbf, 
    0x75, 0x95, 0x73, 0x68, 0xdd, 0x0a, 0x33, 0x3c, 0x38, 0x82, 0x0a, 0x8c, 0xa4, 0x38, 0xea, 0x14]
const _PRIVATE_KEY_PEM = `
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPHi3fINtRpHl7pTBg4An791lXNo3QozPDiCCoykOOoU
-----END PRIVATE KEY-----
`
const _PRIVATE_KEY_ENCRYPTED_PASSWORD = 'DUMMY_PASSWORD'
const _PRIVATE_KEY_ENCRYPTED = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIGbMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAilknqfXkNebAICCAAw
DAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEENAOqBTnIW/nyzxwCRHVfaYEQHKW
Uw6lpK791dK4BdCKTNW5vVf9SsK/tV84jLQe3trMOOlfhOVlNOgsN3Lc9lv8KXAl
gp2tpy5jUiz2oMXizoc=
-----END ENCRYPTED PRIVATE KEY-----
`
const _CERTIFICATE_PEM = `
-----BEGIN CERTIFICATE-----
MIIBLTCB4KADAgECAgAwBQYDK2VwMBAxDjAMBgNVBAMTBURVTU1ZMB4XDTIyMDgw
MTAwMDAwMFoXDTQyMDgwMTAwMDAwMFowEDEOMAwGA1UEAxMFRFVNTVkwKjAFBgMr
ZXADIQDO6SXZ72UTttgHeNzE2MSW+EAv6ursB4R3rChL/R8TEqNgMF4wDwYDVR0T
AQH/BAUwAwEB/zALBgNVHQ8EBAMCAuQwHQYDVR0OBBYEFO8YyyjCtKlhAGcnChmz
iEexqF1SMB8GA1UdIwQYMBaAFO8YyyjCtKlhAGcnChmziEexqF1SMAUGAytlcANB
ABk1of0UwIHJ5CpK1FlHX1QOo+LpL7Hvpc8oSqUJoFov/DKFWgrPnLCeSuFT2ul6
Y3GkSavo4YOzluCZgG6fHAE=
-----END CERTIFICATE-----`
const _CERTIFICATION_REQUEST_PEM = `
-----BEGIN CERTIFICATE REQUEST-----
MIGPMEMCAQAwEDEOMAwGA1UEAxMFRFVNTVkwKjAFBgMrZXADIQDO6SXZ72UTttgH
eNzE2MSW+EAv6ursB4R3rChL/R8TEqAAMAUGAytlcANBAB9zQRVRFEmDYHlP28VT
+zTu3Pdgnu63dwJ5ApdbZ6CBfSnEtzZd9tkztTizuIkdvvqaAHnTB2Z8uMD2Nwjd
3gA=
-----END CERTIFICATE REQUEST-----`

describe('ed25519_encryptedpem', function() {

    it('should generate new ed25519 encrypted private key and read it back (round-trip)', function() {
        const { privateKey } = ED25519.generateKeyPair({seed: Buffer.from(_PRIVATE_KEY_VALUE)});
        
        // Encrypt key to pem
        const asn1Key = ED25519.privateKeyToAsn1(privateKey);
        const encryptedPrivateKeyInfo = PKI.encryptPrivateKeyInfo(
          asn1Key, 
          _PRIVATE_KEY_ENCRYPTED_PASSWORD,
          { algorithm: 'aes256' }
        );
        const pem = PKI.encryptedPrivateKeyToPem(encryptedPrivateKeyInfo);

        // Test - decrypt key
        const wrappedKey = PKI.encryptedPrivateKeyFromPem(pem);
        const decryptedAsn1Key = PKI.decryptPrivateKeyInfo(wrappedKey, _PRIVATE_KEY_ENCRYPTED_PASSWORD);
        const key = ED25519.privateKeyFromAsn1(decryptedAsn1Key);

        ASSERT.equal(key.privateKeyBytes.buffer, Buffer.from(_PRIVATE_KEY_VALUE).buffer);
      });

    it('should generate new ed25519 private key and read it back (round-trip)', function() {
        // Note : this tests the ED25519 module following adding option {parseAllBytes: false} in privateKeyFromAsn1()
        const { privateKey } = ED25519.generateKeyPair({seed: Buffer.from(_PRIVATE_KEY_VALUE)});
        const originalPrivateKeyBytes = Buffer.from(privateKey.privateKeyBytes.slice(0, 32));
        const pem = ED25519.privateKeyToPem(privateKey);
        
        const keyFromPem = ED25519.privateKeyFromPem(pem);

        ASSERT.equal(originalPrivateKeyBytes.buffer, keyFromPem.privateKeyBytes.buffer);
      })    

    it('should decrypt an ED25519 private key', function() {
        const wrappedKey = PKI.encryptedPrivateKeyFromPem(_PRIVATE_KEY_ENCRYPTED);
        const asn1Key = PKI.decryptPrivateKeyInfo(wrappedKey, _PRIVATE_KEY_ENCRYPTED_PASSWORD);
        const key = ED25519.privateKeyFromAsn1(asn1Key);
        ASSERT.equal(key.privateKeyBytes.buffer, Buffer.from(_PRIVATE_KEY_VALUE).buffer);
      })
 
})

describe('x509_ed25519', function() {

    it('should load a x509 certification request', function() {
        const csr = PKI.certificationRequestFromPem(_CERTIFICATION_REQUEST_PEM)
        ASSERT.ok(csr.verify())
      });

    it('should generate new x509 csr with ed25519 key, sign and verify it', function() {
        const keyPair = ED25519.generateKeyPair({seed: Buffer.from(_PRIVATE_KEY_VALUE)})
        const csr = PKI.createCertificationRequest()
        csr.publicKey = keyPair.publicKey
        var attrs = [{
            name: 'commonName',
            value: 'DUMMY'
        }]
        csr.setSubject(attrs)
        csr.sign(keyPair.privateKey)
        const pem = PKI.certificationRequestToPem(csr)

        // Load and verify
        const csrReloaded = PKI.certificationRequestFromPem(pem);
        ASSERT.ok(csrReloaded.verify());
      });

    it('should load a x509 certificate', function() {
        const cert = PKI.certificateFromPem(_CERTIFICATE_PEM)
        ASSERT.equal(cert.subject.getField('CN').value, 'DUMMY')
      });

    it('should generate new x509 certificate with ed25519 key', function() {
        const keyPair = ED25519.generateKeyPair({seed: Buffer.from(_PRIVATE_KEY_VALUE)})
        const cert = PKI.createCertificate()
        cert.publicKey = keyPair.publicKey
        cert.serialNumber = 0x01
        cert.validity.notBefore = new Date('2022-08-01')
        cert.validity.notAfter = new Date('2042-08-01')

        const attrs = [{
            name: 'commonName',
            value: 'DUMMY'
        }]
        cert.setSubject(attrs)
        cert.setIssuer(attrs)  // Self
        cert.setExtensions([{
            name: 'basicConstraints',
            critical: true,
            cA: true,
        }, {
            name: 'keyUsage',
            keyCertSign: true,
            digitalSignature: true,
            nonRepudiation: true,
            keyEncipherment: true,
            dataEncipherment: false
        }, {
            name: 'subjectKeyIdentifier'
        }, {
            name: 'authorityKeyIdentifier',
            keyIdentifier: true,
        }])

        cert.sign(keyPair.privateKey)

        // Exporter sous format PEM
        const pem = PKI.certificateToPem(cert)

        // Load and verify PEM
        const certificateFromPem = PKI.certificateFromPem(pem)
        ASSERT.ok(certificateFromPem.verify(certificateFromPem))
      });

})