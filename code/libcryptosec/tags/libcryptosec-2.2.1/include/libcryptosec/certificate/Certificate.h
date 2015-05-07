#ifndef CERTIFICATE_H_
#define CERTIFICATE_H_

/* system includes */
#include <time.h>
#include <vector>
#include <string>
/* openssl includes */
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>
/* libcryptosec includes */
#include <libcryptosec/Base64.h>
#include <libcryptosec/ByteArray.h>
#include <libcryptosec/DateTime.h>
#include <libcryptosec/MessageDigest.h>
#include <libcryptosec/PrivateKey.h>
#include <libcryptosec/PublicKey.h>
#include <libcryptosec/certificate/CertificateRequest.h>

#include "RDNSequence.h"
#include "Extension.h"
#include "KeyUsageExtension.h"
#include "ExtendedKeyUsageExtension.h"
#include "BasicConstraintsExtension.h"
#include "CRLDistributionPointsExtension.h"
#include "AuthorityInformationAccessExtension.h"
#include "IssuerAlternativeNameExtension.h"
#include "SubjectAlternativeNameExtension.h"
#include "SubjectInformationAccessExtension.h"
#include "AuthorityKeyIdentifierExtension.h"
#include "SubjectKeyIdentifierExtension.h"
#include "CertificatePoliciesExtension.h"

#include <libcryptosec/exception/CertificationException.h>
#include <libcryptosec/exception/EncodeException.h>

class Certificate
{
public:
	Certificate(X509 *cert);
	Certificate(std::string pemEncoded) throw (EncodeException);
	Certificate(ByteArray &derEncoded) throw (EncodeException);
	Certificate(const Certificate& cert);
	virtual ~Certificate();
	std::string getPemEncoded() const throw (EncodeException);
	ByteArray getDerEncoded() const throw (EncodeException);
	/**
	 * @deprecated
	 * Retorna o conteudo da extensão em formato XML.
	 * Esta função será substituida por toXml().
	 * */
	std::string getXmlEncoded();
	std::string getXmlEncoded(std::string tab);
	virtual std::string toXml(std::string tab = "");
	long getSerialNumber() throw (CertificationException);
	BigInteger getSerialNumberBigInt() throw (CertificationException);
	MessageDigest::Algorithm getMessageDigestAlgorithm()
			throw (MessageDigestException);
	PublicKey* getPublicKey() throw (CertificationException, AsymmetricKeyException);
	ByteArray getPublicKeyInfo() throw (CertificationException);
	long getVersion() throw (CertificationException);
	DateTime getNotBefore();
	DateTime getNotAfter();
	RDNSequence getIssuer();
	RDNSequence getSubject();
	std::vector<Extension *> getExtension(Extension::Name extensionName);
	std::vector<Extension *> getExtensions();
	std::vector<Extension *> getUnknownExtensions();
	ByteArray getFingerPrint(MessageDigest::Algorithm algorithm) const
		throw (CertificationException, EncodeException, MessageDigestException);
	bool verify(PublicKey &publicKey);
	X509* getX509() const;
	/**
	 * create a new certificate request using the data from this certificate
	 * @param privateKey certificate request signing key
	 * @param algorithm message digest algorithm
	 * @throws CertificationException error on conversion of x509 to x509 req
	 */
	CertificateRequest getNewCertificateRequest(PrivateKey &privateKey, MessageDigest::Algorithm algorithm)
		throw (CertificationException);
	Certificate& operator =(const Certificate& value);
	bool operator ==(const Certificate& value);
	bool operator !=(const Certificate& value);
protected:
	X509 *cert;
};

#endif /*CERTIFICATE_H_*/
