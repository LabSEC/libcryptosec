#ifndef CERTIFICATEREVOCATIONLISTBUILDER_H_
#define CERTIFICATEREVOCATIONLISTBUILDER_H_

#include <openssl/x509.h>

#include <string>
#include <vector>

#include <libcryptosec/DateTime.h>
#include <libcryptosec/MessageDigest.h>
#include <libcryptosec/PrivateKey.h>

#include "CertificateRevocationList.h"
#include "RDNSequence.h"
#include "RevokedCertificate.h"

#include "Extension.h"
#include "KeyUsageExtension.h"
#include "ExtendedKeyUsageExtension.h"
#include "BasicConstraintsExtension.h"
#include "CRLDistributionPointsExtension.h"
#include "AuthorityInformationAccessExtension.h"
#include "IssuerAlternativeNameExtension.h"
#include "SubjectAlternativeNameExtension.h"
#include "AuthorityKeyIdentifierExtension.h"
#include "SubjectKeyIdentifierExtension.h"
#include "SubjectInformationAccessExtension.h"
#include "CertificatePoliciesExtension.h"
#include "CRLNumberExtension.h"

#include <libcryptosec/exception/AsymmetricKeyException.h>
#include <libcryptosec/exception/CertificationException.h>

class CertificateRevocationListBuilder
{
public:
	CertificateRevocationListBuilder();
	CertificateRevocationListBuilder(std::string pemEncoded)
			throw (EncodeException);
	CertificateRevocationListBuilder(ByteArray &derEncoded)
			throw (EncodeException);
	CertificateRevocationListBuilder(const CertificateRevocationListBuilder& crl);
	virtual ~CertificateRevocationListBuilder();
	std::string getXmlEncoded();
	std::string getXmlEncoded(std::string tab);
	void setSerialNumber(long serial) throw (CertificationException);
	/**
	 * Definir serial à partir de BigInteger, para seriais maiores do que um "long".
	 */
	void setSerialNumber(BigInteger serial) throw (CertificationException, BigIntegerException);
	long getSerialNumber() throw (CertificationException);
	BigInteger getSerialNumberBigInt() throw (CertificationException, BigIntegerException);
	void setVersion(long version);
	long getVersion() throw (CertificationException);
	void setIssuer(RDNSequence &issuer) throw (CertificationException);
	void setIssuer(X509* issuer) throw (CertificationException);
	RDNSequence getIssuer();
	void setLastUpdate(DateTime &dateTime);
	DateTime getLastUpdate();
	void setNextUpdate(DateTime &dateTime);
	DateTime getNextUpdate();
	void addRevokedCertificate(RevokedCertificate &revoked)
			throw (CertificationException);
	void addRevokedCertificates(std::vector<RevokedCertificate> &revoked)
			throw (CertificationException);
	std::vector<RevokedCertificate> getRevokedCertificate();
	CertificateRevocationList* sign(PrivateKey &privateKey, MessageDigest::Algorithm messageDigestAlgorithm)
			throw (CertificationException);
	X509_CRL* getX509Crl() const;
	CertificateRevocationListBuilder& operator =(const CertificateRevocationListBuilder& value);
	void addExtension(Extension& extension) throw (CertificationException);
	void addExtensions(std::vector<Extension *> &extensions) throw (CertificationException);
	void replaceExtension(Extension &extension) throw (CertificationException);
	std::vector<Extension*> getExtension(Extension::Name extensionName);
	std::vector<Extension*> getExtensions();
	std::vector<Extension *> getUnknownExtensions();

	
protected:
	X509_CRL *crl;
};

#endif /*CERTIFICATEREVOCATIONLISTBUILDER_H_*/
