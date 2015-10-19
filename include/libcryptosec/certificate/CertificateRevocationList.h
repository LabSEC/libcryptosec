#ifndef CERTIFICATEREVOCATIONLIST_H_
#define CERTIFICATEREVOCATIONLIST_H_

#include <openssl/x509.h>

#include <string>
#include <vector>

#include <libcryptosec/ByteArray.h>
#include <libcryptosec/Base64.h>
#include <libcryptosec/DateTime.h>
#include <libcryptosec/PublicKey.h>

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
#include "DeltaCRLIndicatorExtension.h"

#include "RDNSequence.h"
#include "RevokedCertificate.h"

class CertificateRevocationList
{
public:
	CertificateRevocationList(X509_CRL *crl);
	CertificateRevocationList(std::string pemEncoded)
			throw (EncodeException);
	CertificateRevocationList(ByteArray &derEncoded)
			throw (EncodeException);
	CertificateRevocationList(const CertificateRevocationList& crl);
	virtual ~CertificateRevocationList();
	std::string getXmlEncoded();
	std::string getXmlEncoded(std::string tab);
	std::string getPemEncoded() throw (EncodeException);
	ByteArray getDerEncoded() throw (EncodeException);
	long getSerialNumber() throw (CertificationException);
	BigInteger getSerialNumberBigInt() throw (CertificationException, BigIntegerException);
	long getBaseCRLNumber() throw (CertificationException);
	BigInteger getBaseCRLNumberBigInt() throw (CertificationException, BigIntegerException);
	long getVersion() throw (CertificationException);
	RDNSequence getIssuer();
	DateTime getLastUpdate();
	DateTime getNextUpdate();
	std::vector<RevokedCertificate> getRevokedCertificate();
	bool verify(PublicKey &publicKey);
	X509_CRL* getX509Crl() const;
	CertificateRevocationList& operator =(const CertificateRevocationList& value);
	std::vector<Extension*> getExtension(Extension::Name extensionName);
	std::vector<Extension *> getExtensions();
	std::vector<Extension *> getUnknownExtensions();
protected:
	X509_CRL *crl;
};

#endif /*CERTIFICATEREVOCATIONLIST_H_*/
