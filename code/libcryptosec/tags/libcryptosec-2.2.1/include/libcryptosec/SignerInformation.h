#ifndef SIGNERINFORMATION_H_
#define SIGNERINFORMATION_H_

#include <openssl/pkcs7.h>

#include "MessageDigest.h"
#include <libcryptosec/certificate/RDNSequence.h>
#include <libcryptosec/asn1/Asn1Attribute.h>

class SignerInformation
{
public:
	//SignerInformation();
	SignerInformation(const PKCS7_SIGNER_INFO* si);
	virtual ~SignerInformation();
	
	int getVersion() const throw();
	std::pair<RDNSequence, long> getIssuerAndSerial() const throw();
	MessageDigest::Algorithm getDigestAlg() const throw();
	std::vector<Asn1Attribute> getSignedAttributes() const throw();
	ObjectIdentifier getEncryptionAlg() const throw();
	ByteArray getSignature() const throw();
	
	
protected:
	PKCS7_SIGNER_INFO* si;
};

#endif /*SIGNERINFORMATION_H_*/
