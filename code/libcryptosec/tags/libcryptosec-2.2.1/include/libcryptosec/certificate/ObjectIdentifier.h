#ifndef OBJECTIDENTIFIER_H_
#define OBJECTIDENTIFIER_H_

#include <openssl/asn1.h>
#include <openssl/objects.h>

#include <string>

#include <libcryptosec/exception/CertificationException.h>

class ObjectIdentifier
{
public:
	ObjectIdentifier();
	ObjectIdentifier(ASN1_OBJECT *asn1Object);
	ObjectIdentifier(const ObjectIdentifier& objectIdentifier);
	virtual ~ObjectIdentifier();
	std::string getXmlEncoded();
	std::string getXmlEncoded(std::string tab);
	std::string getOid()
			throw (CertificationException);
	int getNid() const;
	std::string getName();
	ASN1_OBJECT* getObjectIdentifier() const;
	ObjectIdentifier& operator =(const ObjectIdentifier& value);
protected:
	ASN1_OBJECT *asn1Object;
};

#endif /*OBJECTIDENTIFIER_H_*/
