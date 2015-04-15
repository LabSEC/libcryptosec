#ifndef OBJECTIDENTIFIERFACTORY_H_
#define OBJECTIDENTIFIERFACTORY_H_

#include <openssl/objects.h>

#include "ObjectIdentifier.h"

#include <libcryptosec/exception/CertificationException.h>

class ObjectIdentifierFactory
{
public:
	static ObjectIdentifier getObjectIdentifier(std::string oid)
			throw (CertificationException);
	static ObjectIdentifier getObjectIdentifier(int nid)
		throw (CertificationException);
	static ObjectIdentifier createObjectIdentifier(std::string oid, std::string name)
			throw (CertificationException);
};

#endif /*OBJECTIDENTIFIERFACTORY_H_*/
