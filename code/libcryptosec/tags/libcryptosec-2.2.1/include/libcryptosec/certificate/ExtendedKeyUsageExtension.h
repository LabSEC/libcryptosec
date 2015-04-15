#ifndef EXTENDEDKEYUSAGEEXTENSION_H_
#define EXTENDEDKEYUSAGEEXTENSION_H_

#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "Extension.h"
#include "ObjectIdentifier.h"
#include "ObjectIdentifierFactory.h"

class ExtendedKeyUsageExtension : public Extension
{
public:
	ExtendedKeyUsageExtension();
	ExtendedKeyUsageExtension(X509_EXTENSION *ext) throw (CertificationException);
	virtual ~ExtendedKeyUsageExtension();
	/**
	 * @deprecated
	 * Retorna o conteudo da extensão em formato XML.
	 * Esta função será substituida por toXml().
	 * */
	std::string getXmlEncoded();
	std::string getXmlEncoded(std::string tab);
	virtual std::string extValue2Xml(std::string tab = "");
	void addUsage(ObjectIdentifier objectIdentifier);
	std::vector<ObjectIdentifier> getUsages();
	X509_EXTENSION* getX509Extension();
protected:
	std::vector<ObjectIdentifier> usages;
};

#endif /*EXTENDEDKEYUSAGEEXTENSION_H_*/
