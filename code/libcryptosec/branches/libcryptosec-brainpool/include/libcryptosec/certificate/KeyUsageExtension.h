#ifndef KEYUSAGEEXTENSION_H_
#define KEYUSAGEEXTENSION_H_

#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "Extension.h"

#include <libcryptosec/exception/CertificationException.h>

class KeyUsageExtension : public Extension
{
public:
	enum Usage
	{
		DIGITAL_SIGNATURE = 0,
		NON_REPUDIATION = 1,
		KEY_ENCIPHERMENT = 2,
		DATA_ENCIPHERMENT = 3,
		KEY_AGREEMENT = 4,
		KEY_CERT_SIGN = 5,
		CRL_SIGN = 6,
		ENCIPHER_ONLY = 7,
		DECIPHER_ONLY = 8,
	};
	KeyUsageExtension();
	KeyUsageExtension(X509_EXTENSION *ext) throw (CertificationException);
	virtual ~KeyUsageExtension();
	
	/**
	 * @deprecated
	 * Retorna o conteudo da extensão em formato XML.
	 * Esta função será substituida por toXml().
	 * */
	std::string getXmlEncoded();
	std::string getXmlEncoded(std::string tab);
	std::string extValue2Xml(std::string tab = "");
	void setUsage(KeyUsageExtension::Usage usage, bool value);
	bool getUsage(KeyUsageExtension::Usage usage);
	static std::string usage2Name(KeyUsageExtension::Usage usage);
	X509_EXTENSION* getX509Extension();
protected:
	bool usages[9];
};

#endif /*KEYUSAGEEXTENSION_H_*/
