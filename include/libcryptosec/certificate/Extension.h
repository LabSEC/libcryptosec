#ifndef EXTENSION_H_
#define EXTENSION_H_

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <libcryptosec/Base64.h>

#include "ObjectIdentifier.h"
#include "ObjectIdentifierFactory.h"

#include <libcryptosec/exception/CertificationException.h>

class Extension
{
public:
	enum Name
	{
		UNKNOWN,
		KEY_USAGE,
		EXTENDED_KEY_USAGE,
		AUTHORITY_KEY_IDENTIFIER,
		CRL_DISTRIBUTION_POINTS,
		AUTHORITY_INFORMATION_ACCESS,
		BASIC_CONSTRAINTS,
		CERTIFICATE_POLICIES,
		ISSUER_ALTERNATIVE_NAME,
		SUBJECT_ALTERNATIVE_NAME,
		SUBJECT_INFORMATION_ACCESS,
		SUBJECT_KEY_IDENTIFIER,
		CRL_NUMBER,
		DELTA_CRL_INDICATOR
	};
	
	Extension(X509_EXTENSION *ext) throw (CertificationException);
	Extension(std::string oid, bool critical, std::string valueBase64) throw (CertificationException);
	virtual ~Extension();
	
	/**
	 * @deprecated
	 * Retorna o conteudo da extensão em formato XML.
	 * Esta função será substituida por toXml().
	 * */
	virtual std::string getXmlEncoded();
	virtual std::string getXmlEncoded(std::string tab);
	std::string toXml(std::string tab = "") throw(CertificationException);
	virtual std::string extValue2Xml(std::string tab = "");
	ObjectIdentifier getObjectIdentifier() const;
	std::string getName();
	Extension::Name getTypeName();
	ByteArray getValue() const;
	std::string getBase64Value();
	void setCritical(bool critical);
	bool isCritical() const;
	virtual X509_EXTENSION* getX509Extension();
	static Extension::Name getName(int nid);
	static Extension::Name getName(X509_EXTENSION *ext);
protected:
	Extension();
	ObjectIdentifier objectIdentifier;
	bool critical;
	ByteArray value;
};

#endif /*EXTENSION_H_*/
