#ifndef SUBJECTALTERNATIVENAMEEXTENSION_H_
#define SUBJECTALTERNATIVENAMEEXTENSION_H_

#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "Extension.h"
#include "GeneralNames.h"

#include <libcryptosec/exception/CertificationException.h>

class SubjectAlternativeNameExtension : public Extension
{
public:
	SubjectAlternativeNameExtension();
	SubjectAlternativeNameExtension(X509_EXTENSION *ext) throw (CertificationException);
	virtual ~SubjectAlternativeNameExtension();
	/**
	 * @deprecated
	 * Retorna o conteudo da extensão em formato XML.
	 * Esta função será substituida por toXml().
	 * */
	std::string getXmlEncoded();
	virtual std::string getXmlEncoded(std::string tab);
	virtual std::string extValue2Xml(std::string tab = "");
	void setSubjectAltName(GeneralNames &generalNames);
	GeneralNames getSubjectAltName();
	X509_EXTENSION* getX509Extension();
protected:
	GeneralNames subjectAltName;
};

#endif /*SUBJECTALTERNATIVENAMEEXTENSION_H_*/
