#ifndef DELTACRLINDICATOREXTENSION_H_
#define DELTACRLINDICATOREXTENSION_H_

#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "Extension.h"
#include <libcryptosec/exception/CertificationException.h>

class DeltaCRLIndicatorExtension : public Extension
{
public:
	DeltaCRLIndicatorExtension(unsigned long baseCrlNumber);
	DeltaCRLIndicatorExtension(X509_EXTENSION *ext) throw (CertificationException);
	virtual ~DeltaCRLIndicatorExtension();
	/**
	 * @deprecated
	 * Retorna o conteudo da extensão em formato XML.
	 * Esta função será substituida por toXml().
	 * */
	std::string getXmlEncoded();
	std::string getXmlEncoded(std::string tab);
	virtual std::string extValue2Xml(std::string tab = "");
	X509_EXTENSION* getX509Extension();
	void setSerial(unsigned long serial); //TODO
	const long getSerial() const; //TODO
protected:
	unsigned long baseCrlNumber;
};

#endif /*DELTACRLINDICATOREXTENSION_H_*/
