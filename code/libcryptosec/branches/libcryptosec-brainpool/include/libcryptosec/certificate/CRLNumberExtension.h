#ifndef CRLNUMBEREXTENSION_H_
#define CRLNUMBEREXTENSION_H_

#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "Extension.h"
#include <libcryptosec/exception/CertificationException.h>

#include <sstream>

class CRLNumberExtension : public Extension
{
public:
	CRLNumberExtension(unsigned long serial);
	CRLNumberExtension(X509_EXTENSION* ext) throw (CertificationException);
	virtual ~CRLNumberExtension();
	/**
	 * @deprecated
	 * Retorna o conteudo da extensão em formato XML.
	 * Esta função será substituida por toXml().
	 * */
	virtual std::string getXmlEncoded(); //TODO
	virtual std::string getXmlEncoded(std::string tab); //TODO
	virtual std::string extValue2Xml(std::string tab = "");
	void setSerial(unsigned long serial); //TODO
	const long getSerial() const; //TODO
	X509_EXTENSION* getX509Extension(); //TODO
	
protected:
	unsigned long serial;	
};

#endif /*CRLNUMBEREXTENSION_H_*/
