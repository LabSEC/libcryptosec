#ifndef BASICCONSTRAINTSEXTENSION_H_
#define BASICCONSTRAINTSEXTENSION_H_

#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "Extension.h"
#include <libcryptosec/exception/CertificationException.h>

class BasicConstraintsExtension : public Extension
{
public:
	BasicConstraintsExtension();
	BasicConstraintsExtension(X509_EXTENSION *ext) throw (CertificationException);
	virtual ~BasicConstraintsExtension();
	virtual std::string extValue2Xml(std::string tab = "");
	virtual std::string getXmlEncoded();
	virtual std::string getXmlEncoded(std::string tab);
	void setCa(bool value);
	bool isCa();
	void setPathLen(long value);
	long getPathLen();
	X509_EXTENSION* getX509Extension();
protected:
	bool ca;
	long pathLen;
};

#endif /*BASICCONSTRAINTSEXTENSION_H_*/
