#ifndef ASN1ATTRIBUTE_H_
#define ASN1ATTRIBUTE_H_

#include <libcryptosec/certificate/ObjectIdentifier.h>
#include "Asn1Type.h"

class Asn1Attribute
{
public:
	Asn1Attribute();
	Asn1Attribute(X509_ATTRIBUTE* attr);
	virtual ~Asn1Attribute();
	
	ObjectIdentifier getOid() const throw();
	void setOid() const throw();
	
	vector<Asn1Type> getValue() const throw();
	void setValue(vector<Asn1Type>) const throw();
	
	//nao faz copia
	X509_ATTRIBUTE* getX509Attribute() const throw();
	
protected:
	X509_ATTRIBUTE* attr;
};

#endif /*ASN1ATTRIBUTE_H_*/
