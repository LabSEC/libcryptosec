#ifndef ASN1OBJECT_H_
#define ASN1OBJECT_H_

#include "Asn1Type.h"
#include <libcryptosec/certificate/ObjectIdentifier.h>

class Asn1Object : public Asn1Type
{
public:
	Asn1Object();
	Asn1Object(ASN1_TYPE* type);
	virtual ~Asn1Object();
	
	//nao faz copia
	ObjectIdentifier* getValue() const throw();
	void setValue(const ObjectIdentifier obj) throw();
};

#endif /*ASN1OBJECT_H_*/
