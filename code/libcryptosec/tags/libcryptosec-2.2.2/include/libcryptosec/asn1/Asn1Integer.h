#ifndef ASN1INTEGER_H_
#define ASN1INTEGER_H_

#include "Asn1Type.h"
#include <libcryptosec/BigInteger.h>

class Asn1Integer : public Asn1Type
{
public:
	Asn1Integer();
	Asn1Integer(ASN1_TYPE* type);
	virtual ~Asn1Integer();
	
	BigInteger* getValue() const throw();
	void setValue(const BigInteger b) throw();
};

#endif /*ASN1INTEGER_H_*/
