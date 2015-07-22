#ifndef ASN1BITSTRING_H_
#define ASN1BITSTRING_H_

#include "Asn1Type.h"

class Asn1BitString : public Asn1Type
{
public:
	Asn1BitString();
	Asn1BitString(ASN1_TYPE* type);
	virtual ~Asn1BitString();
	
	int getValue(int index) const throw();
	void setValue(int index, int value) throw();
};

#endif /*ASN1BITSTRING_H_*/
