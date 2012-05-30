#ifndef ASN1SEQUENCE_H_
#define ASN1SEQUENCE_H_

#include "Asn1Type.h"

class Asn1Sequence : public Asn1Type
{
public:
	Asn1Sequence();
	Asn1Sequence(ASN1_TYPE* type);
	virtual ~Asn1Sequence();
	
	const Asn1Type* getValue(int index) const throw();
	void addValue(int index = -1) throw();
};

#endif /*ASN1SEQUENCE_H_*/
