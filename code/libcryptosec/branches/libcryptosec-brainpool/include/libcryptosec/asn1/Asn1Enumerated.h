#ifndef ASN1ENUMERATED_H_
#define ASN1ENUMERATED_H_

#include "Asn1Type.h"

class Asn1Enumerated : public Asn1Type
{
public:
	Asn1Enumerated();
	Asn1Enumerated(ASN1_TYPE* type);
	virtual ~Asn1Enumerated();
	
	long getValue() const throw();
	void setValue(long c) throw();
};

#endif /*ASN1ENUMERATED_H_*/
