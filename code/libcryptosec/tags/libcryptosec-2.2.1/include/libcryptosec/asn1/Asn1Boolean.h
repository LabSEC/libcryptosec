#ifndef ASN1BOOLEAN_H_
#define ASN1BOOLEAN_H_

#include "Asn1Type.h"

class Asn1Boolean : public Asn1Type
{
public:
	Asn1Boolean();
	Asn1Boolean(ASN1_TYPE* asn1type);
	virtual ~Asn1Boolean();
	
	bool getValue() const throw();
	void setValue(bool b) throw();

protected:	
	ASN1_BOOLEAN asn1Boolean;
};

#endif /*ASN1BOOLEAN_H_*/
