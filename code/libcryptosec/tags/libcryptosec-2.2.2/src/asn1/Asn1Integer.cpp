#include <libcryptosec/asn1/Asn1Integer.h>

Asn1Integer::Asn1Integer()
{
	this->asn1Type = ASN1_TYPE_new();
	ASN1_TYPE_set(this->asn1Type, V_ASN1_INTEGER, ASN1_INTEGER_new());
}

Asn1Integer::Asn1Integer(ASN1_TYPE* type) : Asn1Type(type)
{
}

Asn1Integer::~Asn1Integer()
{
}

//faz copia
BigInteger* Asn1Integer::getValue() const throw()
{
	BigInteger* ret = NULL;
	
	if(this->asn1Type->value.integer != NULL)
	{
		ret = new BigInteger(this->asn1Type->value.integer);
	}
	
	return ret;
}

//faz copia
void Asn1Integer::setValue(const BigInteger b) throw()
{
	ASN1_TYPE_set(this->asn1Type, V_ASN1_INTEGER, b.getASN1Value());
}
