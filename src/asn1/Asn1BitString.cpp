#include <libcryptosec/asn1/Asn1BitString.h>

Asn1BitString::Asn1BitString()
{
	this->asn1Type = ASN1_TYPE_new();
	ASN1_TYPE_set(this->asn1Type, V_ASN1_BIT_STRING, NULL);
}

Asn1BitString::Asn1BitString(ASN1_TYPE* type) : Asn1Type(type) 
{
}

Asn1BitString::~Asn1BitString() 
{
}

int Asn1BitString::getValue(int index) const throw()
{
	return ASN1_BIT_STRING_get_bit(this->asn1Type->value.bit_string, index);
}

void Asn1BitString::setValue(int index, int value) throw()
{
	ASN1_BIT_STRING_set_bit(this->asn1Type->value.bit_string, index, value);
}