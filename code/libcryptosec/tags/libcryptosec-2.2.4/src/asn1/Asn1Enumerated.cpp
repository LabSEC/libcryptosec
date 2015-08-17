#include <libcryptosec/asn1/Asn1Enumerated.h>

Asn1Enumerated::Asn1Enumerated()
{
	this->asn1Type = ASN1_TYPE_new();
	ASN1_TYPE_set(this->asn1Type, V_ASN1_ENUMERATED, NULL);
}

Asn1Enumerated::Asn1Enumerated(ASN1_TYPE* type) : Asn1Type(type)
{
}

Asn1Enumerated::~Asn1Enumerated()
{
}

long Asn1Enumerated::getValue() const throw()
{
	return ASN1_ENUMERATED_get(this->asn1Type->value.enumerated);
}


void Asn1Enumerated::setValue(long c) throw()
{
	ASN1_ENUMERATED_set(this->asn1Type->value.enumerated, c);
}
