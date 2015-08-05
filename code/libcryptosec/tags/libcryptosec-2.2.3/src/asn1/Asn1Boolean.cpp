#include <libcryptosec/asn1/Asn1Boolean.h>

Asn1Boolean::Asn1Boolean() : Asn1Type()
{
	this->asn1Type = ASN1_TYPE_new();
	ASN1_TYPE_set(this->asn1Type, V_ASN1_BOOLEAN, 0);
}

Asn1Boolean::Asn1Boolean(ASN1_TYPE* type) : Asn1Type(type)
{
}

Asn1Boolean::~Asn1Boolean()
{
}

bool Asn1Boolean::getValue() const throw()
{
	return this->asn1Type->value.boolean;
}

void Asn1Boolean::setValue(bool b) throw()
{
	this->asn1Type->value.boolean = b ? 255 : 0;
}
