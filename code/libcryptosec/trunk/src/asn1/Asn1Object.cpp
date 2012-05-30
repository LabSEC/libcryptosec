#include <libcryptosec/asn1/Asn1Object.h>

Asn1Object::Asn1Object()
{
	this->asn1Type = ASN1_TYPE_new();
	ASN1_TYPE_set(this->asn1Type, V_ASN1_OBJECT, NULL);
}

Asn1Object::Asn1Object(ASN1_TYPE* type)
{
	this->asn1Type = type;
}

Asn1Object::~Asn1Object()
{
}

ObjectIdentifier* Asn1Object::getValue() const throw()
{
	ObjectIdentifier* ret = NULL;
	
	if(this->asn1Type->value.object != NULL)
	{
		ret = new ObjectIdentifier(this->asn1Type->value.object); 
	}
	
	return ret;
}

//faz copia
void Asn1Object::setValue(const ObjectIdentifier obj) throw()
{
	ASN1_TYPE_set(this->asn1Type, V_ASN1_OBJECT, OBJ_dup(obj.getObjectIdentifier()));
}
