#include <libcryptosec/asn1/Asn1Type.h>

Asn1Type::Asn1Type()
{
	this->asn1Type = ASN1_TYPE_new();
}

Asn1Type::Asn1Type(ASN1_TYPE* asn1Type)
{
	this->asn1Type = asn1Type;
}

Asn1Type::~Asn1Type()
{
	ASN1_TYPE_free(this->asn1Type);
}

Asn1Type::Type Asn1Type::getType() const throw()
{
	Type ret;
	
	switch(this->asn1Type->type)
	{
		case V_ASN1_BOOLEAN :
			ret = Asn1Type::BOOLEAN;
			break;
			
/*		case V_ASN1_STRING :
			ret = Asn1Type::STRING;
			break;*/
			
		case V_ASN1_OBJECT :
			ret = Asn1Type::OBJECT;
			break;
			
		case V_ASN1_INTEGER :
			ret = Asn1Type::INTEGER;
			break;
			
		case V_ASN1_ENUMERATED :
			ret = Asn1Type::ENUMERATED;
			break;
			
		case V_ASN1_BIT_STRING :
			ret = Asn1Type::BIT_STRING;
			break;
			
		case V_ASN1_OCTET_STRING :
			ret = Asn1Type::OCTET_STRING;
			break;
			
		case V_ASN1_PRINTABLESTRING :
			ret = Asn1Type::PRINTABLESTRING;
			break;
			
		case V_ASN1_T61STRING :
			ret = Asn1Type::T61STRING;
			break;
			
		case V_ASN1_IA5STRING :
			ret = Asn1Type::IA5STRING;
			break;
			
		case V_ASN1_BMPSTRING :
			ret = Asn1Type::BMPSTRING;
			break;
			
		case V_ASN1_UNIVERSALSTRING :
			ret = Asn1Type::UNIVERSALSTRING;
			break;
			
		case V_ASN1_UTCTIME :
			ret = Asn1Type::UTCTIME;
			break;
			
		case V_ASN1_GENERALIZEDTIME :
			ret = Asn1Type::GENERALIZEDTIME;
			break;
			
		case V_ASN1_VISIBLESTRING :
			ret = Asn1Type::VISIBLESTRING;
			break;
			
		case V_ASN1_UTF8STRING :
			ret = Asn1Type::UTF8STRING;
			break;
			
		case V_ASN1_SEQUENCE :
			ret = Asn1Type::SEQUENCE;
			break;
			
		case V_ASN1_SET : 
			ret = Asn1Type::SET;
			break;
	}
	
	return ret;
}

const ASN1_TYPE* Asn1Type::getAsn1Type() const throw()
{
	return this->asn1Type;
}

bool Asn1Type::operator==(Asn1Type const& c) const throw()
{
	bool ret = false;
	const ASN1_TYPE* aType = c.getAsn1Type();
	
	
	if(this->asn1Type->type == aType->type)
	{
		switch(this->asn1Type->type)
		{
			case V_ASN1_BOOLEAN :
				ret = this->asn1Type->value.boolean == aType->value.boolean;
				break;
				
			/*		case V_ASN1_STRING :
				ret = Asn1Type::STRING;
				break;*/
				
			case V_ASN1_OBJECT :
				ret = OBJ_cmp(this->asn1Type->value.object, aType->value.object) == 0;
				break;
				
			case V_ASN1_INTEGER :
				ret = ASN1_INTEGER_cmp(this->asn1Type->value.integer, aType->value.integer) == 0;
				break;
				
			case V_ASN1_ENUMERATED :
				ret = ASN1_STRING_cmp(this->asn1Type->value.enumerated, aType->value.enumerated) == 0;
				break;
				
			case V_ASN1_BIT_STRING :
				ret = ASN1_STRING_cmp(this->asn1Type->value.enumerated, aType->value.enumerated) == 0;
				break;
				
			case V_ASN1_OCTET_STRING :
				ret = ASN1_STRING_cmp(this->asn1Type->value.octet_string, aType->value.octet_string) == 0;
				break;
				
			case V_ASN1_PRINTABLESTRING :
				ret = ASN1_STRING_cmp(this->asn1Type->value.printablestring, aType->value.printablestring) == 0;
				break;
				
			case V_ASN1_T61STRING :
				ret = ASN1_STRING_cmp(this->asn1Type->value.t61string, aType->value.t61string) == 0;
				break;
				
			case V_ASN1_IA5STRING :
				ret = ASN1_STRING_cmp(this->asn1Type->value.ia5string, aType->value.ia5string) == 0;
				break;
				
			case V_ASN1_BMPSTRING :
				ret = ASN1_STRING_cmp(this->asn1Type->value.bmpstring, aType->value.bmpstring) == 0;
				break;
				
			case V_ASN1_UNIVERSALSTRING :
				ret = ASN1_STRING_cmp(this->asn1Type->value.universalstring, aType->value.universalstring) == 0;
				break;
				
			case V_ASN1_UTCTIME :
				ret = ASN1_STRING_cmp(this->asn1Type->value.utctime, aType->value.utctime) == 0;
				break;
				
			case V_ASN1_GENERALIZEDTIME :
				ret = ASN1_STRING_cmp(this->asn1Type->value.generalizedtime, aType->value.generalizedtime) == 0;
				break;
				
			case V_ASN1_VISIBLESTRING :
				ret = ASN1_STRING_cmp(this->asn1Type->value.visiblestring, aType->value.visiblestring) == 0;
				break;
				
			case V_ASN1_UTF8STRING :
				ret = ASN1_STRING_cmp(this->asn1Type->value.utf8string, aType->value.utf8string) == 0;
				break;
				
	/*		case V_ASN1_SEQUENCE :
				ret = Asn1Type::SEQUENCE;
				break;
				
			case V_ASN1_SET : 
				ret = Asn1Type::SET;
				break;*/
		}
	}
	
	return ret;
}

bool Asn1Type::operator!=(Asn1Type const& c) const throw()
{
	return !this->operator==(c);
}
