#include <libcryptosec/certificate/Extension.h>

Extension::Extension()
{
	this->critical = false;
}

Extension::Extension(X509_EXTENSION *ext) throw (CertificationException)
{
	if (ext == NULL)
	{
		throw CertificationException(CertificationException::INVALID_EXTENSION, "Extension::Extension");
	}
	this->objectIdentifier = ObjectIdentifier(OBJ_dup(ext->object));
	this->critical = X509_EXTENSION_get_critical(ext)?true:false;
	this->value = ByteArray(ext->value->data, ext->value->length);
}

Extension::Extension(std::string oid, bool critical, std::string valueBase64)  throw (CertificationException)
{
	this->objectIdentifier = ObjectIdentifierFactory::getObjectIdentifier(oid);
	this->critical = critical;
	this->value = Base64::decode(valueBase64);
}

Extension::~Extension()
{
}

std::string Extension::toXml(std::string tab) throw(CertificationException)
{
	std::string ret, critical;
	ret = tab + "<extension>\n";
		ret += tab + "\t<extnID>"+ this->getName() +"</extnID>\n";
		ret += tab + "\t<oid>"+ this->getObjectIdentifier().getOid() +"</oid>\n";
		critical = (this->isCritical())?"yes":"no";
		ret += tab + "\t<critical>"+ critical +"</critical>\n";
		ret += tab + "\t<extnValue>"+ +"\n" + this->extValue2Xml(tab + "\t\t") + tab + "\t</extnValue>\n";
	ret += tab + "</extension>\n";
	return ret;
}

std::string Extension::extValue2Xml(std::string tab)
{
	return tab + "<base64Value>\n" +  tab + "\t" + this->getBase64Value() + "\n" + tab + "</base64Value>\n";
}

std::string Extension::getXmlEncoded()
{
	return this->getXmlEncoded("");
}

std::string Extension::getXmlEncoded(std::string tab)
{
	std::string ret, critical;
	ret = tab + "<extension>\n";
		ret += tab + "\t<extnID>"+ this->getName() +"</extnID>\n";
		critical = (this->isCritical())?"yes":"no";
		ret += tab + "\t<critical>"+ critical +"</critical>\n";
		ret += tab + "\t<extnValue>"+ this->getBase64Value() +"</extnValue>\n";
	ret += tab + "</extension>\n";
	return ret;
}

ObjectIdentifier Extension::getObjectIdentifier() const
{
	return this->objectIdentifier;
}

std::string Extension::getName()
{
	return this->objectIdentifier.getName();
}

Extension::Name Extension::getTypeName()
{
	return Extension::getName(this->objectIdentifier.getNid());
}

ByteArray Extension::getValue() const
{
	return this->value; 
}

std::string Extension::getBase64Value()
{
	return Base64::encode(this->value);
}

bool Extension::isCritical() const
{
	return this->critical;
}

void Extension::setCritical(bool critical)
{
	this->critical = critical;
}

X509_EXTENSION* Extension::getX509Extension()
{
	X509_EXTENSION *ret;
	ByteArray data;
	ret = X509_EXTENSION_new();
	ret->object = OBJ_dup(this->objectIdentifier.getObjectIdentifier());
	ret->critical = this->critical?1:0;
	ret->value = ASN1_OCTET_STRING_new();
	data = this->value;
	ASN1_OCTET_STRING_set(ret->value, data.getDataPointer(), this->value.size());
	return ret;
}

Extension::Name Extension::getName(int nid)
{
	Extension::Name ret;
	switch (nid)
	{
		case NID_key_usage:
			ret = Extension::KEY_USAGE;
			break;
		case NID_ext_key_usage:
			ret = Extension::EXTENDED_KEY_USAGE;
			break;
		case NID_authority_key_identifier:
			ret = Extension::AUTHORITY_KEY_IDENTIFIER;
			break;
		case NID_crl_distribution_points:
			ret = Extension::CRL_DISTRIBUTION_POINTS;
			break;
		case NID_info_access:
			ret = Extension::AUTHORITY_INFORMATION_ACCESS;
			break;
		case NID_basic_constraints:
			ret = Extension::BASIC_CONSTRAINTS;
			break;
		case NID_certificate_policies:
			ret = Extension::CERTIFICATE_POLICIES;
			break;
		case NID_issuer_alt_name:
			ret = Extension::ISSUER_ALTERNATIVE_NAME;
			break;
		case NID_subject_alt_name:
			ret = Extension::SUBJECT_ALTERNATIVE_NAME;
			break;
		case NID_sinfo_access:
			ret = Extension::SUBJECT_INFORMATION_ACCESS;
			break;
		case NID_subject_key_identifier:
			ret = Extension::SUBJECT_KEY_IDENTIFIER;
			break;
		case NID_crl_number:
			ret = Extension::CRL_NUMBER;
			break;
		case NID_delta_crl:
			ret = Extension::DELTA_CRL_INDICATOR;
			break;			
		default:
			ret = Extension::UNKNOWN;
	}
	return ret;
}

Extension::Name Extension::getName(X509_EXTENSION *ext)
{
	int nid;
	nid = OBJ_obj2nid(ext->object);
	return Extension::getName(nid);
}
