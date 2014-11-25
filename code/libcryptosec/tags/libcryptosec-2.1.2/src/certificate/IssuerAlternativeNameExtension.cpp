#include <libcryptosec/certificate/IssuerAlternativeNameExtension.h>

IssuerAlternativeNameExtension::IssuerAlternativeNameExtension() : Extension()
{
	this->objectIdentifier = ObjectIdentifierFactory::getObjectIdentifier(NID_issuer_alt_name);
}

IssuerAlternativeNameExtension::IssuerAlternativeNameExtension(X509_EXTENSION *ext)
		throw (CertificationException) : Extension(ext)
{
	GENERAL_NAMES *generalNames;
	if (OBJ_obj2nid(ext->object) != NID_issuer_alt_name)
	{
		throw CertificationException(CertificationException::INVALID_TYPE, "IssuerAlternativeNameExtension::IssuerAlternativeNameExtension");
	}
	generalNames = (GENERAL_NAMES *)X509V3_EXT_d2i(ext);
	this->issuerAltName = GeneralNames(generalNames);
	sk_GENERAL_NAME_free(generalNames);
}

IssuerAlternativeNameExtension::~IssuerAlternativeNameExtension()
{
}

std::string IssuerAlternativeNameExtension::extValue2Xml(std::string tab)
{	
	return this->issuerAltName.getXmlEncoded(tab);
}

std::string IssuerAlternativeNameExtension::getXmlEncoded()
{
	return this->getXmlEncoded("");
}

std::string IssuerAlternativeNameExtension::getXmlEncoded(std::string tab)
{
	std::string ret, string;
	ret = tab + "<issuerAlternativeName>\n";
		ret += tab + "\t<extnID>" + this->getName() + "</extnID>\n";
		string = (this->critical)?"yes":"no";
		ret += tab + "\t<critical>" + string + "</critical>\n";
		ret += tab + "\t<extnValue>\n";


			ret += this->issuerAltName.getXmlEncoded(tab + "\t\t");

		ret += tab + "\t</extnValue>\n";
	ret += tab + "</issuerAlternativeName>\n";
	return ret;
}

void IssuerAlternativeNameExtension::setIssuerAltName(GeneralNames &generalNames)
{
	this->issuerAltName = generalNames;
}

GeneralNames IssuerAlternativeNameExtension::getIssuerAltName()
{
	return this->issuerAltName;
}

X509_EXTENSION* IssuerAlternativeNameExtension::getX509Extension()
{
	X509_EXTENSION *ret;
	GENERAL_NAMES *generalNames;
	generalNames = this->issuerAltName.getInternalGeneralNames();
	ret = X509V3_EXT_i2d(NID_issuer_alt_name, this->critical?1:0, (void *)generalNames);
	sk_GENERAL_NAME_free(generalNames);
	return ret;
}
