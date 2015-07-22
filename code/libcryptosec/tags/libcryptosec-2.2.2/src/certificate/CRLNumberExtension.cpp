#include <libcryptosec/certificate/CRLNumberExtension.h>

CRLNumberExtension::CRLNumberExtension(unsigned long serial=0) : Extension() 
{
	this->serial = serial;
    this->objectIdentifier = ObjectIdentifierFactory::getObjectIdentifier(NID_crl_number);
}

CRLNumberExtension::CRLNumberExtension(X509_EXTENSION* ext) throw (CertificationException) : Extension(ext)
{
	ASN1_INTEGER* serialAsn1 = NULL;
	
	if (OBJ_obj2nid(ext->object) != NID_crl_number)
	{
		X509_EXTENSION_free(ext);
		throw CertificationException(CertificationException::INVALID_TYPE, "CRLNumberExtension::CRLNumberExtension");
	}
	serialAsn1 = (ASN1_INTEGER *)X509V3_EXT_d2i(ext);
	
	if(!serialAsn1)
	{	
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CRLNumberExtension::CRLNumberExtension");
	}
	
	this->serial = ASN1_INTEGER_get(serialAsn1);
	ASN1_INTEGER_free(serialAsn1);
}

CRLNumberExtension::~CRLNumberExtension()
{
}

std::string CRLNumberExtension::getXmlEncoded()
{
	return this->getXmlEncoded("");
}

//TODO testar!
std::string CRLNumberExtension::extValue2Xml(std::string tab)
{
	stringstream s;
	std::string ret, string, serial;
		
	s << this->serial;
	serial = s.str();
	
	ret += tab + "\t<crlNumber>" + serial + "</crlNumber>\n";

	return ret;
}

//TODO: metodo nunca invocado
std::string CRLNumberExtension::getXmlEncoded(std::string tab)
{
	stringstream s;
	std::string ret, string, serial;
		
	s << this->serial;
	serial = s.str();
	
	ret = tab + "<crlNumber>\n";
		ret += tab + "\t<extnID>" + this->getName() + "</extnID>\n";
		string = (this->isCritical())?"yes":"no";
		ret += tab + "\t<critical>" + string + "</critical>\n";
		ret += tab + "\t<extnValue>\n";
			ret += tab + "\t\t<crlNumber>" + serial + "</crlNumber>\n";
			ret += tab + "\t</extnValue>\n";
	ret += tab + "</crlNumber>\n";
	return ret;
}

void CRLNumberExtension::setSerial(unsigned long serial)
{
	this->serial = serial;
}

//TODO
const long CRLNumberExtension::getSerial() const
{
	return this->serial;
}

//TODO
X509_EXTENSION* CRLNumberExtension::getX509Extension()
{
	return 0;
}
