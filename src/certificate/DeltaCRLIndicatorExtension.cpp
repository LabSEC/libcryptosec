#include <libcryptosec/certificate/DeltaCRLIndicatorExtension.h>

DeltaCRLIndicatorExtension::DeltaCRLIndicatorExtension(unsigned long baseCrlNumber=0) : Extension() 
{
	this->baseCrlNumber = baseCrlNumber;
    this->objectIdentifier = ObjectIdentifierFactory::getObjectIdentifier(NID_delta_crl);
}

DeltaCRLIndicatorExtension::DeltaCRLIndicatorExtension(X509_EXTENSION* ext) throw (CertificationException) : Extension(ext)
{
	ASN1_INTEGER* serialAsn1 = NULL;
	
	if (OBJ_obj2nid(ext->object) != NID_delta_crl)
	{
		X509_EXTENSION_free(ext);
		throw CertificationException(CertificationException::INVALID_TYPE, "DeltaCRLIndicatorExtension::DeltaCRLIndicatorExtension");
	}
	serialAsn1 = (ASN1_INTEGER *)X509V3_EXT_d2i(ext);
	
	if(!serialAsn1)
	{	
		throw CertificationException(CertificationException::INTERNAL_ERROR, "DeltaCRLIndicatorExtension::DeltaCRLIndicatorExtension");
	}
	
	this->baseCrlNumber = ASN1_INTEGER_get(serialAsn1);
	ASN1_INTEGER_free(serialAsn1);
}

DeltaCRLIndicatorExtension::~DeltaCRLIndicatorExtension()
{
	
}

std::string DeltaCRLIndicatorExtension::getXmlEncoded()
{
	return this->getXmlEncoded("");
}


std::string DeltaCRLIndicatorExtension::extValue2Xml(std::string tab)
{
	stringstream s;
	std::string ret, string, baseCrlNumber;
		
	s << this->baseCrlNumber;
	baseCrlNumber = s.str();
	
	ret += tab + "\t<baseCRLNumber>" + baseCrlNumber + "</baseCRLNumber>\n";

	return ret;
}


std::string DeltaCRLIndicatorExtension::getXmlEncoded(std::string tab)
{
	stringstream s;	
	std::string ret, string, baseCrlNumber;
		
	s << this->baseCrlNumber;
	baseCrlNumber = s.str();
	
	ret = tab + "<deltaCRLIndicator>\n";
	ret += tab + "\t<extnID>" + this->getName() + "</extnID>\n";
	string = (this->isCritical())?"yes":"no";
	ret += tab + "\t<critical>" + string + "</critical>\n";
	ret += tab + "\t<extnValue>\n";
	ret += tab + "\t\t<baseCRLNumber>" + baseCrlNumber + "</baseCRLNumber>\n";
	ret += tab + "\t</extnValue>\n";
	ret += tab + "</deltaCRLIndicator>\n";
	return ret;
}

void DeltaCRLIndicatorExtension::setSerial(unsigned long baseCrlNumber)
{
	this->baseCrlNumber = baseCrlNumber;
}


const long DeltaCRLIndicatorExtension::getSerial() const
{
	return this->baseCrlNumber;
}


X509_EXTENSION* DeltaCRLIndicatorExtension::getX509Extension()
{
	X509_EXTENSION *ret;
	ASN1_INTEGER* baseCrlNumber;
	
	ret = X509_EXTENSION_new();

	int rc;
	baseCrlNumber = ASN1_INTEGER_new();
	ASN1_INTEGER_set(baseCrlNumber, this->baseCrlNumber);
	
	ret = X509V3_EXT_i2d(NID_delta_crl, this->critical?1:0, (void *)baseCrlNumber);
	return ret;
}