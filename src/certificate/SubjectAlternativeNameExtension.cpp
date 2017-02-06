#include <libcryptosec/certificate/SubjectAlternativeNameExtension.h>

SubjectAlternativeNameExtension::SubjectAlternativeNameExtension() : Extension()
{
	this->objectIdentifier = ObjectIdentifierFactory::getObjectIdentifier(NID_subject_alt_name);
}

SubjectAlternativeNameExtension::SubjectAlternativeNameExtension(X509_EXTENSION *ext)
		throw (CertificationException) : Extension(ext)
{
	GENERAL_NAMES *generalNames;
	if (OBJ_obj2nid(X509_EXTENSION_get_object(ext)) != NID_subject_alt_name)
	{
		throw CertificationException(CertificationException::INVALID_TYPE, "SubjectAlternativeNameExtension::SubjectAlternativeNameExtension");
	}
	generalNames = (GENERAL_NAMES *)X509V3_EXT_d2i(ext);
	this->subjectAltName = GeneralNames(generalNames);
	sk_GENERAL_NAME_pop_free(generalNames, GENERAL_NAME_free);
}

SubjectAlternativeNameExtension::~SubjectAlternativeNameExtension()
{
}

std::string SubjectAlternativeNameExtension::extValue2Xml(std::string tab)
{
	return this->subjectAltName.getXmlEncoded(tab);
}

std::string SubjectAlternativeNameExtension::getXmlEncoded()
{
	return this->getXmlEncoded("");
}

std::string SubjectAlternativeNameExtension::getXmlEncoded(std::string tab)
{
	std::string ret, string;
	ret = tab + "<subjectAlternativeName>\n";
		ret += tab + "\t<extnID>" + this->getName() + "</extnID>\n";
		string = (this->critical)?"yes":"no";
		ret += tab + "\t<critical>" + string + "</critical>\n";
		ret += tab + "\t<extnValue>\n";
		
			ret += this->subjectAltName.getXmlEncoded(tab + "\t\t");
		ret += tab + "\t</extnValue>\n";
	ret += tab + "</subjectAlternativeName>\n";
	return ret;
}

void SubjectAlternativeNameExtension::setSubjectAltName(GeneralNames &generalNames)
{
	this->subjectAltName = generalNames;
}

GeneralNames SubjectAlternativeNameExtension::getSubjectAltName()
{
	return this->subjectAltName;
}

X509_EXTENSION* SubjectAlternativeNameExtension::getX509Extension()
{
	X509_EXTENSION *ret;
	GENERAL_NAMES *generalNames;
	generalNames = this->subjectAltName.getInternalGeneralNames();
	ret = X509V3_EXT_i2d(NID_subject_alt_name, this->critical?1:0, (void *)generalNames);
	sk_GENERAL_NAME_pop_free(generalNames, GENERAL_NAME_free);
	return ret;
}
