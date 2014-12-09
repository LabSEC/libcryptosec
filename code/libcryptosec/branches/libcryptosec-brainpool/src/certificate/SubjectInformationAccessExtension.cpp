#include "libcryptosec/certificate/SubjectInformationAccessExtension.h"

SubjectInformationAccessExtension::SubjectInformationAccessExtension() : Extension() {
	this->objectIdentifier = ObjectIdentifierFactory::getObjectIdentifier(NID_sinfo_access);
}

SubjectInformationAccessExtension::SubjectInformationAccessExtension(X509_EXTENSION *ext)
		throw (CertificationException) : Extension(ext)
{
	STACK_OF(ACCESS_DESCRIPTION) *subjectInfoAccess;
	AccessDescription accessDescription;

	if (OBJ_obj2nid(ext->object) != NID_sinfo_access)
	{
		throw CertificationException(CertificationException::INVALID_TYPE, "SubjectInformationAccessExtension::SubjectInformationAccessExtension");
	}
	int i, num = 0;
	subjectInfoAccess = (STACK_OF(ACCESS_DESCRIPTION) *)X509V3_EXT_d2i(ext);
	num = sk_ACCESS_DESCRIPTION_num(subjectInfoAccess);
	for (i=0;i<num;i++)
	{
		accessDescription = AccessDescription((ACCESS_DESCRIPTION *)sk_ACCESS_DESCRIPTION_value(subjectInfoAccess, i));
		this->accessDescriptions.push_back(accessDescription);
	}
	sk_ACCESS_DESCRIPTION_free(subjectInfoAccess);
}

SubjectInformationAccessExtension::~SubjectInformationAccessExtension() {
}

X509_EXTENSION* SubjectInformationAccessExtension::getX509Extension() {
	X509_EXTENSION *ret;
	STACK_OF(ACCESS_DESCRIPTION) *subjectInfoAccess;

	subjectInfoAccess = sk_ACCESS_DESCRIPTION_new_null();
	unsigned int i;
	for (i=0;i<this->accessDescriptions.size();i++)
	{
		sk_ACCESS_DESCRIPTION_push(subjectInfoAccess, this->accessDescriptions.at(i).getAccessDescription());
	}
	ret = X509V3_EXT_i2d(NID_sinfo_access, this->critical?1:0, (void *)subjectInfoAccess);
	sk_ACCESS_DESCRIPTION_free(subjectInfoAccess);
	return ret;
}

void SubjectInformationAccessExtension::addAccessDescription(AccessDescription& accessDescription) {
	accessDescriptions.push_back(accessDescription);
}

std::vector<AccessDescription> SubjectInformationAccessExtension::getAccessDescriptions() {
	return accessDescriptions;
}


std::string SubjectInformationAccessExtension::extValue2Xml(std::string tab)
{
	std::string ret, string;
	unsigned int i;

	ret = tab + "<accessDescriptions>\n";
	for (i=0;i<this->accessDescriptions.size();i++)
	{
		string = this->accessDescriptions.at(i).getXmlEncoded(tab + "\t");
		ret += string;
	}
	ret += tab + "</accessDescriptions>\n";

	return ret;
}

std::string SubjectInformationAccessExtension::getXmlEncoded()
{
	return this->getXmlEncoded("");
}

std::string SubjectInformationAccessExtension::getXmlEncoded(std::string tab)
{
	std::string ret, string;
	unsigned int i;

	ret = tab + "<subjectInformationAccess>\n";
		ret += tab + "\t<extnID>" + this->getName() + "</extnID>\n";
		string = (this->isCritical())?"yes":"no";
		ret += tab + "\t<critical>" + string + "</critical>\n";
		ret += tab + "\t<extnValue>\n";
			ret += tab + "\t\t<accessDescriptions>\n";

			for (i=0;i<this->accessDescriptions.size();i++)
			{
				string = this->accessDescriptions.at(i).getXmlEncoded(tab + "\t\t\t");
				ret += string;
			}

			ret += tab + "\t\t</accessDescriptions>\n";
		ret += tab + "\t</extnValue>\n";
	ret += tab + "</subjectInformationAccess>\n";
	return ret;
}
