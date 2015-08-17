#include "libcryptosec/certificate/AuthorityInformationAccessExtension.h"

AuthorityInformationAccessExtension::AuthorityInformationAccessExtension() : Extension() {
	this->objectIdentifier = ObjectIdentifierFactory::getObjectIdentifier(NID_info_access);
}

AuthorityInformationAccessExtension::AuthorityInformationAccessExtension(X509_EXTENSION *ext)
		throw (CertificationException) : Extension(ext)
{
	AUTHORITY_INFO_ACCESS *authorityInfoAccess;
	AccessDescription accessDescription;

	if (OBJ_obj2nid(ext->object) != NID_info_access)
	{
		throw CertificationException(CertificationException::INVALID_TYPE, "AuthorityInformationAccessExtension::AuthorityInformationAccessExtension");
	}
	int i, num = 0;
	authorityInfoAccess = (AUTHORITY_INFO_ACCESS *)X509V3_EXT_d2i(ext);
	num = sk_ACCESS_DESCRIPTION_num(authorityInfoAccess);
	for (i=0;i<num;i++)
	{
		accessDescription = AccessDescription((ACCESS_DESCRIPTION *)sk_ACCESS_DESCRIPTION_value(authorityInfoAccess, i));
		this->accessDescriptions.push_back(accessDescription);
	}
	AUTHORITY_INFO_ACCESS_free(authorityInfoAccess);
}

X509_EXTENSION* AuthorityInformationAccessExtension::getX509Extension() {
	X509_EXTENSION *ret;
	AUTHORITY_INFO_ACCESS *authorityInfoAccess;

	authorityInfoAccess = AUTHORITY_INFO_ACCESS_new();
	unsigned int i;
	for (i=0;i<this->accessDescriptions.size();i++)
	{
		sk_ACCESS_DESCRIPTION_push(authorityInfoAccess, this->accessDescriptions.at(i).getAccessDescription());
	}
	ret = X509V3_EXT_i2d(NID_info_access, this->critical?1:0, (void *)authorityInfoAccess);
	AUTHORITY_INFO_ACCESS_free(authorityInfoAccess);
	return ret;
}

void AuthorityInformationAccessExtension::addAccessDescription(AccessDescription& accessDescription) {
	accessDescriptions.push_back(accessDescription);
}

std::vector<AccessDescription> AuthorityInformationAccessExtension::getAccessDescriptions() {
	return accessDescriptions;
}


std::string AuthorityInformationAccessExtension::extValue2Xml(std::string tab)
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

std::string AuthorityInformationAccessExtension::getXmlEncoded()
{
	return this->getXmlEncoded("");
}

std::string AuthorityInformationAccessExtension::getXmlEncoded(std::string tab)
{
	std::string ret, string;
	unsigned int i;

	ret = tab + "<authorityInformationAccess>\n";
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
	ret += tab + "</authorityInformationAccess>\n";
	return ret;
}


AuthorityInformationAccessExtension::~AuthorityInformationAccessExtension() {
}
