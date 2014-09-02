#include <libcryptosec/certificate/AccessDescription.h>

AccessDescription::AccessDescription() {
}

AccessDescription::AccessDescription(ACCESS_DESCRIPTION *accessDescription) {
	if(accessDescription->method) {
		accessMethod = ObjectIdentifier(OBJ_dup(accessDescription->method));
	}
	if(accessDescription->location) {
		accessLocation = GeneralName(accessDescription->location);
	}
}

ACCESS_DESCRIPTION* AccessDescription::getAccessDescription() {
	ACCESS_DESCRIPTION* accessDescription = ACCESS_DESCRIPTION_new();

	accessDescription->method = accessMethod.getObjectIdentifier();
	accessDescription->location = accessLocation.getGeneralName();

	return accessDescription;
}

GeneralName AccessDescription::getAccessLocation()
{
    return accessLocation;
}

ObjectIdentifier AccessDescription::getAccessMethod()
{
    return accessMethod;
}

void AccessDescription::setAccessLocation(GeneralName accessLocation)
{
    this->accessLocation = accessLocation;
}

void AccessDescription::setAccessMethod(ObjectIdentifier accessMethod)
{
    this->accessMethod = accessMethod;
}

std::string AccessDescription::getXmlEncoded()
{
	return this->getXmlEncoded("");
}

std::string AccessDescription::getXmlEncoded(std::string tab)
{
	std::string ret;
	ret = tab + "<accessDescription>\n";
	ret += this->accessMethod.getXmlEncoded(tab + "\t");
	ret += this->accessLocation.getXmlEncoded(tab + "\t");
	ret += tab + "</accessDescription>\n";
	return ret;
}

AccessDescription::~AccessDescription() {
}
