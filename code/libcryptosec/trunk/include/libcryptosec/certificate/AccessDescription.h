#ifndef ACCESSDESCRIPTION_H_
#define ACCESSDESCRIPTION_H_

#include <openssl/x509v3.h>
#include <libcryptosec/certificate/ObjectIdentifier.h>
#include <libcryptosec/certificate/GeneralName.h>

class AccessDescription {
public:
	AccessDescription();
	AccessDescription(ACCESS_DESCRIPTION *accessDescription);
	virtual ~AccessDescription();
	ACCESS_DESCRIPTION* getAccessDescription();
	GeneralName getAccessLocation();
	ObjectIdentifier getAccessMethod();
	void setAccessLocation(GeneralName accessLocation);
	void setAccessMethod(ObjectIdentifier accessMethod);
	std::string getXmlEncoded();
	std::string getXmlEncoded(std::string tab);
private:
	ObjectIdentifier accessMethod;
	GeneralName accessLocation;
};

#endif /* ACCESSDESCRIPTION_H_ */
