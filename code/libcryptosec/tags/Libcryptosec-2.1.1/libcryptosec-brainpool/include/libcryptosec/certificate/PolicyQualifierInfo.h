#ifndef POLICYQUALIFIERINFO_H_
#define POLICYQUALIFIERINFO_H_

#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <string>

#include "ObjectIdentifier.h"
#include "ObjectIdentifierFactory.h"
#include "UserNotice.h"

#include <libcryptosec/exception/CertificationException.h>

class PolicyQualifierInfo
{
public:
	enum Type
	{
		UNDEFINED,
		CPS_URI,
		USER_NOTICE,
	};
	PolicyQualifierInfo();
	PolicyQualifierInfo(POLICYQUALINFO *policyQualInfo);
	virtual ~PolicyQualifierInfo();
	std::string getXmlEncoded();
	std::string getXmlEncoded(std::string tab);
	ObjectIdentifier getObjectIdentifier();
	void setCpsUri(std::string cpsUri);
	std::string getCpsUri();
	void setUserNotice(UserNotice userNotice);
	UserNotice getUserNotice();
	PolicyQualifierInfo::Type getType();
	POLICYQUALINFO* getPolicyQualInfo() const;
protected:
	PolicyQualifierInfo::Type type;
	ObjectIdentifier objectIdentifier;
	UserNotice userNotice;
	std::string cpsUri;
	
	void setObjectIdentifier(ObjectIdentifier objectIdentifier);
};

#endif /*POLICYQUALIFIERINFO_H_*/
