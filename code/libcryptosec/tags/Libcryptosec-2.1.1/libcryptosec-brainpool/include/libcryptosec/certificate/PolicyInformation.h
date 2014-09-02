#ifndef POLICYINFORMATION_H_
#define POLICYINFORMATION_H_

#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <vector>
#include <string>

#include "ObjectIdentifier.h"
#include "PolicyQualifierInfo.h"

#include <libcryptosec/exception/CertificationException.h>

class PolicyInformation
{
public:
	PolicyInformation();
	PolicyInformation(POLICYINFO *policyInfo);
	virtual ~PolicyInformation();
	std::string getXmlEncoded();
	std::string getXmlEncoded(std::string tab);
	void setPolicyIdentifier(ObjectIdentifier policyIdentifier);
	ObjectIdentifier getPolicyIdentifier();
	void addPolicyQualifierInfo(PolicyQualifierInfo &policyQualifierInfo);
	std::vector<PolicyQualifierInfo> getPoliciesQualifierInfo();
	POLICYINFO* getPolicyInfo() const;
protected:
	ObjectIdentifier policyIdentifier;
	std::vector<PolicyQualifierInfo> policyQualifiers; 
};

#endif /*POLICYINFORMATION_H_*/
