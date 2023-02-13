#include <libcryptosec/certificate/PolicyInformation.h>

PolicyInformation::PolicyInformation()
{
}

PolicyInformation::PolicyInformation(POLICYINFO *policyInfo)
{
	int i, num;
	PolicyQualifierInfo policyQualifierInfo;
	if (policyInfo)
	{
		this->policyIdentifier = ObjectIdentifier(OBJ_dup(policyInfo->policyid));
		num = sk_POLICYQUALINFO_num(policyInfo->qualifiers);
		for (i=0;i<num;i++)
		{
			policyQualifierInfo = PolicyQualifierInfo(sk_POLICYQUALINFO_value(policyInfo->qualifiers, i));
			this->policyQualifiers.push_back(policyQualifierInfo);
		}
	}
}

PolicyInformation::~PolicyInformation()
{
}

std::string PolicyInformation::getXmlEncoded()
{
	return this->getXmlEncoded("");
}

std::string PolicyInformation::getXmlEncoded(std::string tab)
{
	std::string ret;
	unsigned int i;
	
	ret = tab + "<policyInformation>\n";
	ret += this->policyIdentifier.getXmlEncoded(tab + "\t");
	for (i=0;i<this->policyQualifiers.size();i++)
	{
		ret += (this->policyQualifiers.at(i)).getXmlEncoded(tab + "\t");
	}
	ret += tab + "</policyInformation>\n";
	return ret;
}

void PolicyInformation::setPolicyIdentifier(ObjectIdentifier policyIdentifier)
{
	this->policyIdentifier = policyIdentifier;
}

ObjectIdentifier PolicyInformation::getPolicyIdentifier()
{
	return this->policyIdentifier;
}

void PolicyInformation::addPolicyQualifierInfo(PolicyQualifierInfo &policyQualifierInfo)
{
	this->policyQualifiers.push_back(policyQualifierInfo);
}

std::vector<PolicyQualifierInfo> PolicyInformation::getPoliciesQualifierInfo()
{
	return this->policyQualifiers;
}

POLICYINFO* PolicyInformation::getPolicyInfo() const
{
	POLICYINFO *ret;
	unsigned int i;
	POLICYQUALINFO *policyQualInfo;
	ret = POLICYINFO_new();
	ret->policyid = OBJ_dup(this->policyIdentifier.getObjectIdentifier());

	if (this->policyQualifiers.size())
	{
		ret->qualifiers = sk_POLICYQUALINFO_new_null();
		for (i=0;i<this->policyQualifiers.size();i++)
		{
			policyQualInfo = this->policyQualifiers.at(i).getPolicyQualInfo();
			sk_POLICYQUALINFO_push(ret->qualifiers, policyQualInfo);
		}
	}

	return ret;
}
