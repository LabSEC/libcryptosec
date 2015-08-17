#include <libcryptosec/certificate/CertificatePoliciesExtension.h>

CertificatePoliciesExtension::CertificatePoliciesExtension() : Extension()
{
	this->objectIdentifier = ObjectIdentifierFactory::getObjectIdentifier(NID_certificate_policies);
}

CertificatePoliciesExtension::CertificatePoliciesExtension(X509_EXTENSION *ext)
		throw (CertificationException) : Extension(ext)
{
	CERTIFICATEPOLICIES *certificatePolicies;
	PolicyInformation policyInformation;
	int i, num;
	if (OBJ_obj2nid(ext->object) != NID_certificate_policies)
	{
		throw CertificationException(CertificationException::INVALID_TYPE, "CertificatePoliciesExtension::CertificatePoliciesExtension");
	}
	certificatePolicies = (CERTIFICATEPOLICIES *)X509V3_EXT_d2i(ext);
	num = sk_POLICYINFO_num(certificatePolicies);
	for (i=0;i<num;i++)
	{
		policyInformation = PolicyInformation(sk_POLICYINFO_value(certificatePolicies, i));
		this->policiesInformation.push_back(policyInformation);
	}
	CERTIFICATEPOLICIES_free(certificatePolicies);
}

CertificatePoliciesExtension::~CertificatePoliciesExtension()
{
}

std::string CertificatePoliciesExtension::extValue2Xml(std::string tab)
{
	unsigned int i;
	std::string ret, string;
	
	for (i=0;i<this->policiesInformation.size();i++)
	{
		ret += (this->policiesInformation.at(i)).getXmlEncoded(tab);
	}

	return ret;
}

std::string CertificatePoliciesExtension::getXmlEncoded()
{
	return this->getXmlEncoded("");
}

std::string CertificatePoliciesExtension::getXmlEncoded(std::string tab)
{
	unsigned int i;
	std::string ret, string;
	ret = tab + "<certificatePolicies>\n";
		ret += tab + "\t<extnID>" + this->getName() + "</extnID>\n";
		string = (this->isCritical())?"yes":"no";
		ret += tab + "\t<critical>" + string + "</critical>\n";
		ret += tab + "\t<extnValue>\n";
			for (i=0;i<this->policiesInformation.size();i++)
			{
				ret += (this->policiesInformation.at(i)).getXmlEncoded(tab + "\t\t");
			}
		ret += tab + "\t</extnValue>\n";
	ret += tab + "</certificatePolicies>\n";
	return ret;
}

void CertificatePoliciesExtension::addPolicyInformation(PolicyInformation &policyInformation)
{
	this->policiesInformation.push_back(policyInformation);
}

std::vector<PolicyInformation> CertificatePoliciesExtension::getPoliciesInformation()
{
	return this->policiesInformation;
}

X509_EXTENSION* CertificatePoliciesExtension::getX509Extension()
{
	X509_EXTENSION *ret;
	CERTIFICATEPOLICIES *certificatePolicies;
//	POLICYINFO *policyInformation;
	unsigned int i;
	certificatePolicies = CERTIFICATEPOLICIES_new();
	for (i=0;i<this->policiesInformation.size();i++)
	{
		sk_POLICYINFO_push(certificatePolicies, this->policiesInformation.at(i).getPolicyInfo());
	}
	ret = X509V3_EXT_i2d(NID_certificate_policies, this->critical?1:0, (void *)certificatePolicies);
//	for (i=0;i<this->policiesInformation.size();i++)
//	{
//		policyInformation = sk_POLICYINFO_value(certificatePolicies, i);
//		sk_POLICYINFO_pop_free(policyInformation->qualifiers, POLICYQUALINFO_free);
//		policyInformation->qualifiers = NULL;
//	}
	sk_POLICYINFO_pop_free(certificatePolicies, POLICYINFO_free);
	return ret;
}
