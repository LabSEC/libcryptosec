#ifndef CERTIFICATEPOLICIESEXTENSION_H_
#define CERTIFICATEPOLICIESEXTENSION_H_

#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <vector>

#include "Extension.h"
#include "PolicyInformation.h"

#include <libcryptosec/exception/CertificationException.h>

class CertificatePoliciesExtension : public Extension
{
public:
	CertificatePoliciesExtension();
	CertificatePoliciesExtension(X509_EXTENSION *ext) throw (CertificationException);
	virtual ~CertificatePoliciesExtension();
	
	/**
	 * @deprecated
	 * Retorna o conteudo da extensão em formato XML.
	 * Esta função será substituida por toXml().
	 * */
	std::string getXmlEncoded();
	std::string getXmlEncoded(std::string tab);
	virtual std::string extValue2Xml(std::string tab = "");
	void addPolicyInformation(PolicyInformation &policyInformation);
	std::vector<PolicyInformation> getPoliciesInformation();
	X509_EXTENSION* getX509Extension();
protected:
	std::vector<PolicyInformation> policiesInformation;
};

#endif /*CERTIFICATEPOLICIESEXTENSION_H_*/
