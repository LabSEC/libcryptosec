#ifndef AUTHORITYINFORMATIONACCESSEXTENSION_H_
#define AUTHORITYINFORMATIONACCESSEXTENSION_H_

#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "Extension.h"
#include "AccessDescription.h"

#include <libcryptosec/exception/CertificationException.h>


class AuthorityInformationAccessExtension : public Extension {
public:
	enum AccessMethod
	{
		CA_ISSUER = NID_ad_ca_issuers,
		OCSP = NID_ad_OCSP,
	};
	AuthorityInformationAccessExtension();
	AuthorityInformationAccessExtension(X509_EXTENSION *ext) throw (CertificationException);
	virtual ~AuthorityInformationAccessExtension();
	X509_EXTENSION* getX509Extension();
	void addAccessDescription(AccessDescription& accessDescription);
	std::vector<AccessDescription> getAccessDescriptions();
	/**
	 * @deprecated
	 * Retorna o conteudo da extensão em formato XML.
	 * Esta função será substituida por toXml().
	 * */
	std::string getXmlEncoded();
	std::string getXmlEncoded(std::string tab);
	virtual std::string extValue2Xml(std::string tab = "");
protected:
	std::vector<AccessDescription> accessDescriptions;
};

#endif /* AUTHORITYINFORMATIONACCESSEXTENSION_H_ */
