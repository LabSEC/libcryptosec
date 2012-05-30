#ifndef CRLDISTRIBUTIONPOINTSEXTENSION_H_
#define CRLDISTRIBUTIONPOINTSEXTENSION_H_

#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "Extension.h"
#include "DistributionPoint.h"

#include <libcryptosec/exception/CertificationException.h>

class CRLDistributionPointsExtension : public Extension
{
public:
	CRLDistributionPointsExtension();
	CRLDistributionPointsExtension(X509_EXTENSION *ext) throw (CertificationException);
	virtual ~CRLDistributionPointsExtension();
	
	/**
	 * @deprecated
	 * Retorna o conteudo da extensão em formato XML.
	 * Esta função será substituida por toXml().
	 * */
	std::string getXmlEncoded();
	std::string getXmlEncoded(std::string tab);
	virtual std::string extValue2Xml(std::string tab = "");
	void addDistributionPoint(DistributionPoint &distributionPoint);
	std::vector<DistributionPoint> getDistributionPoints();
	X509_EXTENSION* getX509Extension();
protected:
	std::vector<DistributionPoint> distributionPoints;
};

#endif /*CRLDISTRIBUTIONPOINTSEXTENSION_H_*/
