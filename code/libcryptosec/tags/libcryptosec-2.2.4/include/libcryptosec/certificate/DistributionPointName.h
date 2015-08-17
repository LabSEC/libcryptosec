#ifndef DISTRIBUTIONPOINTNAME_H_
#define DISTRIBUTIONPOINTNAME_H_

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "GeneralNames.h"
#include "RDNSequence.h"

#include <libcryptosec/exception/CertificationException.h>

class DistributionPointName
{
public:
	enum Type
	{
		UNDEFINED,
		FULL_NAME,
		RELATIVE_NAME,
	};
	DistributionPointName();
	DistributionPointName(DIST_POINT_NAME *dpn);
	virtual ~DistributionPointName();
	std::string getXmlEncoded();
	std::string getXmlEncoded(std::string tab);
	void setNameRelativeToCrlIssuer(RDNSequence &rdnSequence);
	RDNSequence getNameRelativeToCrlIssuer();
	void setFullName(GeneralNames &generalNames);
	GeneralNames getFullName();
	DistributionPointName::Type getType() const;
	DIST_POINT_NAME* getDistPointName();
protected:
	GeneralNames fullName;
	RDNSequence relativeName;
	DistributionPointName::Type type;
};

#endif /*DISTRIBUTIONPOINTNAME_H_*/
