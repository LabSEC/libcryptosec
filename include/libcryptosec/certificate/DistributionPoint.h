#ifndef DISTRIBUTIONPOINT_H_
#define DISTRIBUTIONPOINT_H_

#include "GeneralNames.h"
#include "DistributionPointName.h"

class DistributionPoint
{
public:
	enum ReasonFlags
	{
		UNUSED = 0,
		KEY_COMPROMISE = 1,
		CA_COMPROMISE = 2,
		AFFILIATION_CHANGED = 3,
		SUPERSEDED = 4,
		CESSATION_OF_OPERATION = 5,
		CERTIFICATE_HOLD = 6,
	};
	DistributionPoint();
	DistributionPoint(DIST_POINT *distPoint);
	virtual ~DistributionPoint();
	std::string getXmlEncoded();
	std::string getXmlEncoded(std::string tab);
	void setDistributionPointName(DistributionPointName &dpn);
	DistributionPointName getDistributionPointName();
	void setReasonFlag(DistributionPoint::ReasonFlags reason, bool value);
	bool getReasonFlag(DistributionPoint::ReasonFlags reason);
	void setCrlIssuer(GeneralNames &crlIssuer);
	GeneralNames getCrlIssuer();
	DIST_POINT* getDistPoint();
	static std::string reasonFlag2Name(DistributionPoint::ReasonFlags reason);
protected:
	DistributionPointName distributionPointName;
	bool reasons[7];
	GeneralNames crlIssuer;
};

#endif /*DISTRIBUTIONPOINT_H_*/
