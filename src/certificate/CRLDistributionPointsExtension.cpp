#include <libcryptosec/certificate/CRLDistributionPointsExtension.h>

CRLDistributionPointsExtension::CRLDistributionPointsExtension() : Extension()
{
	this->objectIdentifier = ObjectIdentifierFactory::getObjectIdentifier(NID_crl_distribution_points);
}

CRLDistributionPointsExtension::CRLDistributionPointsExtension(X509_EXTENSION *ext)
		throw (CertificationException) : Extension(ext)
{
	CRL_DIST_POINTS *points;
	DistributionPoint distPoint;
	int i, num = 0;
	if (OBJ_obj2nid(X509_EXTENSION_get_object(ext)) != NID_crl_distribution_points)
	{
		throw CertificationException(CertificationException::INVALID_TYPE, "CRLDistributionPointsExtension::CRLDistributionPointsExtension");
	}
	points = (CRL_DIST_POINTS *)X509V3_EXT_d2i(ext);
	num = sk_DIST_POINT_num(points);
	for (i=0;i<num;i++)
	{
		distPoint = DistributionPoint((DIST_POINT *)sk_DIST_POINT_value(points, i));
		this->distributionPoints.push_back(distPoint);
	}
	CRL_DIST_POINTS_free(points);
}

CRLDistributionPointsExtension::~CRLDistributionPointsExtension()
{
}

std::string CRLDistributionPointsExtension::extValue2Xml(std::string tab)
{
	std::string ret, string;
	unsigned int i;

	ret += tab + "<distributionPoints>\n";

	for (i=0;i<this->distributionPoints.size();i++)
	{
		string = this->distributionPoints.at(i).getXmlEncoded(tab + "\t");
		ret += string;
	}
	
	ret += tab + "</distributionPoints>\n";

	return ret;
}

std::string CRLDistributionPointsExtension::getXmlEncoded()
{
	return this->getXmlEncoded("");
}

std::string CRLDistributionPointsExtension::getXmlEncoded(std::string tab)
{
	std::string ret, string;
	unsigned int i;
	ret = tab + "<CRLDistributionPoints>\n";
		ret += tab + "\t<extnID>" + this->getName() + "</extnID>\n";
		string = (this->isCritical())?"yes":"no";
		ret += tab + "\t<critical>" + string + "</critical>\n";
		ret += tab + "\t<extnValue>\n";
			ret += tab + "\t\t<distributionPoints>\n";

			for (i=0;i<this->distributionPoints.size();i++)
			{
				string = this->distributionPoints.at(i).getXmlEncoded("\t\t\t");
				ret += tab + string;
			}
			
			ret += tab + "\t\t</distributionPoints>\n";
		ret += tab + "\t</extnValue>\n";
	ret += tab + "</CRLDistributionPoints>\n";
	return ret;
}

void CRLDistributionPointsExtension::addDistributionPoint(DistributionPoint &distributionPoint)
{
//	CRL_DIST_POINTS *points;
//	bool critical;
//	points = (CRL_DIST_POINTS *)X509V3_EXT_d2i(this->ext);
//	sk_DIST_POINT_insert(points, DistributionPoint::clone(value.getDistPoint()), -1);
//	critical = this->isCritical();
//	X509_EXTENSION_free(this->ext);
//	this->ext = X509V3_EXT_i2d(NID_crl_distribution_points, critical?1:0, (void *)points);
	this->distributionPoints.push_back(distributionPoint); 
}

std::vector<DistributionPoint> CRLDistributionPointsExtension::getDistributionPoints()
{
//	CRL_DIST_POINTS *points;
//	DIST_POINT *distPoint;
//	DistributionPoint onePoint;
//	std::vector<DistributionPoint> ret;
//	int i, num;
//	points = (CRL_DIST_POINTS *)X509V3_EXT_d2i(this->ext);
//	num = sk_DIST_POINT_num(points);
//	for (i=0;i<num;i++)
//	{
//		distPoint = sk_DIST_POINT_value(points, i);
//		onePoint = DistributionPoint(DistributionPoint::clone(distPoint));
//		ret.push_back(onePoint);
//	}
//	return ret;
	return this->distributionPoints;
}

X509_EXTENSION* CRLDistributionPointsExtension::getX509Extension()
{
	X509_EXTENSION *ret;
	CRL_DIST_POINTS *distPoints;
	unsigned int i;
	distPoints = CRL_DIST_POINTS_new();
	for (i=0;i<this->distributionPoints.size();i++)
	{
		sk_DIST_POINT_push(distPoints, this->distributionPoints.at(i).getDistPoint());
	}
	ret = X509V3_EXT_i2d(NID_crl_distribution_points, this->critical?1:0, (void *)distPoints);
	CRL_DIST_POINTS_free(distPoints);
	return ret;
}
