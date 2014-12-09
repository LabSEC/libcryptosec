#include <libcryptosec/certificate/DistributionPoint.h>

DistributionPoint::DistributionPoint()
{
	int i;
	for (i=0;i<7;i++)
	{
		this->reasons[i] = false;
	}
}

DistributionPoint::DistributionPoint(DIST_POINT *distPoint)
{
	int i;
	if (distPoint)
	{
		if (distPoint->distpoint)
		{
			this->distributionPointName = DistributionPointName(distPoint->distpoint);
		}
		if (distPoint->reasons)
		{
			for (i=0;i<7;i++)
			{
				this->reasons[i] = (ASN1_BIT_STRING_get_bit(distPoint->reasons, i))?true:false;
			}
		}
		else
		{
			for (i=0;i<7;i++)
			{
				this->reasons[i] = false;
			}
		}
		if (distPoint->CRLissuer)
		{
			this->crlIssuer = GeneralNames(distPoint->CRLissuer);
		}
	}
}

DistributionPoint::~DistributionPoint()
{
}

std::string DistributionPoint::getXmlEncoded()
{
	return this->getXmlEncoded("");
}

std::string DistributionPoint::getXmlEncoded(std::string tab)
{
	std::string ret, string, reasonValue;
	int i;

	ret = tab + "<distributionPoint>\n";
	if (this->distributionPointName.getType() != DistributionPointName::UNDEFINED)
	{
		ret += this->distributionPointName.getXmlEncoded(tab + "\t");
	}
	
	ret += tab + "\t<reasonFlag>\n";
	for (i=0;i<7;i++)
	{
		string = reasonFlag2Name((DistributionPoint::ReasonFlags)i);
		reasonValue = this->reasons[i]?"1":"0";
		ret += tab + "\t\t<"+ string +">" + reasonValue + "</" + string + ">\n";
	}
	ret += tab + "\t</reasonFlag>\n";
	
	if (this->crlIssuer.getNumberOfEntries() > 0)
	{	
		ret += this->crlIssuer.getXmlEncoded(tab + "\t");
	}
	ret += tab + "</distributionPoint>\n";
	return ret;
}

void DistributionPoint::setDistributionPointName(DistributionPointName &dpn)
{
//	if (this->distPoint->distpoint)
//	{
//		DIST_POINT_NAME_free(this->distPoint->distpoint);
//	}
//	this->distPoint->distpoint = DistributionPointName::clone(dpn.getDistPointName());
	this->distributionPointName = dpn;
}

DistributionPointName DistributionPoint::getDistributionPointName()
{
//	DistributionPointName ret;
//	if (!this->distPoint->distpoint)
//	{
//		throw CertificationException(CertificationException::SET_NO_VALUE, "DistributionPoint::getDistributionPointName");
//	}
//	ret = DistributionPointName(DistributionPointName::clone(this->distPoint->distpoint));
//	return ret;
	return this->distributionPointName;
}

void DistributionPoint::setReasonFlag(DistributionPoint::ReasonFlags reason, bool value)
{
//	if (!this->distPoint->reasons)
//	{
//		this->distPoint->reasons = ASN1_BIT_STRING_new();
//		ASN1_BIT_STRING_set(this->distPoint->reasons, (unsigned char *)"\0", 1);
//	}
//	ASN1_BIT_STRING_set_bit(this->distPoint->reasons, (int)reason, value?1:0);
//	
//	GENERAL_NAME *n2;
//	n2 = sk_GENERAL_NAME_value(this->distPoint->CRLissuer, 0);
////	printf("REA: NUM1: %d \n", n2->type);
	this->reasons[reason] = value;
}

bool DistributionPoint::getReasonFlag(DistributionPoint::ReasonFlags reason)
{
//	int ret;
//	if (!this->distPoint->reasons)
//	{
//		throw CertificationException(CertificationException::SET_NO_VALUE, "DistributionPoint::getReasonFlags");
//	}
//	ret = ASN1_BIT_STRING_get_bit(this->distPoint->reasons, (int)reason);
//	return ret?true:false;
	return this->reasons[reason];
}

void DistributionPoint::setCrlIssuer(GeneralNames &crlIssuer)
{
//	if (this->distPoint->CRLissuer)
//	{
//		GENERAL_NAMES_free(this->distPoint->CRLissuer);
//	}
//	this->distPoint->CRLissuer = crlIssuer.getInternalGeneralNames();
//	
////	GENERAL_NAME *n1, *n2;
////	n1 = sk_GENERAL_NAME_value(generalNames, 0);
////	n2 = sk_GENERAL_NAME_value(this->distPoint->CRLissuer, 0);
////	printf("SET: NUM1: %d X %d :2NUM\n", n1->type, n2->type);
	this->crlIssuer = crlIssuer;
}

GeneralNames DistributionPoint::getCrlIssuer()
{
//	GENERAL_NAMES *generalNames;
//	if (!this->distPoint->CRLissuer)
//	{
//		throw CertificationException(CertificationException::SET_NO_VALUE, "DistributionPoint::getCrlIssuer");
//	}
//	generalNames = sk_GENERAL_NAME_dup(this->distPoint->CRLissuer);
//	
//	GENERAL_NAME *n1, *n2;
//	n1 = sk_GENERAL_NAME_value(generalNames, 0);
//	n2 = sk_GENERAL_NAME_value(this->distPoint->CRLissuer, 0);
////	printf("GET: NUM1: %d X %d :2NUM\n", n1->type, n2->type);
//	
////	int num = sk_GENERAL_NAME_num(generalNames);
////	int num2 = sk_GENERAL_NAME_num(this->distPoint->CRLissuer);
////	printf("NUM1: %d X %d :2NUM\n", num, num2);
//	return GeneralNames(generalNames);
	return this->crlIssuer;
}

DIST_POINT* DistributionPoint::getDistPoint()
{
	DIST_POINT *ret;
	bool anyReasons;
	int i;
	ret = DIST_POINT_new();
	if (this->distributionPointName.getType() != DistributionPointName::UNDEFINED)
	{
		ret->distpoint = this->distributionPointName.getDistPointName();
	}
	anyReasons = false;
	i = 0;
	while (!anyReasons && i<7)
	{
		if (this->reasons[i])
		{
			anyReasons = true;
		}
		i++;
	}
	if (anyReasons)
	{
		ret->reasons = ASN1_BIT_STRING_new();
		for (i=0;i<7;i++)
		{
			ASN1_BIT_STRING_set_bit(ret->reasons, i, this->reasons[i]?1:0);
		}
	}
	if (this->crlIssuer.getNumberOfEntries() > 0)
	{
		ret->CRLissuer = this->crlIssuer.getInternalGeneralNames();
	}
	return ret;
}

//DistributionPoint& DistributionPoint::operator =(const DistributionPoint& value)
//{
//	if (this->distPoint)
//	{
//		DIST_POINT_free(this->distPoint);
//	}
//    this->distPoint = DistributionPoint::clone(value.getDistPoint());
//    return (*this);
//}

std::string DistributionPoint::reasonFlag2Name(DistributionPoint::ReasonFlags reason)
{
	std::string ret;
	switch (reason)
	{
		case DistributionPoint::UNUSED:
			ret = "unused";
			break;
		case DistributionPoint::KEY_COMPROMISE:
			ret = "keyCompromise";
			break;
		case DistributionPoint::CA_COMPROMISE:
			ret = "caCompromise";
			break;
		case DistributionPoint::AFFILIATION_CHANGED:
			ret = "affiliationChanged";
			break;
		case DistributionPoint::SUPERSEDED:
			ret = "superseded";
			break;
		case DistributionPoint::CESSATION_OF_OPERATION:
			ret = "cessationOfOperation";
			break;
		case DistributionPoint::CERTIFICATE_HOLD:
			ret = "certificateHold";
			break;
	}
	return ret;
}

//DIST_POINT* DistributionPoint::clone(DIST_POINT *value)
//{
//	DIST_POINT *ret;
//	int i;
//	ret = DIST_POINT_new();
//	ret->reasons = ASN1_BIT_STRING_new();
//	for (i=0;i<7;i++)
//	{
//		ASN1_BIT_STRING_set_bit(ret->reasons, i, ASN1_BIT_STRING_get_bit(value->reasons, i));
//	}
//	if (value->CRLissuer)
//	{
//		ret->CRLissuer = sk_GENERAL_NAME_dup(value->CRLissuer);
//	}
//	else
//	{
//		value->CRLissuer = NULL;
//	}
//	if (ret->distpoint)
//	{
//		ret->distpoint = DistributionPointName::clone(value->distpoint);
//	}
//	else
//	{
//		ret->distpoint = NULL;	
//	}
//	return ret;
//}
