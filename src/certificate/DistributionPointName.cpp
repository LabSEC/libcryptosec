#include <libcryptosec/certificate/DistributionPointName.h>

DistributionPointName::DistributionPointName()
{
	this->type = DistributionPointName::UNDEFINED;
}

DistributionPointName::DistributionPointName(DIST_POINT_NAME *dpn)
{
	if (dpn)
	{
		switch (dpn->type)
		{
			case 0:
				this->type = DistributionPointName::FULL_NAME;
				this->fullName = GeneralNames(dpn->name.fullname);
				break;
			case 1:
				this->type = DistributionPointName::RELATIVE_NAME;
				this->relativeName = RDNSequence(dpn->name.relativename);
				break;
			default:
				this->type = DistributionPointName::UNDEFINED;
				break;
		}
	}
}

DistributionPointName::~DistributionPointName()
{
}

std::string DistributionPointName::getXmlEncoded()
{
	return this->getXmlEncoded("");
}

std::string DistributionPointName::getXmlEncoded(std::string tab)
{
	std::string ret;
	GeneralNames gns;
	RDNSequence rdn;
	ret = tab + "<distributionPointName>\n";
	switch (this->type)
	{
		case DistributionPointName::FULL_NAME:
			ret += this->fullName.getXmlEncoded(tab + "\t");
			break;
		case DistributionPointName::RELATIVE_NAME:
			ret += this->relativeName.getXmlEncoded(tab + "\t");
			break;
		default:
			ret += tab + "\tundefined\n";
			break;
	}
	ret += tab + "</distributionPointName>\n";
	return ret;
}

void DistributionPointName::setNameRelativeToCrlIssuer(RDNSequence &rdnSequence)
{
	this->type = DistributionPointName::RELATIVE_NAME;
	this->relativeName = rdnSequence;
	this->fullName = GeneralNames();
}

RDNSequence DistributionPointName::getNameRelativeToCrlIssuer()
{
//	X509_NAME *rdn;
//	X509_NAME_ENTRY *entry, *entry2;
//	int i, num;
//	if (this->dpn->type != 1)
//	{
//		throw CertificationException(CertificationException::SET_NO_VALUE, "CertificationException::getNameRelativeToCrlIssuer");
//	}
//	rdn = X509_NAME_new();
//	num = sk_X509_NAME_ENTRY_num(this->dpn->name.relativename);
//	for (i=0;i<num;i++)
//	{
//		entry = sk_X509_NAME_ENTRY_value(this->dpn->name.relativename, i);
////		entry2 = X509_NAME_ENTRY_dup(entry);
//		X509_NAME_add_entry(rdn, entry, -1, 0);
////		X509_NAME_ENTRY_free(entry2);
//	}
//	return RDNSequence(rdn);
	return this->relativeName;
}

void DistributionPointName::setFullName(GeneralNames &generalNames)
{
//	if (this->dpn->type == 0)
//	{
//		GENERAL_NAMES_free(this->dpn->name.fullname);
//	}
//	else if (this->dpn->type == 1)
//	{
//		sk_X509_NAME_ENTRY_free(this->dpn->name.relativename);
//	}
//	this->dpn->type = 0;
//	this->dpn->name.fullname = generalNames.getInternalGeneralNames();
	this->type = DistributionPointName::FULL_NAME;
	this->fullName = generalNames;
	this->relativeName = RDNSequence();
}

GeneralNames DistributionPointName::getFullName()
{
//	GENERAL_NAMES *gn;
//	if (this->dpn->type != 0)
//	{
//		throw CertificationException(CertificationException::SET_NO_VALUE, "CertificationException::getFullName");
//	}
//	gn = sk_GENERAL_NAME_dup(this->dpn->name.fullname);
//	return GeneralNames(gn);
	return this->fullName;
}

DistributionPointName::Type DistributionPointName::getType() const
{
	return this->type;
}

DIST_POINT_NAME* DistributionPointName::getDistPointName()
{
	DIST_POINT_NAME *ret;
	X509_NAME *name;
	ret = DIST_POINT_NAME_new();
	switch (this->type)
	{
		case DistributionPointName::FULL_NAME:
			ret->type = 0;
			ret->name.fullname = this->fullName.getInternalGeneralNames();
			break;
		case DistributionPointName::RELATIVE_NAME:
			ret->type = 1;
			name = this->relativeName.getX509Name();
			DIST_POINT_set_dpname(ret, name);
			X509_NAME_free(name);
			break;
		default:
			ret->type = -1;
			break;
	}
	return ret;
}

//DistributionPointName& DistributionPointName::operator =(const DistributionPointName& value)
//{
//	DIST_POINT_NAME_free(this->dpn);
//    this->dpn = DistributionPointName::clone(value.getDistPointName());
//    return (*this);
//}
//
//DIST_POINT_NAME* DistributionPointName::clone(DIST_POINT_NAME *value)
//{
//	DIST_POINT_NAME *ret;
//	ret = DIST_POINT_NAME_new();
//	ret->type = value->type;
//	if (value->type == 0)
//	{
//		ret->name.fullname = sk_GENERAL_NAME_dup(value->name.fullname);
//	}
//	else if(value->type == 1)
//	{
//		ret->name.relativename = sk_X509_NAME_ENTRY_dup(value->name.relativename);
//	}
//	return ret;
//}
