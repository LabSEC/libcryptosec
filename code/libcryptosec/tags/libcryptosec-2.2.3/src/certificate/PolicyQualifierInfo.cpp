#include <libcryptosec/certificate/PolicyQualifierInfo.h>

PolicyQualifierInfo::PolicyQualifierInfo()
{
	this->type = PolicyQualifierInfo::UNDEFINED;
}

PolicyQualifierInfo::PolicyQualifierInfo(POLICYQUALINFO *policyQualInfo)
{
	char *data;
	if (policyQualInfo)
	{
		this->objectIdentifier = ObjectIdentifier(OBJ_dup(policyQualInfo->pqualid));
		switch (this->objectIdentifier.getNid())
		{
			case NID_id_qt_cps:
				this->type = PolicyQualifierInfo::CPS_URI;
				data = (char *)ASN1_STRING_data(policyQualInfo->d.cpsuri);
				this->cpsUri = data;
				break;
			case NID_id_qt_unotice:
				this->type = PolicyQualifierInfo::USER_NOTICE;
				this->userNotice = UserNotice(policyQualInfo->d.usernotice);
				break;
			default:
				this->type = PolicyQualifierInfo::UNDEFINED;
		}
	}
	else
	{
		this->type = PolicyQualifierInfo::UNDEFINED;
	}
}

PolicyQualifierInfo::~PolicyQualifierInfo()
{
}

std::string PolicyQualifierInfo::getXmlEncoded()
{
	return this->getXmlEncoded("");
}

std::string PolicyQualifierInfo::getXmlEncoded(std::string tab)
{
	std::string ret;
	ret = tab + "<policyQualifierInfo>\n";
	switch (this->type)
	{
		case PolicyQualifierInfo::USER_NOTICE:
			ret += this->objectIdentifier.getXmlEncoded(tab + "\t");
			ret += this->userNotice.getXmlEncoded(tab + "\t");
			break;
		case PolicyQualifierInfo::CPS_URI:
			ret += this->objectIdentifier.getXmlEncoded(tab + "\t");
			ret += tab + "\t<cPSuri>" + this->cpsUri + "</cPSuri>\n";
			break;
		default:
			break;
	}
	ret += tab + "</policyQualifierInfo>\n";
	return ret;
}

void PolicyQualifierInfo::setObjectIdentifier(ObjectIdentifier objectIdentifier)
{
	this->objectIdentifier = objectIdentifier;
}

ObjectIdentifier PolicyQualifierInfo::getObjectIdentifier()
{
	return this->objectIdentifier;
}

void PolicyQualifierInfo::setCpsUri(std::string cpsUri)
{
	//no caso de cpsUri = "" ha problema de codificacao ASN1
	if(cpsUri.size() > 0)
	{
		this->userNotice = UserNotice();
		this->objectIdentifier = ObjectIdentifierFactory::getObjectIdentifier(NID_id_qt_cps);
		this->cpsUri = cpsUri;
		this->type = PolicyQualifierInfo::CPS_URI;
	}
}

std::string PolicyQualifierInfo::getCpsUri()
{
	return this->cpsUri;
}

void PolicyQualifierInfo::setUserNotice(UserNotice userNotice)
{
	this->userNotice = userNotice;
	this->objectIdentifier = ObjectIdentifierFactory::getObjectIdentifier(NID_id_qt_unotice);
	this->cpsUri = std::string();
	this->type = PolicyQualifierInfo::USER_NOTICE;
}

UserNotice PolicyQualifierInfo::getUserNotice()
{
	return this->userNotice;
}

PolicyQualifierInfo::Type PolicyQualifierInfo::getType()
{
	return this->type;
}

POLICYQUALINFO* PolicyQualifierInfo::getPolicyQualInfo() const
{
	POLICYQUALINFO *ret;
	ret = POLICYQUALINFO_new();
	switch (this->type)
	{
		case PolicyQualifierInfo::CPS_URI:
			ret->pqualid = OBJ_dup(this->objectIdentifier.getObjectIdentifier());
			ret->d.cpsuri = ASN1_IA5STRING_new();
			ASN1_STRING_set(ret->d.cpsuri, this->cpsUri.c_str(), this->cpsUri.size());
			break;
		case PolicyQualifierInfo::USER_NOTICE:
			ret->pqualid = OBJ_dup(this->objectIdentifier.getObjectIdentifier());
			ret->d.usernotice = this->userNotice.getUserNotice();
			break;
		default:
			break;
	}
	return ret;
}
