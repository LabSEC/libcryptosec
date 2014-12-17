#include <libcryptosec/certificate/UserNotice.h>

UserNotice::UserNotice()
{
	this->organization.erase();
	this->explicitText.erase();
}

UserNotice::UserNotice(USERNOTICE *userNotice)
{
	char *data;
	int i, num;
	ASN1_INTEGER *asn1Int;
	if (userNotice)
	{
		if (userNotice->exptext)
		{
			data = (char *)ASN1_STRING_data(userNotice->exptext);
			this->explicitText = data;
		}
		else
		{
			this->explicitText.erase();
		}
		if (userNotice->noticeref)
		{
			data = (char *)ASN1_STRING_data(userNotice->noticeref->organization);
			this->organization = data;
			
			num = sk_ASN1_INTEGER_num(userNotice->noticeref->noticenos);
			for (i=0;i<num;i++)
			{
				asn1Int = sk_ASN1_INTEGER_value(userNotice->noticeref->noticenos, i);
				this->noticeNumbers.push_back(ASN1_INTEGER_get(asn1Int));
			}
		}
		else
		{
			this->organization.erase();
		}
	}
	else
	{
		this->organization.erase();
		this->explicitText.erase();
	}
}

UserNotice::~UserNotice()
{
}

std::string UserNotice::getXmlEncoded()
{
	return this->getXmlEncoded("");
}

std::string UserNotice::getXmlEncoded(std::string tab)
{
	std::string ret;
	std::string ints;
	unsigned int i;
	char temp[15];
	long value;
	ret = tab + "<userNotice>\n";

		if (!this->organization.empty())
		{
			ret += tab + "\t<noticeRef>\n";
				ret += tab + "\t\t<organization>" + this->organization + "</organization>\n";
				ints = "";
				if (this->noticeNumbers.size() > 0)
				{
					value = this->noticeNumbers.at(0);
					sprintf(temp, "%d", (int)value);
					ints = temp;
					for (i=1;i<this->noticeNumbers.size();i++)
					{
						value = this->noticeNumbers.at(i);
						sprintf(temp, "%d", (int)value);
						ints += " ";
						ints += temp;
					}
				}
				ret += tab + "\t\t<noticeNumbers>" + ints + "</noticeNumbers>\n";
			ret += tab + "\t</noticeRef>\n";
		}
		
		if (!this->explicitText.empty())
		{
			ret += tab + "\t<explicitText>" + this->explicitText + "</explicitText>\n";
		}
	ret += tab + "</userNotice>\n";
	return ret;
}

void UserNotice::setNoticeReference(std::string organization, std::vector<long> noticeNumbers)
{
	this->organization = organization;
	this->noticeNumbers = noticeNumbers;
}

std::pair<std::string, std::vector<long> > UserNotice::getNoticeReference()
{
	std::pair<std::string, std::vector<long> > ret;
	ret.first = this->organization;
	ret.second = this->noticeNumbers;
	return ret;
}

void UserNotice::setExplicitText(std::string explicitText)
{
	this->explicitText = explicitText;
}

std::string UserNotice::getExplicitText()
{
	return this->explicitText;
}

USERNOTICE* UserNotice::getUserNotice() const
{
	USERNOTICE *ret;
	unsigned int i;
	ASN1_INTEGER *asn1Int;
	ret = USERNOTICE_new();
	if (!this->explicitText.empty())
	{
		ret->exptext = ASN1_UTF8STRING_new();
		ASN1_STRING_set(ret->exptext, this->explicitText.c_str(), this->explicitText.size());
	}
	if (!this->organization.empty())
	{
		ret->noticeref = NOTICEREF_new();
		ret->noticeref->organization = ASN1_UTF8STRING_new();
		ASN1_STRING_set(ret->noticeref->organization, this->organization.c_str(), this->organization.size());
		ret->noticeref->noticenos = sk_ASN1_INTEGER_new_null();
		for (i=0;i<this->noticeNumbers.size();i++)
		{
			asn1Int = ASN1_INTEGER_new();
			ASN1_INTEGER_set(asn1Int, this->noticeNumbers.at(i));
			sk_ASN1_INTEGER_push(ret->noticeref->noticenos, asn1Int);
		}
	}
	return ret;
}
