#include <libcryptosec/certificate/GeneralNames.h>

GeneralNames::GeneralNames()
{
}

GeneralNames::GeneralNames(GENERAL_NAMES *generalNames)
{
	int i, num;
	GENERAL_NAME *value;
	std::string data, oid;
	RDNSequence directoryName;
	ObjectIdentifier registeredId;
	num = sk_GENERAL_NAME_num(generalNames);
	if (generalNames)
	{
		for (i=0;i<num;i++)
		{
			value = sk_GENERAL_NAME_value(generalNames, i);
			GeneralName generalName(value);
			this->generalNames.push_back(generalName);
		}
	}
}

//GeneralNames::GeneralNames(const GeneralNames& gns)
//{
//	this->generalNames = sk_GENERAL_NAME_dup(gns.getGeneralNames());
//}

GeneralNames::~GeneralNames()
{
}

std::string GeneralNames::getXmlEncoded()
{
	return this->getXmlEncoded("");
}

std::string GeneralNames::getXmlEncoded(std::string tab)
{
	unsigned int i;
	std::string ret;
	ret += tab + "<generalNames>\n";
	
	for (i=0;i<this->generalNames.size();i++)
	{
		ret += this->generalNames.at(i).getXmlEncoded(tab + "\t");
	}
	
	ret += tab + "</generalNames>\n";
	return ret;
}

void GeneralNames::addGeneralName(GeneralName &generalName)
{
	this->generalNames.push_back(generalName);
}

std::vector<GeneralName> GeneralNames::getGeneralNames() const
{
	return this->generalNames;
}

int GeneralNames::getNumberOfEntries() const
{
	return this->generalNames.size();
}

GENERAL_NAMES* GeneralNames::getInternalGeneralNames()
{
	GENERAL_NAMES *ret;
	GENERAL_NAME *generalName;
	unsigned int i;
	ret = GENERAL_NAMES_new();
	for (i=0;i<this->generalNames.size();i++)
	{
		generalName = this->generalNames.at(i).getGeneralName();
		sk_GENERAL_NAME_push(ret, generalName);
	}
	return ret;
}

/**
 * @deprecated Método movido para a classe GeneralName. Futuramente poderá ser removido dessa classe.
 */
std::string GeneralNames::data2IpAddress(unsigned char *data)
{
	return GeneralName::data2IpAddress(data);
}

GeneralNames& GeneralNames::operator=(const GeneralNames& value)
{
	this->generalNames = value.getGeneralNames(); 
	return *this;
}
