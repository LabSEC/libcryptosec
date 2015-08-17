#include <libcryptosec/certificate/GeneralName.h>

GeneralName::GeneralName()
{
	this->type = GeneralName::UNDEFINED;
}

//GeneralName::GeneralName(const GeneralName& generalName)
//{
//	this->type = generalName.getType();
//	switch (this->type)
//	{
//		case GeneralName::RFC_822_NAME:
//			this->data = generalName.getRfc822Name();
//			break;
//		case GeneralName::DNS_NAME:
//			this->data = generalName.getDnsName();
//			break;
//		case GeneralName::DIRECTORY_NAME:
//			this->directoryName = generalName.getDirectoryName();
//			break;
//		case GeneralName::UNIFORM_RESOURCE_IDENTIFIER:
//			this->data = generalName.getUniformResourceIdentifier();
//			break;
//		case GeneralName::IP_ADDRESS:
//			this->data = generalName.getIpAddress();
//			break;
//		case GeneralName::REGISTERED_ID:
//			this->registeredId = generalName.getRegisteredId();
//			break;
//		default:
//			break;
//	}
//}

GeneralName::GeneralName(GENERAL_NAME *generalName) {
	std::string data, oid;
	unsigned char *temp;
	RDNSequence directoryName;
	ObjectIdentifier registeredId;

	switch (generalName->type)
	{
		case GEN_OTHERNAME:
			if (V_ASN1_OCTET_STRING == generalName->d.otherName->value->type) {
				ASN1_OCTET_STRING *	octetString = generalName->d.otherName->value->value.octet_string;
				data.assign((const char *)octetString->data, octetString->length);
				char oidChar[100];
				OBJ_obj2txt(oidChar, 100, generalName->d.otherName->type_id, 1);
				oid = oidChar;
				this->setOtherName(oid, data);
			}
			break;
		case GEN_EMAIL:
			data = (char *)ASN1_STRING_data(generalName->d.rfc822Name);
			this->setRfc822Name(data);
			break;
		case GEN_DNS:
			data = (char *)ASN1_STRING_data(generalName->d.dNSName);
			this->setDnsName(data);
			break;
		case GEN_DIRNAME:
			directoryName = RDNSequence(generalName->d.directoryName);
			this->setDirectoryName(directoryName);
			break;
		case GEN_IPADD:
			temp = (unsigned char *)ASN1_STRING_data(generalName->d.iPAddress);
			data = GeneralName::data2IpAddress(temp);
			this->setIpAddress(data);
			break;
		case GEN_URI:
			data = (char *)ASN1_STRING_data(generalName->d.uniformResourceIdentifier);
			this->setUniformResourceIdentifier(data);
			break;
		case GEN_RID:
			registeredId = ObjectIdentifier(OBJ_dup(generalName->d.registeredID));
			this->setRegisteredId(registeredId);
			break;
		default:
			this->type = GeneralName::UNDEFINED;
			break;
	}
}

GeneralName::~GeneralName()
{
}

std::string GeneralName::getXmlEncoded()
{
	return this->getXmlEncoded("");
}

std::string GeneralName::getXmlEncoded(std::string tab)
{
	std::string ret, name;
	name = GeneralName::type2Name(this->type);
	ret = tab + "<" + name + ">\n";
	switch (this->type)
	{
		case GeneralName::OTHER_NAME:
			ret += tab + "\t" + oid + " : " + data + "\n";
			break;
		case GeneralName::RFC_822_NAME:
			ret += tab + "\t" + data + "\n";
			break;
		case GeneralName::DNS_NAME:
			ret += tab + "\t" + data + "\n";
			break;
		case GeneralName::DIRECTORY_NAME:
			ret += this->directoryName.getXmlEncoded(tab + "\t");
			break;
		case GeneralName::UNIFORM_RESOURCE_IDENTIFIER:
			ret += tab + "\t" + data + "\n";
			break;
		case GeneralName::IP_ADDRESS:
			ret += tab + "\t" + data + "\n";
			break;
		case GeneralName::REGISTERED_ID:
			ret += tab + "\t" + this->registeredId.getName() + "\n";
			break;
		default:
			break;
	}
	ret += tab + "</" + name + ">\n";
	return ret;
}

void GeneralName::setOtherName(std::string oid, std::string data) {
	this->clean();
	this->type = GeneralName::OTHER_NAME;
	this->oid = oid;
	this->data = data;
}

pair<std::string, std::string> GeneralName::getOtherName() const {
	return pair<std::string, std::string>(this->oid, this->data);
}

void GeneralName::setRfc822Name(std::string rfc822Name)
{
	this->clean();
	this->type = GeneralName::RFC_822_NAME;
	this->data = rfc822Name;
}

std::string GeneralName::getRfc822Name() const
{
	return this->data;
}
 
void GeneralName::setDnsName(std::string dnsName)
{
	this->clean();
	this->type = GeneralName::DNS_NAME;
	this->data = dnsName;
}

std::string GeneralName::getDnsName() const
{
	return this->data;
}

void GeneralName::setDirectoryName(RDNSequence &directoryName)
{
	this->clean();
	this->type = GeneralName::DIRECTORY_NAME;
	this->directoryName = directoryName;
}

RDNSequence GeneralName::getDirectoryName() const
{
	return this->directoryName;
}

void GeneralName::setUniformResourceIdentifier(std::string uniformResourceIdentifier)
{
	this->clean();
	this->type = GeneralName::UNIFORM_RESOURCE_IDENTIFIER;
	this->data = uniformResourceIdentifier;
}

std::string GeneralName::getUniformResourceIdentifier() const
{
	return this->data;
}

void GeneralName::setIpAddress(std::string ipAddress)
{
	this->clean();
	this->type = GeneralName::IP_ADDRESS;
	this->data = ipAddress;
}

std::string GeneralName::getIpAddress() const
{
	return this->data;
}

void GeneralName::setRegisteredId(ObjectIdentifier registeredId)
{
	this->clean();
	this->type = GeneralName::REGISTERED_ID;
	this->registeredId = registeredId;
}

ObjectIdentifier GeneralName::getRegisteredId() const
{
	return this->registeredId;
}

GeneralName::Type GeneralName::getType() const
{
	return this->type;
}

GENERAL_NAME* GeneralName::getGeneralName()
{
	GENERAL_NAME *ret;
	unsigned char *ipAddress;
	ret = GENERAL_NAME_new();
	switch (this->type)
	{
		case GeneralName::OTHER_NAME:
			ret->type = GEN_OTHERNAME;
			ret->d.otherName = OTHERNAME_new();
			ret->d.otherName->type_id = OBJ_txt2obj(this->oid.c_str(), 1);
			ASN1_TYPE* otherNameValue;
			otherNameValue = ASN1_TYPE_new();
			ASN1_TYPE_set_octetstring(otherNameValue, (unsigned char*) this->data.c_str(), this->data.length());
			ret->d.otherName->value = otherNameValue;
			break;
		case GeneralName::RFC_822_NAME:
			ret->type = GEN_EMAIL;
			ret->d.rfc822Name = ASN1_IA5STRING_new();
			ASN1_STRING_set(ret->d.rfc822Name, this->data.c_str(), this->data.size());
			break;
		case GeneralName::DNS_NAME:
			ret->type = GEN_DNS;
			ret->d.dNSName = ASN1_IA5STRING_new();
			ASN1_STRING_set(ret->d.dNSName, this->data.c_str(), this->data.size());
			break;
		case GeneralName::DIRECTORY_NAME:
			ret->type = GEN_DIRNAME;
			ret->d.directoryName = this->directoryName.getX509Name();
			break;
		case GeneralName::UNIFORM_RESOURCE_IDENTIFIER:
			ret->type = GEN_URI;
			ret->d.uniformResourceIdentifier = ASN1_IA5STRING_new();
			ASN1_STRING_set(ret->d.uniformResourceIdentifier, this->data.c_str(), this->data.size());
			break;
		case GeneralName::IP_ADDRESS:
			ret->type = GEN_IPADD;
			ret->d.iPAddress = ASN1_OCTET_STRING_new();
			ipAddress = GeneralName::ipAddress2Data(this->data);
			ASN1_OCTET_STRING_set(ret->d.iPAddress, ipAddress, 4);
			free(ipAddress);
			break;
		case GeneralName::REGISTERED_ID:
			ret->type = GEN_RID;
			ret->d.registeredID = OBJ_dup(this->registeredId.getObjectIdentifier());
			break;
		case GeneralName::UNDEFINED:
			break;
	}
	return ret;
}

void GeneralName::clean()
{
	switch (this->type)
	{
		case GeneralName::OTHER_NAME:
			this->oid = std::string();
			this->data = std::string();
			break;
		case GeneralName::RFC_822_NAME:
			this->data = std::string();
			break;
		case GeneralName::DNS_NAME:
			this->data = std::string();
			break;
		case GeneralName::DIRECTORY_NAME:
			this->directoryName = RDNSequence();
			break;
		case GeneralName::UNIFORM_RESOURCE_IDENTIFIER:
			this->data = std::string();
			break;
		case GeneralName::IP_ADDRESS:
			this->data = std::string();
			break;
		case GeneralName::REGISTERED_ID:
			this->registeredId = ObjectIdentifier();
			break;
		default:
			break;
	}
}

std::string GeneralName::type2Name(GeneralName::Type type)
{
	std::string ret;
	switch (type)
	{
		case GeneralName::OTHER_NAME:
			ret = "otherName";
			break;
		case GeneralName::RFC_822_NAME:
			ret = "rfc822Name";
			break;
		case GeneralName::DNS_NAME:
			ret = "dnsName";
			break;
		case GeneralName::DIRECTORY_NAME:
			ret = "directoryName";
			break;
		case GeneralName::UNIFORM_RESOURCE_IDENTIFIER:
			ret = "uniformResourceIdentifier";
			break;
		case GeneralName::IP_ADDRESS:
			ret = "iPAddress";
			break;
		case GeneralName::REGISTERED_ID:
			ret = "registeredID";
			break;
		default:
			ret = "undefined";
			break;
	}
	return ret;
}

unsigned char* GeneralName::ipAddress2Data(std::string ipAddress)
{
	unsigned char *ret;
	int value, i;
	unsigned int size, tempSize;
	char data[4];
	size = 0;
	ret = (unsigned char *)calloc(5, sizeof(unsigned char));
	for (i=0;i<4 && size < ipAddress.size();i++)
	{
		ret[i] = 0x0;
		tempSize = 0;
		while (ipAddress[size] != '.' && size < ipAddress.size())
		{
			data[tempSize] = ipAddress[size];
			size++;
			tempSize++;
		}
		size++;
		data[tempSize] = '\0';
		value = atoi(data);
		ret[i] = (value & 0x00FF);
	}
	ret[4] = 0x0;
	return ret;
}

GeneralName& GeneralName::operator=(const GeneralName& value)
{
	this->type = value.type;
		
	switch (this->type)
	{
		case GeneralName::OTHER_NAME:
			this->oid = value.oid;
			this->data = value.data;
			break;
		case GeneralName::RFC_822_NAME:
			this->data = value.data;
			break;
		case GeneralName::DNS_NAME:
			this->data = value.data;
			break;
		case GeneralName::DIRECTORY_NAME:
			this->directoryName = value.directoryName;
			break;
		case GeneralName::UNIFORM_RESOURCE_IDENTIFIER:
			this->data = value.data;
			break;
		case GeneralName::IP_ADDRESS:
			this->data = value.data;
			break;
		case GeneralName::REGISTERED_ID:
			this->registeredId = value.registeredId;
			break;
		default:
			break;
	}
	
	return *this;
}

std::string GeneralName::data2IpAddress(unsigned char *data)
{
	std::string ret;
	int value, i;
	char temp[4];

	value = data[0];
	sprintf(temp, "%d", value);
	ret = temp;
	for (i=1;i<4;i++)
	{
		value = data[i];
		sprintf(temp, "%d", value);
		ret += ".";
		ret += temp;
	}
	return ret;
}
