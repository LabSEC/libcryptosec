#include <libcryptosec/certificate/KeyUsageExtension.h>

KeyUsageExtension::KeyUsageExtension() : Extension()
{
//	ASN1_BIT_STRING *bitString;
//	short value;
//	bitString = ASN1_BIT_STRING_new();
//	value = 0x00;
//	ASN1_BIT_STRING_set(bitString, (unsigned char *)&value, sizeof(short));
//	this->ext = X509V3_EXT_i2d(NID_key_usage, 0, (void *)bitString);
//	ASN1_BIT_STRING_free(bitString);
	int i;
	this->objectIdentifier = ObjectIdentifierFactory::getObjectIdentifier(NID_key_usage);
	for (i=0;i<9;i++)
	{
		this->usages[i] = false;
	}
}

//KeyUsageExtension::KeyUsageExtension(std::string pemEncoded)
//{
//	ByteArray value;
//	unsigned char *temp;
//	value = Base64::decode(pemEncoded);
//	temp = (unsigned char *)OPENSSL_malloc(value.size() + 1);
//	memcpy(temp, value.getDataPointer(), value.size());
//	this->ext = d2i_X509_EXTENSION(NULL, &temp, value.size());
//}

KeyUsageExtension::KeyUsageExtension(X509_EXTENSION *ext)
		throw (CertificationException) : Extension(ext)
{
	ASN1_BIT_STRING *bitString;
	int i;
	if (OBJ_obj2nid(ext->object) != NID_key_usage)
	{
		X509_EXTENSION_free(ext);
		throw CertificationException(CertificationException::INVALID_TYPE, "KeyUsageExtension::KeyUsageExtension");
	}
	bitString = (ASN1_BIT_STRING *)X509V3_EXT_d2i(ext);
	for (i=0;i<9;i++)
	{
		this->usages[i] = (ASN1_BIT_STRING_get_bit(bitString, i))?true:false;
	}
	ASN1_BIT_STRING_free(bitString);
}

KeyUsageExtension::~KeyUsageExtension()
{
}

//std::string KeyUsageExtension::getPemEncoded()
//{
//	std::string ret;
//	unsigned char *temp = NULL;
//	ByteArray data;
//	int size;
//	
////	i2d_X509_EXTENSION()
//	
//	size = i2d_X509_EXTENSION(this->ext, &temp);
//	data = ByteArray(temp, size);
//	ret = Base64::encode(data);
//	return ret;
//}

std::string KeyUsageExtension::extValue2Xml(std::string tab)
{
	int i;
	std::string ret, string, name;
	
	for (i=0;i<9;i++)
	{
		string = this->usages[i]?"1":"0";
		name = KeyUsageExtension::usage2Name((KeyUsageExtension::Usage)i);
		{
			ret += tab + "<" + name + ">" + string + "</" + name + ">\n";
		}
	}
	
	return ret;
}

std::string KeyUsageExtension::getXmlEncoded()
{
	return this->getXmlEncoded("");
}

std::string KeyUsageExtension::getXmlEncoded(std::string tab)
{
	int i;
	std::string ret, string, name;
	ret = tab + "<keyUsage>\n";
		ret += tab + "\t<extnID>" + this->getName() + "</extnID>\n";
		string = (this->isCritical())?"yes":"no";
		ret += tab + "\t<critical>" + string + "</critical>\n";
		ret += tab + "\t<extnValue>\n";
			for (i=0;i<9;i++)
			{
				string = this->usages[i]?"1":"0";
				name = KeyUsageExtension::usage2Name((KeyUsageExtension::Usage)i);
				{
					ret += tab + "\t\t<" + name + ">" + string + "</" + name + ">\n";
				}
			}
		ret += tab + "\t</extnValue>\n";
	ret += tab + "</keyUsage>\n";
	return ret;
}

void KeyUsageExtension::setUsage(KeyUsageExtension::Usage usage, bool value)
{
//	ASN1_BIT_STRING *bitString;
//	bitString = (ASN1_BIT_STRING *)X509V3_EXT_d2i(this->ext);
//	ASN1_BIT_STRING_set_bit(bitString, (int)usage,value?1:0);
//	X509_EXTENSION_free(this->ext);
//	this->ext = X509V3_EXT_i2d(NID_key_usage, (this->isCritical())?1:0, (void *)bitString);
//	ASN1_BIT_STRING_free(bitString);
	this->usages[usage] = value;
}

bool KeyUsageExtension::getUsage(KeyUsageExtension::Usage usage)
{
//	int ret;
//	ASN1_BIT_STRING *bitString;
//	bitString = (ASN1_BIT_STRING *)X509V3_EXT_d2i(this->ext);
//	ret = ASN1_BIT_STRING_get_bit(bitString, (int)usage);
//	ASN1_BIT_STRING_free(bitString);
//	return ret?true:false;
	return this->usages[usage];
}

//void KeyUsageExtension::setUsages(bool[9] usages)+
//{
//	
//}
//
//bool[9] KeyUsageExtension::getUsages()
//{
//	
//}

X509_EXTENSION* KeyUsageExtension::getX509Extension()
{
	X509_EXTENSION *ret;
	ASN1_BIT_STRING *bitString;
	int i;
	bitString = ASN1_BIT_STRING_new();
	for (i=0;i<9;i++)
	{
		ASN1_BIT_STRING_set_bit(bitString, i, this->usages[i]?1:0);
	}
	ret = X509V3_EXT_i2d(NID_key_usage, (this->isCritical())?1:0, (void *)bitString);
	ASN1_BIT_STRING_free(bitString);
	return ret;
}

std::string KeyUsageExtension::usage2Name(KeyUsageExtension::Usage usage)
{
	std::string ret;
	switch (usage)
	{
		case KeyUsageExtension::DIGITAL_SIGNATURE:
			ret = "digitalSignature";
			break;
		case KeyUsageExtension::NON_REPUDIATION:
			ret = "nonRepudiation";
			break;
		case KeyUsageExtension::KEY_ENCIPHERMENT:
			ret = "keyEncipherment";
			break;
		case KeyUsageExtension::DATA_ENCIPHERMENT:
			ret = "dataEncipherment";
			break;
		case KeyUsageExtension::KEY_AGREEMENT:
			ret = "keyAgreement";
			break;
		case KeyUsageExtension::KEY_CERT_SIGN:
			ret = "keyCertSign";
			break;
		case KeyUsageExtension::CRL_SIGN:
			ret = "crlSign";
			break;
		case KeyUsageExtension::ENCIPHER_ONLY:
			ret = "encipherOnly";
			break;
		case KeyUsageExtension::DECIPHER_ONLY:
			ret = "decipherOnly";
			break;
	}
	return ret;
}
