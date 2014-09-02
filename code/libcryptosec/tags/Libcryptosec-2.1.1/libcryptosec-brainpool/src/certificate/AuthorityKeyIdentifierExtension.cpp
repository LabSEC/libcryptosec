#include <libcryptosec/certificate/AuthorityKeyIdentifierExtension.h>

AuthorityKeyIdentifierExtension::AuthorityKeyIdentifierExtension() : Extension()
{
	this->objectIdentifier = ObjectIdentifierFactory::getObjectIdentifier(NID_authority_key_identifier);
	this->serialNumber = -1;
}

AuthorityKeyIdentifierExtension::AuthorityKeyIdentifierExtension(X509_EXTENSION *ext)
		throw (CertificationException) : Extension(ext)
{
	AUTHORITY_KEYID *authKeyId;
	if (this->objectIdentifier.getNid() != NID_authority_key_identifier)
	{
		throw CertificationException(CertificationException::INVALID_TYPE, "AuthorityKeyIdentifierExtension::AuthorityKeyIdentifierExtension");
	}
	authKeyId = (AUTHORITY_KEYID *)X509V3_EXT_d2i(ext);
	if (authKeyId->keyid)
	{
		this->keyIdentifier = ByteArray(authKeyId->keyid->data, authKeyId->keyid->length);
	}
	if (authKeyId->issuer)
	{
		this->authorityCertIssuer = GeneralNames(authKeyId->issuer);
	}
	if (authKeyId->serial)
	{
		this->serialNumber = ASN1_INTEGER_get(authKeyId->serial);
	}
	else
	{
		this->serialNumber = -1;
	}
	AUTHORITY_KEYID_free(authKeyId);
}

AuthorityKeyIdentifierExtension::~AuthorityKeyIdentifierExtension()
{
}

std::string AuthorityKeyIdentifierExtension::extValue2Xml(std::string tab)
{
	std::string ret, string;
	char temp[15];

	if (this->keyIdentifier.size() > 0)
	{
		ret += tab + "<keyIdentifier>" + Base64::encode(this->keyIdentifier) + "</keyIdentifier>\n";
	}
	
	if (this->authorityCertIssuer.getNumberOfEntries() > 0)
	{
		ret += tab + "<authorityCertIssuer>\n";
		ret += this->authorityCertIssuer.getXmlEncoded(tab + "\t");
		ret += tab + "</authorityCertIssuer>\n";
	}
	
	if (this->serialNumber > 0)
	{
		sprintf(temp, "%d", (int)this->serialNumber);
		string = temp;
		ret += tab + "<authorityCertSerialNumber>" + string + "</authorityCertSerialNumber>\n";
	}
			
	return ret;
}

std::string AuthorityKeyIdentifierExtension::getXmlEncoded()
{
	return this->getXmlEncoded("");
}

std::string AuthorityKeyIdentifierExtension::getXmlEncoded(std::string tab)
{
	std::string ret, string;
	char temp[15];
	ret = tab + "<authorityKeyIdentifier>\n";
		ret += tab + "\t<extnID>" + this->getName() + "</extnID>\n";
		string = (this->critical)?"yes":"no";
		ret += tab + "\t<critical>" + string + "</critical>\n";
		ret += tab + "\t<extnValue>\n";

			if (this->keyIdentifier.size() > 0)
			{
				ret += tab + "\t\t<keyIdentifier>" + Base64::encode(this->keyIdentifier) + "</keyIdentifier>\n";
			}
			
			if (this->authorityCertIssuer.getNumberOfEntries() > 0)
			{
				ret += tab + "\t\t<authorityCertIssuer>\n";
				ret += this->authorityCertIssuer.getXmlEncoded(tab + "\t\t\t");
				ret += tab + "\t\t</authorityCertIssuer>\n";
			}
			
			if (this->serialNumber > 0)
			{
				sprintf(temp, "%d", (int)this->serialNumber);
				string = temp;
				ret += tab + "\t\t<authorityCertSerialNumber>" + string + "</authorityCertSerialNumber>\n";
			}
			
		ret += tab + "\t</extnValue>\n";
	ret += tab + "</authorityKeyIdentifier>\n";
	return ret;
}

void AuthorityKeyIdentifierExtension::setKeyIdentifier(ByteArray keyIdentifier)
{
	this->keyIdentifier = keyIdentifier;
}

ByteArray AuthorityKeyIdentifierExtension::getKeyIdentifier()
{
	return this->keyIdentifier;
}

void AuthorityKeyIdentifierExtension::setAuthorityCertIssuer(GeneralNames &generalNames)
{
	this->authorityCertIssuer = generalNames;
}

GeneralNames AuthorityKeyIdentifierExtension::getAuthorityCertIssuer()
{
	return this->authorityCertIssuer;
}

void AuthorityKeyIdentifierExtension::setAuthorityCertSerialNumber(long serialNumber)
{
	this->serialNumber = serialNumber;
}

long AuthorityKeyIdentifierExtension::getAuthorityCertSerialNumber()
{
	return this->serialNumber;
}

X509_EXTENSION* AuthorityKeyIdentifierExtension::getX509Extension()
{
	X509_EXTENSION *ret;
	AUTHORITY_KEYID *authKeyId;
	ByteArray temp;
	authKeyId = AUTHORITY_KEYID_new();
	if (this->keyIdentifier.size() > 0)
	{
		authKeyId->keyid = ASN1_OCTET_STRING_new();
		temp = this->keyIdentifier;
		ASN1_OCTET_STRING_set(authKeyId->keyid, temp.getDataPointer(), temp.size());
	}
	if (this->authorityCertIssuer.getNumberOfEntries() > 0)
	{
		authKeyId->issuer = this->authorityCertIssuer.getInternalGeneralNames();
	}
	if (this->serialNumber >= 0)
	{
		authKeyId->serial = ASN1_INTEGER_new();
		ASN1_INTEGER_set(authKeyId->serial, this->serialNumber);
	}
	ret = X509V3_EXT_i2d(NID_authority_key_identifier, this->critical?1:0, (void *)authKeyId);
	AUTHORITY_KEYID_free(authKeyId);
	return ret;
}
