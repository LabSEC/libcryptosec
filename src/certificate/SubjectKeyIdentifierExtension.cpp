#include <libcryptosec/certificate/SubjectKeyIdentifierExtension.h>

SubjectKeyIdentifierExtension::SubjectKeyIdentifierExtension() : Extension()
{
	this->objectIdentifier = ObjectIdentifierFactory::getObjectIdentifier(NID_subject_key_identifier);
}

SubjectKeyIdentifierExtension::SubjectKeyIdentifierExtension(X509_EXTENSION *ext)
		throw (CertificationException) : Extension(ext)
{
	ASN1_OCTET_STRING *octetString;
	if (OBJ_obj2nid(X509_EXTENSION_get_object(ext)) != NID_subject_key_identifier)
	{
		throw CertificationException(CertificationException::INVALID_TYPE, "SubjectKeyIdentifierExtension::SubjectKeyIdentifierExtension");
	}
	octetString = (ASN1_OCTET_STRING *)X509V3_EXT_d2i(ext);
	keyIdentifier = ByteArray(octetString->data, octetString->length);
	ASN1_OCTET_STRING_free(octetString);
}

SubjectKeyIdentifierExtension::~SubjectKeyIdentifierExtension()
{
}

std::string SubjectKeyIdentifierExtension::extValue2Xml(std::string tab)
{
	std::string ret, string;
	ByteArray subjKeyId;

	subjKeyId = this->getKeyIdentifier();
	ret += tab + "<keyIdentifier>" + Base64::encode(subjKeyId) + "</keyIdentifier>\n";

	return ret;
}

std::string SubjectKeyIdentifierExtension::getXmlEncoded()
{
	return this->getXmlEncoded("");
}

std::string SubjectKeyIdentifierExtension::getXmlEncoded(std::string tab)
{
	std::string ret, string;
	ByteArray subjKeyId;
	ret = tab + "<subjectKeyIdentifier>\n";
		ret += tab + "\t<extnID>" + this->getName() + "</extnID>\n";
		string = (this->isCritical())?"yes":"no";
		ret += tab + "\t<critical>" + string + "</critical>\n";
		subjKeyId = this->getKeyIdentifier();
		ret += tab + "\t<extnValue>" + Base64::encode(subjKeyId) + "</extnValue>\n";

	ret += tab + "</subjectKeyIdentifier>\n";
	return ret;
}

void SubjectKeyIdentifierExtension::setKeyIdentifier(ByteArray keyIdentifier)
{
	this->keyIdentifier = keyIdentifier;
}

ByteArray SubjectKeyIdentifierExtension::getKeyIdentifier() const
{
	return this->keyIdentifier;
}

X509_EXTENSION* SubjectKeyIdentifierExtension::getX509Extension()
{
	X509_EXTENSION *ret;
	ASN1_OCTET_STRING *octetString;
	ByteArray data;
	
	ret = X509_EXTENSION_new();
	octetString = ASN1_OCTET_STRING_new();
	data = this->keyIdentifier;
	ASN1_OCTET_STRING_set(octetString, data.getDataPointer(), data.size());
	ret = X509V3_EXT_i2d(NID_subject_key_identifier, this->critical?1:0, (void *)octetString);
	return ret;
}
