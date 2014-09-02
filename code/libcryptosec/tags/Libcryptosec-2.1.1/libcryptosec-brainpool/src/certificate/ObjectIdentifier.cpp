#include <libcryptosec/certificate/ObjectIdentifier.h>

ObjectIdentifier::ObjectIdentifier()
{
	this->asn1Object = ASN1_OBJECT_new();
//	printf("New OID: nid: %d - length: %d\n", this->asn1Object->nid, this->asn1Object->length);
}

ObjectIdentifier::ObjectIdentifier(ASN1_OBJECT *asn1Object)
{
	this->asn1Object = asn1Object;
//	printf("Set OID: nid: %d - length: %d\n", this->asn1Object->nid, this->asn1Object->length);
}

ObjectIdentifier::ObjectIdentifier(const ObjectIdentifier& objectIdentifier)
{
	this->asn1Object = OBJ_dup(objectIdentifier.getObjectIdentifier());
}

ObjectIdentifier::~ObjectIdentifier()
{
	ASN1_OBJECT_free(this->asn1Object);
}

std::string ObjectIdentifier::getXmlEncoded()
{
	return this->getXmlEncoded("");
}

std::string ObjectIdentifier::getXmlEncoded(std::string tab)
{
	std::string ret, oid;
	try
	{
		oid = this->getOid();
	}
	catch (...)
	{
		oid = "";
	}
	ret = tab + "<oid>" + oid + "</oid>\n";
	return ret;
}

std::string ObjectIdentifier::getOid()
		throw (CertificationException)
{
	char data[30];
	if (!this->asn1Object->data)
	{
		throw CertificationException(CertificationException::SET_NO_VALUE, "ObjectIdentifier::getOid");
	}
	OBJ_obj2txt(data, 30, this->asn1Object, 1);
	return std::string(data);
}

int ObjectIdentifier::getNid() const
{
	return OBJ_obj2nid(this->asn1Object);
}

std::string ObjectIdentifier::getName()
{
	const char *data;
	std::string ret;
	if (!this->asn1Object->data)
	{
		return "undefined";
	}
	if (this->asn1Object->nid)
	{
		data = OBJ_nid2sn(this->asn1Object->nid);
		ret = data;
	}
	else if ((this->asn1Object->nid = OBJ_obj2nid(this->asn1Object)) != NID_undef)
	{
		data = OBJ_nid2sn(this->asn1Object->nid);
		ret = data;
	}
	else
	{
		ret = this->getOid();
	}
	return ret;
}

ASN1_OBJECT* ObjectIdentifier::getObjectIdentifier() const
{
	return this->asn1Object;
}

ObjectIdentifier& ObjectIdentifier::operator =(const ObjectIdentifier& value)
{	
	if (this->asn1Object)
	{
		ASN1_OBJECT_free(this->asn1Object);
	}
	if (value.getObjectIdentifier()->length > 0)
	{
		this->asn1Object = OBJ_dup(value.getObjectIdentifier());
	}
	else
	{
		this->asn1Object = ASN1_OBJECT_new();
	}
	return (*this);
}
