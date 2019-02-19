#include <libcryptosec/certificate/ExtendedKeyUsageExtension.h>

ExtendedKeyUsageExtension::ExtendedKeyUsageExtension() : Extension()
{
	this->objectIdentifier = ObjectIdentifierFactory::getObjectIdentifier(NID_ext_key_usage);
}

ExtendedKeyUsageExtension::ExtendedKeyUsageExtension(X509_EXTENSION *ext)
		throw (CertificationException) : Extension(ext)
{
	STACK_OF(ASN1_OBJECT) *extKeyUsages;
	ObjectIdentifier objectIdentifier;
	int nid;
	std::string value;
	char temp[30];
	//ASN1_OBJECT *asn1Obj, *newAsn1Obj;
	ASN1_OBJECT *asn1Obj;
	if (OBJ_obj2nid(X509_EXTENSION_get_object(ext)) != NID_ext_key_usage)
	{
		throw CertificationException(CertificationException::INVALID_TYPE, "ExtendedKeyUsageExtension::ExtendedKeyUsageExtension");
	}
	extKeyUsages = (STACK_OF(ASN1_OBJECT) *) X509V3_EXT_d2i(ext);
		
	while(sk_ASN1_OBJECT_num(extKeyUsages) > 0)
	{
		asn1Obj = sk_ASN1_OBJECT_pop(extKeyUsages);
		nid = OBJ_obj2nid(asn1Obj);
		if (nid == NID_undef)
		{
			OBJ_obj2txt(temp, 30, asn1Obj, 0);
			value = temp;
			objectIdentifier = ObjectIdentifierFactory::getObjectIdentifier(value);
		}
		else
		{
			//newAsn1Obj = OBJ_nid2obj(nid);
			//objectIdentifier = ObjectIdentifier(newAsn1Obj);
			objectIdentifier = ObjectIdentifier(asn1Obj);
		}
		this->usages.push_back(objectIdentifier);
	}
	sk_ASN1_OBJECT_free(extKeyUsages);
}

ExtendedKeyUsageExtension::~ExtendedKeyUsageExtension()
{
}

std::string ExtendedKeyUsageExtension::extValue2Xml(std::string tab)
{
	std::string ret;

	for (unsigned int i=0;i<this->usages.size();i++)
	{
		ret += tab + "<usage>" + this->usages.at(i).getName() + "</usage>\n";
	}
	
	return ret;
}

std::string ExtendedKeyUsageExtension::getXmlEncoded()
{
	return this->getXmlEncoded("");
}

std::string ExtendedKeyUsageExtension::getXmlEncoded(std::string tab)
{
	std::string ret, string;
	unsigned int i;
	ret = tab + "<extendedKeyUsage>\n";
		ret += tab + "\t<extnID>" + this->getName() + "</extnID>\n";
		string = (this->isCritical())?"yes":"no";
		ret += tab + "\t<critical>" + string + "</critical>\n";
		for (i=0;i<this->usages.size();i++)
		{
			ret += tab + "\t\t<usage>" + this->usages.at(i).getName() + "</usage>\n";
		}
	ret += tab + "</extendedKeyUsage>\n";
	return ret;
}

void ExtendedKeyUsageExtension::addUsage(ObjectIdentifier oid)
{
//	STACK_OF(ASN1_OBJECT) *extKeyUsages;
//	bool critical;
//	extKeyUsages = (STACK_OF(ASN1_OBJECT) *) X509V3_EXT_d2i(this->ext);
//	sk_ASN1_OBJECT_push(extKeyUsages, OBJ_dup(oid.getObjectIdentifier()));
//	critical = this->isCritical();
//	X509_EXTENSION_free(this->ext);
//	this->ext = X509V3_EXT_i2d(NID_ext_key_usage, (critical)?1:0, (void *)extKeyUsages);
	this->usages.push_back(oid);
}

std::vector<ObjectIdentifier> ExtendedKeyUsageExtension::getUsages()
{
//	STACK_OF(ASN1_OBJECT) *extKeyUsages;
//	ASN1_OBJECT *asn1Obj, *newAsn1Obj;
//	int i, num;
//	ObjectIdentifier objectIdentifier;
//	std::vector<ObjectIdentifier> ret;
//	char temp[30];
//	std::string value;
//	
//	extKeyUsages = (STACK_OF(ASN1_OBJECT) *)X509V3_EXT_d2i(this->ext);
//	num = sk_ASN1_OBJECT_num(extKeyUsages);
//	for (i=0;i<num;i++)
//	{
//		asn1Obj = sk_ASN1_OBJECT_value(extKeyUsages, i);
//		int nid = OBJ_obj2nid(asn1Obj);
//		if (nid == NID_undef)
//		{
//			OBJ_obj2txt(temp, 30, asn1Obj, 0);
//			value = temp;
//			objectIdentifier = ObjectIdentifierFactory::getObjectIdentifier(value);
//		}
//		else
//		{
//			newAsn1Obj = OBJ_nid2obj(nid);
//			objectIdentifier = ObjectIdentifier(newAsn1Obj);
//		}
//		ret.push_back(objectIdentifier);
//	}
//	return ret;
	return this->usages;
}

X509_EXTENSION* ExtendedKeyUsageExtension::getX509Extension()
{
	X509_EXTENSION *ret;
	ASN1_OBJECT *asn1Obj;
	STACK_OF(ASN1_OBJECT) *extKeyUsages;
	unsigned int i;
	extKeyUsages = sk_ASN1_OBJECT_new_null();
	for (i=0;i<this->usages.size();i++)
	{
		asn1Obj = OBJ_dup(this->usages.at(i).getObjectIdentifier());
		sk_ASN1_OBJECT_push(extKeyUsages, asn1Obj);
	}
	ret = X509V3_EXT_i2d(NID_ext_key_usage, this->critical?1:0, (void *)extKeyUsages);
	sk_ASN1_OBJECT_pop_free(extKeyUsages, ASN1_OBJECT_free);
	return ret;
}
