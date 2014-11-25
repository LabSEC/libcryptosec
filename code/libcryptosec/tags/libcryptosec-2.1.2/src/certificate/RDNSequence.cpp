#include <libcryptosec/certificate/RDNSequence.h>

RDNSequence::RDNSequence()
{
	this->newEntries.clear();
//	printf("NUM: %d\n", this->newEntries.size());
}

RDNSequence::RDNSequence(X509_NAME *rdn)
{
	X509_NAME_ENTRY *nameEntry;
	int i, num;
	char *data;
	std::string value;
	std::pair<ObjectIdentifier, std::string> oneEntry;
	if (rdn)
	{
		num = sk_X509_NAME_ENTRY_num(rdn->entries);
		for (i=0;i<num;i++)
		{
			nameEntry = sk_X509_NAME_ENTRY_value(rdn->entries, i);
			oneEntry.first = ObjectIdentifier(OBJ_dup(nameEntry->object));
			
			data = (char *)ASN1_STRING_data(nameEntry->value);
			value = std::string(data);
			oneEntry.second = value;
			
			this->newEntries.push_back(oneEntry);
			
			
//			nameEntry = sk_X509_NAME_ENTRY_value(rdn->entries, i);
//			nid = OBJ_obj2nid(nameEntry->object);
//			if (nid != NID_undef)
//			{
//				if (RDNSequence::id2Type(nid) != RDNSequence::UNKNOWN)
//				{
//					data = (char *)ASN1_STRING_data(nameEntry->value);
//					value = data;
//					this->entries[RDNSequence::id2Type(nid)].push_back(value);
//				}
//				else
//				{
//					data = (char *)ASN1_STRING_data(nameEntry->value);
//					value = data;
//					oneEntry.second = value;
//					data = (char *)calloc(31, sizeof(char));
//					OBJ_obj2txt(data, 30, nameEntry->object, 1);
//					value = data;
//					free(data);
//					oneEntry.first = value;
//					this->unknownEntries.push_back(oneEntry);
//				}
//			}
		}
	}
}

RDNSequence::RDNSequence(STACK_OF(X509_NAME_ENTRY) *entries)
{
	X509_NAME_ENTRY *nameEntry;
	int i, num;
	char *data;
	std::string value;
	std::pair<ObjectIdentifier, std::string> oneEntry;
//	std::vector<std::string> entry;
//
//	for (i=0;i<14;i++)
//	{
//		this->entries.push_back(entry);
//	}
	if (entries)
	{
		num = sk_X509_NAME_ENTRY_num(entries);
		for (i=0;i<num;i++)
		{
			nameEntry = sk_X509_NAME_ENTRY_value(entries, i);
			
			oneEntry.first = ObjectIdentifier(OBJ_dup(nameEntry->object));
			
			data = (char *)ASN1_STRING_data(nameEntry->value);
			value = data;
			oneEntry.second = value;
			
			this->newEntries.push_back(oneEntry);
			
//			nid = OBJ_obj2nid(nameEntry->object);
//			if (nid != NID_undef)
//			{
//				if (RDNSequence::id2Type(nid) != RDNSequence::UNKNOWN)
//				{
//					data = (char *)ASN1_STRING_data(nameEntry->value);
//					value = data;
//					this->entries[RDNSequence::id2Type(nid)].push_back(value);
//				}
//				else
//				{
//					data = (char *)ASN1_STRING_data(nameEntry->value);
//					value = data;
//					oneEntry.second = value;
//					data = (char *)calloc(31, sizeof(char));
//					OBJ_obj2txt(data, 30, nameEntry->object, 1);
//					value = data;
//					free(data);
//					oneEntry.first = value;
//					this->unknownEntries.push_back(oneEntry);
//				}
//			}
		}
	}
}

RDNSequence::~RDNSequence()
{
}

std::string RDNSequence::getXmlEncoded()
{
	return this->getXmlEncoded("");
}

std::string RDNSequence::getXmlEncoded(std::string tab)
{
	std::string ret;
	int nid;
//	unsigned int j;
//	std::map<RDNSequence::EntryType, std::vector<std::string> >::iterator iter;
	std::vector<std::pair<ObjectIdentifier, std::string> >::iterator iterEntries;
	
	ret = tab + "<RDNSequence>\n";
	
	for (iterEntries = this->newEntries.begin();iterEntries != this->newEntries.end();iterEntries++)
	{
		nid = iterEntries->first.getNid();
		if (RDNSequence::id2Type(nid) != RDNSequence::UNKNOWN)
		{
			ret += tab + "\t<" + RDNSequence::getNameId(RDNSequence::id2Type(nid)) + ">" + iterEntries->second + "</" + RDNSequence::getNameId(RDNSequence::id2Type(nid)) + ">\n";
		}
		else
		{
			ret += tab + "\t<unknownAttribute>" + iterEntries->first.getOid() + ":" + iterEntries->second + "</unknownAttribute>\n";
		}
	}
	
//	for (iter = this->entries.begin();iter != this->entries.end();iter++)
//	{
//		for (j=0;j<iter->second.size();j++)
//		{
//			ret += tab + "\t<" + RDNSequence::getNameId(iter->first) + ">" + iter->second.at(j) + "</" + RDNSequence::getNameId(iter->first) + ">\n";
//		}
//	}
//	
//	for (iterUnknown = this->unknownEntries.begin();iterUnknown != this->unknownEntries.end();iterUnknown++)
//	{
//		ret += tab + "\t<unknownAttribute>" + iterUnknown->first + ":" + iterUnknown->second + "</unknownAttribute>\n";
//	}
	
	ret += tab + "</RDNSequence>\n";
	return ret;
}

void RDNSequence::addEntry(RDNSequence::EntryType type, std::string value)
{
//	this->entries[type].push_back(value);
	std::pair<ObjectIdentifier, std::string> oneEntry;
	ObjectIdentifier oid;
	if (type != RDNSequence::UNKNOWN)
	{
		oneEntry.first = ObjectIdentifierFactory::getObjectIdentifier(RDNSequence::type2Id(type));
		oneEntry.second = value;
		this->newEntries.push_back(oneEntry);
	}
}

void RDNSequence::addEntry(RDNSequence::EntryType type, std::vector<std::string> values)
{
	unsigned int i;
	for (i=0;i<values.size();i++)
	{
		this->addEntry(type, values.at(i));
	}
}

std::vector<std::string> RDNSequence::getEntries(RDNSequence::EntryType type)
{
//	return this->entries[type];
	unsigned int i;
	std::vector<std::string> ret;
	for (i=0;i<this->newEntries.size();i++)
	{
		if (id2Type(OBJ_obj2nid(this->newEntries.at(i).first.getObjectIdentifier())) == type)
		{
			ret.push_back(this->newEntries.at(i).second);
		}
	}
	return ret;
}

std::vector<std::pair<ObjectIdentifier, std::string> > RDNSequence::getUnknownEntries()
{
//	std::vector<std::string> ret;
	std::vector<std::pair<ObjectIdentifier, std::string> > ret;
	std::pair<ObjectIdentifier, std::string> oneEntry;
	unsigned int i;
	for (i=0;i<this->newEntries.size();i++)
	{
		if (id2Type(OBJ_obj2nid(this->newEntries.at(i).first.getObjectIdentifier())) == RDNSequence::UNKNOWN)
		{
			oneEntry.first = this->newEntries.at(i).first;
			oneEntry.second = this->newEntries.at(i).second;
			ret.push_back(oneEntry);
		}
	}
	return ret;
}

std::vector<std::pair<ObjectIdentifier, std::string> > RDNSequence::getEntries() const
{
	return this->newEntries;
}

X509_NAME* RDNSequence::getX509Name()
{
//	unsigned int j;
	X509_NAME *ret;
	X509_NAME_ENTRY *entry;
//	ASN1_OBJECT *asn1Obj;
	std::string data;
//	std::map<RDNSequence::EntryType, std::vector<std::string> >::iterator iter;
	
//	std::vector<std::pair<std::string, std::string> >::iterator iterUnknown;

	std::vector<std::pair<ObjectIdentifier, std::string> >::iterator iterEntries;
	
	ret = X509_NAME_new();
	
	for (iterEntries = this->newEntries.begin();iterEntries != this->newEntries.end();iterEntries++)
	{
//		printf("Num: %s - %s\n", RDNSequence::getNameId(RDNSequence::id2Type(iterEntries->first.getNid())).c_str(), iterEntries->second.c_str());
		entry = X509_NAME_ENTRY_new();
		X509_NAME_ENTRY_set_object(entry, iterEntries->first.getObjectIdentifier());
		data = iterEntries->second;
		X509_NAME_ENTRY_set_data(entry, MBSTRING_ASC, (unsigned char *)data.c_str(), data.length());
		X509_NAME_add_entry(ret, entry, -1, 0);
		X509_NAME_ENTRY_free(entry);
		
		
//		asn1Obj = OBJ_nid2obj(RDNSequence::type2Id(iter->first));
//		for (j=0;j<iter->second.size();j++)
//		{
//			entry = X509_NAME_ENTRY_new();
//			X509_NAME_ENTRY_set_object(entry, asn1Obj);
//			data = iter->second.at(j);
//			X509_NAME_ENTRY_set_data(entry, MBSTRING_ASC, (unsigned char *)data.c_str(), data.length());
//			X509_NAME_add_entry(ret, entry, -1, 0);
//			X509_NAME_ENTRY_free(entry);
//		}
//		ASN1_OBJECT_free(asn1Obj);
	}
//	for (iterUnknown = this->unknownEntries.begin();iterUnknown != this->unknownEntries.end();iterUnknown++)
//	{
//		asn1Obj = OBJ_txt2obj(iterUnknown->first.c_str(), 1);
//		entry = X509_NAME_ENTRY_new();
//		X509_NAME_ENTRY_set_object(entry, asn1Obj);
//		X509_NAME_ENTRY_set_data(entry, MBSTRING_ASC, (unsigned char *)iterUnknown->second.c_str(), iterUnknown->second.length());
//		X509_NAME_add_entry(ret, entry, -1, 0);
//		X509_NAME_ENTRY_free(entry);
//		ASN1_OBJECT_free(asn1Obj);
//	}
//	X509_NAME_print_ex_fp(stderr, ret, 0, 0);
	return ret;
}

std::string RDNSequence::getNameId(RDNSequence::EntryType type)
{
	std::string ret;
	switch (type)
	{
		case RDNSequence::COUNTRY:
			ret = "countryName";
			break;
		case RDNSequence::ORGANIZATION:
			ret = "organizationName";
			break;
		case RDNSequence::ORGANIZATION_UNIT:
			ret = "organizationalUnitName";
			break;
		case RDNSequence::DN_QUALIFIER:
			ret = "dnQualifier";
			break;
		case RDNSequence::STATE_OR_PROVINCE:
			ret = "stateOrProvinceName";
			break;
		case RDNSequence::COMMON_NAME:
			ret = "commonName";
			break;
		case RDNSequence::SERIAL_NUMBER:
			ret = "serialNumber";
			break;
		case RDNSequence::LOCALITY:
			ret = "localityName";
			break;
		case RDNSequence::TITLE:
			ret = "title";
			break;
		case RDNSequence::SURNAME:
			ret = "surname";
			break;
		case RDNSequence::GIVEN_NAME:
			ret = "givenName";
			break;
		case RDNSequence::INITIALS:
			ret = "initials";
			break;
		case RDNSequence::PSEUDONYM:
			ret = "pseudonym";
			break;
		case RDNSequence::GENERATION_QUALIFIER:
			ret = "generationQualifier";
			break;
		case RDNSequence::EMAIL:
			ret = "e-mail";
			break;
		case RDNSequence::DOMAIN_COMPONENT:
			ret = "domainComponent";
			break;
		default:
			ret = "unsupported";
			break;
	}
	return ret;
}

RDNSequence::EntryType RDNSequence::id2Type(int id)
{
	RDNSequence::EntryType ret;
	switch (id)
	{
		case NID_countryName:
			ret = RDNSequence::COUNTRY;
			break;
		case NID_organizationName:
			ret = RDNSequence::ORGANIZATION;
			break;
		case NID_organizationalUnitName:
			ret = RDNSequence::ORGANIZATION_UNIT;
			break;
		case NID_dnQualifier:
			ret = RDNSequence::DN_QUALIFIER;
			break;
		case NID_stateOrProvinceName:
			ret = RDNSequence::STATE_OR_PROVINCE;
			break;
		case NID_commonName:
			ret = RDNSequence::COMMON_NAME;
			break;
		case NID_serialNumber:
			ret = RDNSequence::SERIAL_NUMBER;
			break;
		case NID_localityName:
			ret = RDNSequence::LOCALITY;
			break;
		case NID_title:
			ret = RDNSequence::TITLE;
			break;
		case NID_surname:
			ret = RDNSequence::SURNAME;
			break;
		case NID_givenName:
			ret = RDNSequence::GIVEN_NAME;
			break;
		case NID_initials:
			ret = RDNSequence::INITIALS;
			break;
		case NID_pseudonym:
			ret = RDNSequence::PSEUDONYM;
			break;
		case NID_generationQualifier:
			ret = RDNSequence::GENERATION_QUALIFIER;
			break;
		case NID_pkcs9_emailAddress:
			ret = RDNSequence::EMAIL;
			break;
		case NID_domainComponent:
			ret = RDNSequence::DOMAIN_COMPONENT;
			break;
		default:
			ret = RDNSequence::UNKNOWN;
	}
	return ret;
}

int RDNSequence::type2Id(RDNSequence::EntryType type)
{
	int ret;
	switch (type)
	{
		case RDNSequence::COUNTRY:
			ret = NID_countryName;
			break;
		case RDNSequence::ORGANIZATION:
			ret = NID_organizationName;
			break;
		case RDNSequence::ORGANIZATION_UNIT:
			ret = NID_organizationalUnitName;
			break;
		case RDNSequence::DN_QUALIFIER:
			ret = NID_dnQualifier;
			break;
		case RDNSequence::STATE_OR_PROVINCE:
			ret = NID_stateOrProvinceName;
			break;
		case RDNSequence::COMMON_NAME:
			ret = NID_commonName;
			break;
		case RDNSequence::SERIAL_NUMBER:
			ret = NID_serialNumber;
			break;
		case RDNSequence::LOCALITY:
			ret = NID_localityName;
			break;
		case RDNSequence::TITLE:
			ret = NID_title;
			break;
		case RDNSequence::SURNAME:
			ret = NID_surname;
			break;
		case RDNSequence::GIVEN_NAME:
			ret = NID_givenName;
			break;
		case RDNSequence::INITIALS:
			ret = NID_initials;
			break;
		case RDNSequence::PSEUDONYM:
			ret = NID_pseudonym;
			break;
		case RDNSequence::GENERATION_QUALIFIER:
			ret = NID_generationQualifier;
			break;
		case RDNSequence::EMAIL:
			ret = NID_pkcs9_emailAddress;
			break;
		case RDNSequence::DOMAIN_COMPONENT:
			ret = NID_domainComponent;
			break;
		case RDNSequence::UNKNOWN:
			ret = NID_undef;
			break;
	}
	return ret;
}

RDNSequence& RDNSequence::operator =(const RDNSequence& value)
{
	this->newEntries = value.getEntries();
	return *this;
}
