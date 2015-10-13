#ifndef RDNSEQUENCE_H_
#define RDNSEQUENCE_H_

#include <openssl/x509.h>

#include <string>
#include <iostream>
#include <vector>
#include <map>

#include <libcryptosec/ByteArray.h>
#include "ObjectIdentifier.h"
#include "ObjectIdentifierFactory.h"

#include <libcryptosec/exception/CertificationException.h>

class RDNSequence
{
public:
	enum EntryType
	{
		COUNTRY = 0,
		STATE_OR_PROVINCE = 1,
		LOCALITY = 2,
		ORGANIZATION = 3,
		ORGANIZATION_UNIT = 4,
		COMMON_NAME = 5,
		EMAIL = 6,
		DN_QUALIFIER = 7,
		SERIAL_NUMBER = 8,
		TITLE = 9,
		SURNAME = 10,
		GIVEN_NAME = 11,
		INITIALS = 12,
		PSEUDONYM = 13,
		GENERATION_QUALIFIER = 14,
		DOMAIN_COMPONENT = 15,
		UNKNOWN = 16,
	};
	
	RDNSequence();
	RDNSequence(X509_NAME *rdn);
	RDNSequence(STACK_OF(X509_NAME_ENTRY) *entries);
	virtual ~RDNSequence();
	std::string getXmlEncoded();
	std::string getXmlEncoded(std::string tab);
	void addEntry(RDNSequence::EntryType type, std::string value);
	void addEntry(RDNSequence::EntryType type, std::vector<std::string> values);
	std::vector<std::string> getEntries(RDNSequence::EntryType type);
	std::vector<std::pair<ObjectIdentifier, std::string> > getUnknownEntries();
	std::vector<std::pair<ObjectIdentifier, std::string> > getEntries() const;
	X509_NAME* getX509Name();
	RDNSequence& operator =(const RDNSequence& value);
protected:
//	std::map<EntryType, std::vector<std::string> > entries;
//	std::vector<std::pair<std::string, std::string> > unknownEntries;
	
	std::vector<std::pair<ObjectIdentifier, std::string> > newEntries;

	static RDNSequence::EntryType id2Type(int id);
	static int type2Id(RDNSequence::EntryType type);
	static std::string getNameId(RDNSequence::EntryType type);

//	std::string getNameId(RDNSequence::EntryType type);
};

#endif /*RDNSEQUENCE_H_*/
