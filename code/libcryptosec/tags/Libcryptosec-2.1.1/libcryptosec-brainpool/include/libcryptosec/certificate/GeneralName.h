#ifndef GENERALNAME_H_
#define GENERALNAME_H_

#include <openssl/x509v3.h>

#include <string>

#include "ObjectIdentifier.h"
#include "RDNSequence.h"

class GeneralName
{
public:
	enum Type
	{
		UNDEFINED,
		OTHER_NAME,
		RFC_822_NAME,
		DNS_NAME,
//		X400_ADDRESS,
		DIRECTORY_NAME,
//		EDI_PARTY_NAME
		UNIFORM_RESOURCE_IDENTIFIER,
		IP_ADDRESS,
		REGISTERED_ID,
	};
	GeneralName();
	GeneralName(GENERAL_NAME *generalName);
//	GeneralName(const GeneralName& generalName);
	virtual ~GeneralName();
	std::string getXmlEncoded();
	std::string getXmlEncoded(std::string tab);
	void setOtherName(std::string oid, std::string data);
	pair<std::string, std::string> getOtherName() const;
	void setRfc822Name(std::string data);
	std::string getRfc822Name() const; 
	void setDnsName(std::string data);
	std::string getDnsName() const;
	void setDirectoryName(RDNSequence &data);
	RDNSequence getDirectoryName() const;
	void setUniformResourceIdentifier(std::string data);
	std::string getUniformResourceIdentifier() const;
	void setIpAddress(std::string data);
	std::string getIpAddress() const;
	void setRegisteredId(ObjectIdentifier objectIdentifier);
	ObjectIdentifier getRegisteredId() const;
	GeneralName::Type getType() const;
	GENERAL_NAME* getGeneralName();
	static std::string type2Name(GeneralName::Type type);
	GeneralName& operator=(const GeneralName& value);
	static std::string  data2IpAddress(unsigned char *data);
protected:
	GeneralName::Type type;
	std::string data; /* rfc822Name, dnsName, uniformResourceIdentifier, ipAddress */
	std::string oid; /* otherName */
	
	RDNSequence directoryName;
	ObjectIdentifier registeredId;
	
	void clean();

	static unsigned char* ipAddress2Data(std::string ipAddress);
};

#endif /*GENERALNAME_H_*/
