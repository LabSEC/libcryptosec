#ifndef GENERALNAMES_H_
#define GENERALNAMES_H_

#include <string>
#include <vector>

#include <openssl/x509v3.h>

#include <libcryptosec/ByteArray.h>

#include "GeneralName.h"
#include "ObjectIdentifier.h"
#include "RDNSequence.h"

class GeneralNames
{
public:
	GeneralNames();
	GeneralNames(GENERAL_NAMES *generalNames);
//	GeneralNames(const GeneralNames& gns);
	virtual ~GeneralNames();
	std::string getXmlEncoded();
	std::string getXmlEncoded(std::string tab);
	void addGeneralName(GeneralName &generalName);
	std::vector<GeneralName> getGeneralNames() const;
	int getNumberOfEntries() const;
	GENERAL_NAMES* getInternalGeneralNames();
	GeneralNames& operator=(const GeneralNames& value);
protected:
	std::vector<GeneralName> generalNames;

	static std::string data2IpAddress(unsigned char *data);
};

#endif /*GENERALNAMES_H_*/
