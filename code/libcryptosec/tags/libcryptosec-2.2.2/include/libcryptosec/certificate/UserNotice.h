#ifndef USERNOTICE_H_
#define USERNOTICE_H_

#include <openssl/asn1.h>
#include <openssl/x509v3.h>

#include <string>
#include <vector>

#include <libcryptosec/exception/CertificationException.h>

class UserNotice
{
public:
	UserNotice();
	UserNotice(USERNOTICE *userNotice);
	virtual ~UserNotice();
	std::string getXmlEncoded();
	std::string getXmlEncoded(std::string tab);
	void setNoticeReference(std::string organization, std::vector<long> noticeNumbers);
	std::pair<std::string, std::vector<long> > getNoticeReference();
	void setExplicitText(std::string explicitText);
	std::string getExplicitText();
	USERNOTICE* getUserNotice() const;
protected:
	std::string organization;
	std::vector<long> noticeNumbers;
	std::string explicitText;
};

#endif /*USERNOTICE_H_*/
