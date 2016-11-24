#ifndef TIMESTAMPREQUEST_H_
#define TIMESTAMPREQUEST_H_

#include <openssl/ts.h>

#include <string>
#include <vector>

#include <libcryptosec/ByteArray.h>
#include <libcryptosec/BigInteger.h>
#include <libcryptosec/MessageDigest.h>
#include <libcryptosec/certificate/Extension.h>
#include <libcryptosec/exception/EncodeException.h>



class TimestampRequest
{
public:
	TimestampRequest();
	TimestampRequest(TS_REQ *req);
	TimestampRequest(ByteArray &derEncoded) throw (EncodeException);
	//TimestampRequest(const	TimestampRequest& req); 
	virtual 	~TimestampRequest();
	//virtual std::string toXml(std::string tab = "");
	//ByteArray getDerEncoded() const
	//		throw (EncodeException);
	MessageDigest::Algorithm getMessageDigestAlgorithm()
			throw (MessageDigestException);
	void setVersion(long version);
	long getVersion();
	void setMessageImprint(ObjectIdentifier algOid, ByteArray &hash);
	ByteArray* getMessageImprintDigest();
	ObjectIdentifier getMessageImprintDigestAlg();
	void setNonce(BigInteger &nonce);
	BigInteger getNonce();
	void setCertReq(bool certReq);
	bool getCertReq();
	std::vector<Extension *> getExtension(Extension::Name extensionName);
	std::vector<Extension *> getExtensions();
	TS_REQ* getTSReq() const;
	TimestampRequest& operator =(const TimestampRequest& value);
protected:
	TS_REQ *req;
};

#endif /*TIMESTAMPREQUEST_H_*/
