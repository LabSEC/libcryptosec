#ifndef HMACEXCEPTION_H_
#define HMACEXCEPTION_H_

#include "LibCryptoSecException.h"

class HmacException : public LibCryptoSecException {

public:
	enum ErrorCode {
		UNKNOWN,
		CTX_INIT,
		CTX_UPDATE,
		CTX_FINISH,
		INVALID_ALGORITHM
	};

	HmacException(std::string where)
	{
		this->where = where;
		this->errorCode = HmacException::UNKNOWN;
	}

	HmacException(HmacException::ErrorCode errorCode, std::string where)
	{
		this->where = where;
		this->errorCode = errorCode;
	}

	~HmacException()  throw () {}

	virtual std::string getMessage() const
	{
		return (HmacException::errorCode2Message(this->errorCode));
	}

	virtual std::string toString() const
	{
    	std::string ret;
    	if (this->errorCode == HmacException::UNKNOWN)
    	{
    		ret = "HmacException. Called by: " + this->where + ".";
    	}
    	else
    	{
    		ret = "HmacException: " + HmacException::errorCode2Message(this->errorCode) + ". Called by: " + this->where + ".";
    	}
    	return ret;
	}

    virtual HmacException::ErrorCode getErrorCode()
    {
    	return this->errorCode;
    }

    static std::string errorCode2Message(HmacException::ErrorCode errorCode)
    {
    	std::string ret;
    	switch (errorCode)
    	{
    		case MessageDigestException::UNKNOWN:
    			ret = "Unknown error";
    			break;
    		case MessageDigestException::INVALID_ALGORITHM:
    			ret = "Invalid message digest algorithm";
    			break;
    		case MessageDigestException::CTX_INIT:
    			ret = "Creating hmac context";
    			break;
    		case MessageDigestException::CTX_UPDATE:
    			ret = "Updating hmac context";
    			break;
    		case MessageDigestException::CTX_FINISH:
    			ret = "Finishing hmac context";
    			break;
    	}
    	return ret;
    }

protected:
	HmacException::ErrorCode errorCode;

};

#endif
