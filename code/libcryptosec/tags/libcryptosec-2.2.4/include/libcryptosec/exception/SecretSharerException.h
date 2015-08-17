#ifndef SECRETSHAREREXCEPTION_H_
#define SECRETSHAREREXCEPTION_H_

#include "LibCryptoSecException.h"

class SecretSharerException : public LibCryptoSecException
{
public:
	enum ErrorCode
	{
		UNKNOWN,
		INTERNAL_ERROR,
		INVALID_THRESHOLD_VALUE,
		INVALID_PARTS_VALUE,
	};
    SecretSharerException(std::string where)
    {
    	this->where = where;
    	this->errorCode = SecretSharerException::UNKNOWN;
    }
    SecretSharerException(SecretSharerException::ErrorCode errorCode, std::string where)
    {
    	this->where = where;
    	this->errorCode = errorCode;
    }
	virtual ~SecretSharerException() throw () {}
	virtual std::string getMessage() const
	{
		return (SecretSharerException::errorCode2Message(this->errorCode));
	}
    virtual std::string toString() const
    {
    	std::string ret;
    	if (this->errorCode == SecretSharerException::UNKNOWN)
    	{
    		ret = "SecretSharerException. Called by: " + this->where + ".";
    	}
    	else
    	{
    		ret = "SecretSharerException: " + SecretSharerException::errorCode2Message(this->errorCode) + ". Called by: " + this->where + ".";
    	}
    	return ret;
    }
    virtual SecretSharerException::ErrorCode getErrorCode()
    {
    	return this->errorCode;
    }
    static std::string errorCode2Message(SecretSharerException::ErrorCode errorCode)
    {
    	std::string ret;
    	switch (errorCode)
    	{
    		case SecretSharerException::UNKNOWN:
    			ret = "Unknown error";
    			break;
    		case SecretSharerException::INTERNAL_ERROR:
    			ret = "Internal error";
    			break;
    		case SecretSharerException::INVALID_THRESHOLD_VALUE:
    			ret = "Invalid threshold value";
    			break;
    		case SecretSharerException::INVALID_PARTS_VALUE:
    			ret = "Invalid parts value";
    			break;
//    		case ErrorCode:::
//    			ret = "";
//    			break;
    	}
    	return ret;
    }
protected:
	SecretSharerException::ErrorCode errorCode;
};

#endif /*SECRETSHAREREXCEPTION_H_*/
