#ifndef SIGNEREXCEPTION_H_
#define SIGNEREXCEPTION_H_

#include "LibCryptoSecException.h"

class SignerException : public LibCryptoSecException
{
public:
	enum ErrorCode
	{
		UNKNOWN,
		SIGNING_DATA,
		VERIFYING_DATA,
		UNSUPPORTED_ASYMMETRIC_KEY_TYPE,
	};
    SignerException(std::string where)
    {
    	this->where = where;
    	this->errorCode = SignerException::UNKNOWN;
    }
    SignerException(SignerException::ErrorCode errorCode, std::string where)
    {
    	this->where = where;
    	this->errorCode = errorCode;
    }
	virtual ~SignerException() throw () {}
	virtual std::string getMessage() const
	{
		return (SignerException::errorCode2Message(this->errorCode));
	}
    virtual std::string toString() const
    {
    	std::string ret;
    	if (this->errorCode == SignerException::UNKNOWN)
    	{
    		ret = "SymmetricCipherException. Called by: " + this->where + ".";
    	}
    	else
    	{
    		ret = "SymmetricCipherException: " + SignerException::errorCode2Message(this->errorCode) + ". Called by: " + this->where + ".";
    	}
    	return ret;
    }
    virtual SignerException::ErrorCode getErrorCode()
    {
    	return this->errorCode;
    }
    static std::string errorCode2Message(SignerException::ErrorCode errorCode)
    {
    	std::string ret;
    	switch (errorCode)
    	{
    		case SignerException::UNKNOWN:
    			ret = "Unknown error";
    			break;
    		case SignerException::SIGNING_DATA:
    			ret = "Signing data";
    			break;
    		case SignerException::VERIFYING_DATA:
    			ret = "Verifying data";
    			break;
    		case SignerException::UNSUPPORTED_ASYMMETRIC_KEY_TYPE:
    			ret = "Unsupported asymmetric key type";
    			break;
//    		case ErrorCode:::
//    			ret = "";
//    			break;
    	}
    	return ret;
    }
protected:
	SignerException::ErrorCode errorCode;


};

#endif /*SIGNEREXCEPTION_H_*/
