#ifndef ASYMMETRICCIPHEREXCEPTION_H_
#define ASYMMETRICCIPHEREXCEPTION_H_

#include "LibCryptoSecException.h"

class AsymmetricCipherException : public LibCryptoSecException
{
public:
    enum ErrorCode
	{
		UNKNOWN,
		ENCRYPTING_DATA,
		DECRYPTING_DATA,
	};
    AsymmetricCipherException(std::string where)
    {
    	this->where = where;
    	this->errorCode = AsymmetricCipherException::UNKNOWN;
    }
    AsymmetricCipherException(AsymmetricCipherException::ErrorCode errorCode, std::string where)
    {
    	this->where = where;
    	this->errorCode = errorCode;
    }
	virtual ~AsymmetricCipherException() throw () {}
	virtual std::string getMessage() const
	{
		return (AsymmetricCipherException::errorCode2Message(this->errorCode));
	}
    virtual std::string toString() const
    {
    	std::string ret;
    	if (this->errorCode == AsymmetricCipherException::UNKNOWN)
    	{
    		ret = "AsymmetricCipherException. Called by: " + this->where + ".";
    	}
    	else
    	{
    		ret = "AsymmetricCipherException: " + AsymmetricCipherException::errorCode2Message(this->errorCode) + ". Called by: " + this->where + ".";
    	}
    	return ret;
    }
    virtual AsymmetricCipherException::ErrorCode getErrorCode()
    {
    	return this->errorCode;
    }
    static std::string errorCode2Message(AsymmetricCipherException::ErrorCode errorCode)
    {
    	std::string ret;
    	switch (errorCode)
    	{
    		case AsymmetricCipherException::UNKNOWN:
    			ret = "Unknown error";
    			break;
    		case AsymmetricCipherException::ENCRYPTING_DATA:
    			ret = "Encrypting data";
    			break;
    		case AsymmetricCipherException::DECRYPTING_DATA:
    			ret = "Decrypting data";
    			break;
//    		case ErrorCode:::
//    			ret = "";
//    			break;
    	}
    	return ret;
    }
protected:
	AsymmetricCipherException::ErrorCode errorCode;
};

#endif /*ASYMMETRICCIPHEREXCEPTION_H_*/
