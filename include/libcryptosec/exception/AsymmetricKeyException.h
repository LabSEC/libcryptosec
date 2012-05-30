#ifndef ASYMMETRICKEYEXCEPTION_H_
#define ASYMMETRICKEYEXCEPTION_H_

#include "LibCryptoSecException.h"

class AsymmetricKeyException : public LibCryptoSecException
{
public:
	enum ErrorCode
	{
		UNKNOWN,
		SET_NO_VALUE,
		INVALID_TYPE,
		INTERNAL_ERROR,
		UNAVAILABLE_KEY,
		INVALID_ASYMMETRIC_KEY,
	};
    AsymmetricKeyException(std::string where)
    {
    	this->where = where;
    	this->errorCode = AsymmetricKeyException::UNKNOWN;
    	this->details = "";
    }
    AsymmetricKeyException(AsymmetricKeyException::ErrorCode errorCode, std::string where)
    {
    	this->where = where;
    	this->errorCode = errorCode;
    	this->details = "";
    }
    AsymmetricKeyException(AsymmetricKeyException::ErrorCode errorCode, std::string details, std::string where)
    {
    	this->where = where;
    	this->errorCode = errorCode;
    	this->details = details;
    }
	virtual ~AsymmetricKeyException() throw () {}
	virtual std::string getMessage() const
	{
		return (AsymmetricKeyException::errorCode2Message(this->errorCode) + ". Details: " + this->details + ".");
	}
    virtual std::string toString() const
    {
    	std::string ret;
    	if (this->errorCode == AsymmetricKeyException::UNKNOWN)
    	{
    		ret = "AsymmetricKeyException. Called by: " + this->where + ".";
    	}
    	else
    	{
    		ret = "AsymmetricKeyException: " + AsymmetricKeyException::errorCode2Message(this->errorCode) + ". Called by: " + this->where + ".";
    	}
    	if (this->details != "")
    	{
    		ret += " More details: " + this->details + ".";
    	}
    	return ret;
	}
	virtual AsymmetricKeyException::ErrorCode getErrorCode()
	{
		return this->errorCode;
	}
	static std::string errorCode2Message(AsymmetricKeyException::ErrorCode errorCode)
	{
		std::string ret;
    	switch (errorCode)
    	{
    		case AsymmetricKeyException::UNKNOWN:
    			ret = "Unknown error";
    			break;
    		case AsymmetricKeyException::SET_NO_VALUE:
    			ret = "Set no value";
    			break;
    		case AsymmetricKeyException::INVALID_TYPE:
    			ret = "Invalid asymmetric key type";
    			break;
    		case AsymmetricKeyException::INTERNAL_ERROR:
    			ret = "Internal error";
    			break;
    		case AsymmetricKeyException::UNAVAILABLE_KEY:
    			ret = "Asymmetric key not available";
    			break;
    		case AsymmetricKeyException::INVALID_ASYMMETRIC_KEY:
    			ret = "Invalid asymmetric key";
    			break;
//    		case AsymmetricKeyException:::
//    			ret = "";
//    			break;
		}
		return ret;
	}
protected:
	AsymmetricKeyException::ErrorCode errorCode;
};

#endif /*ASYMMETRICKEYEXCEPTION_H_*/
