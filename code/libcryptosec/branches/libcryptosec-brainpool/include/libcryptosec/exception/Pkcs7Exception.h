#ifndef PKCS7EXCEPTION_H_
#define PKCS7EXCEPTION_H_

#include "LibCryptoSecException.h"

class Pkcs7Exception : public LibCryptoSecException
{
public:
	enum ErrorCode
	{
		UNKNOWN,
		INVALID_PKCS7,
		INVALID_TYPE,
		DECRYPTING,
		INTERNAL_ERROR,
		INVALID_SYMMETRIC_CIPHER,
		INVALID_CERTIFICATE,
		ADDING_SIGNER,
		ADDING_CERTIFICATE,
	};
    Pkcs7Exception(std::string where)
    {
    	this->where = where;
    	this->errorCode = Pkcs7Exception::UNKNOWN;
    }
    Pkcs7Exception(Pkcs7Exception::ErrorCode errorCode, std::string where)
    {
    	this->where = where;
    	this->errorCode = errorCode;
    }
    Pkcs7Exception(Pkcs7Exception::ErrorCode errorCode, std::string where, bool opensslDetails)
    {
    	this->where = where;
    	this->errorCode = errorCode;
    	if (opensslDetails)
		{
			this->details = OpenSSLErrorHandler::getErrors();
		}
		else
		{
			this->details = "";
		}
    }
	virtual ~Pkcs7Exception() throw () {}
	virtual std::string getMessage() const
	{
		return (Pkcs7Exception::errorCode2Message(this->errorCode));
	}
    virtual std::string toString() const
    {
    	std::string ret;
    	if (this->errorCode == Pkcs7Exception::UNKNOWN)
    	{
    		ret = "Pkcs7Exception. Called by: " + this->where + ".";
    	}
    	else
    	{
    		ret = "Pkcs7Exception: " + Pkcs7Exception::errorCode2Message(this->errorCode) + ". Called by: " + this->where + ".";
    	}
    	if (this->details != "")
    	{
    		ret += " More details:\n" + this->details + ".";
    	}
    	return ret;
    }
    virtual Pkcs7Exception::ErrorCode getErrorCode()
    {
    	return this->errorCode;
    }
    static std::string errorCode2Message(Pkcs7Exception::ErrorCode errorCode)
    {
    	std::string ret;
    	switch (errorCode)
    	{
    		case Pkcs7Exception::UNKNOWN:
    			ret = "Unknown error";
    			break;
    		case Pkcs7Exception::INVALID_PKCS7:
    			ret = "Invalid pkcs7 structure";
    			break;
    		case Pkcs7Exception::INVALID_TYPE:
    			ret = "Invalid type";
    			break;
    		case Pkcs7Exception::DECRYPTING:
    			ret = "Decrypting";
    			break;
    		case Pkcs7Exception::INTERNAL_ERROR:
    			ret = "Internal error";
    			break;
    		case Pkcs7Exception::INVALID_SYMMETRIC_CIPHER:
    			ret = "Invalid symmetric cipher";
    			break;
    		case Pkcs7Exception::INVALID_CERTIFICATE:
    			ret = "Invalid certificate";
    			break;
    		case Pkcs7Exception::ADDING_SIGNER:
    			ret = "Adding signer";
    			break;
    		case Pkcs7Exception::ADDING_CERTIFICATE:
    			ret = "Adding certificate";
    			break;
//    		case Pkcs7Exception:::
//    			ret = "";
//    			break;
//    		case Pkcs7Exception:::
//    			ret = "";
//    			break;
    	}
    	return ret;
    }
    
protected:
	Pkcs7Exception::ErrorCode errorCode;
};

#endif /*PKCS7EXCEPTION_H_*/
