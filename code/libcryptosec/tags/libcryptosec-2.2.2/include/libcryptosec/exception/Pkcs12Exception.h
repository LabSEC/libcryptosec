#ifndef PKCS12EXCEPTION_H_
#define PKCS12EXCEPTION_H_

#include "LibCryptoSecException.h"

class Pkcs12Exception : public LibCryptoSecException
{
public:
	Pkcs12Exception();
	virtual ~Pkcs12Exception() throw() {};
	
	enum ErrorCode
	{
		UNKNOWN,
		KEY_AND_CERT_DO_NOT_MATCH,
		PARSE_ERROR,
		MAC_VERIFY_FAILURE,
	};

	Pkcs12Exception(std::string where)
    {
    	this->where = where;
    	this->errorCode = Pkcs12Exception::UNKNOWN;
    }
    Pkcs12Exception(Pkcs12Exception::ErrorCode errorCode, std::string where)
    {
    	this->where = where;
    	this->errorCode = errorCode;
    }
	
	virtual std::string getMessage() const
	{
		return (Pkcs12Exception::errorCode2Message(this->errorCode));
	}
   
	virtual std::string toString() const
    {
    	std::string ret;
    	if (this->errorCode == Pkcs12Exception::UNKNOWN)
    	{
    		ret = "Pkcs12Exception. Called by: " + this->where + ".";
    	}
    	else
    	{
    		ret = "Pkcs12Exception: " + Pkcs12Exception::errorCode2Message(this->errorCode) + ". Called by: " + this->where + ".";
    	}
    	if (this->details != "")
    	{
    		ret += " More details:\n" + this->details + ".";
    	}
    	return ret;
    }
	
    virtual Pkcs12Exception::ErrorCode getErrorCode()
    {
    	return this->errorCode;
    }
    
    static std::string errorCode2Message(Pkcs12Exception::ErrorCode errorCode)
    {
    	std::string ret;
    	switch (errorCode)
    	{
    		case Pkcs12Exception::UNKNOWN:
    			ret = "Unknown error";
    			break;
    		case Pkcs12Exception::KEY_AND_CERT_DO_NOT_MATCH:
    			ret = "Key and certificate do not match";
    			break;
    		case Pkcs12Exception::MAC_VERIFY_FAILURE : 
    			ret = "MAC verification failure";
    			break;
    		case Pkcs12Exception::PARSE_ERROR :
    			ret = "Parse error";
    			break;
    			//    		case Pkcs12Exception:::
    			//    			ret = "";
    			//    			break;
    			//    		case Pkcs12Exception:::
    			//    			ret = "";
    			//    			break;    			
    	}
    	return ret;
    }
    
protected:
	Pkcs12Exception::ErrorCode errorCode;
};

#endif /*PKCS12EXCEPTION_H_*/
