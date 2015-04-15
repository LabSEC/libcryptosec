#ifndef CERTIFICATIONEXCEPTION_H_
#define CERTIFICATIONEXCEPTION_H_

#include "LibCryptoSecException.h"

class CertificationException : public LibCryptoSecException
{
public:
	enum ErrorCode
	{
		UNKNOWN,
		INVALID_CERTIFICATE,
		INVALID_CRL,
		INVALID_EXTENSION,
		SET_NO_VALUE,
		INTERNAL_ERROR,
		UNSUPPORTED_ASYMMETRIC_KEY_TYPE,
		INVALID_TYPE,
		ADDING_EXTENSION,
		UNKNOWN_OID,
		KNOWN_OID,
	};
    CertificationException(std::string where)
    {
    	this->where = where;
    	this->errorCode = CertificationException::UNKNOWN;
    }
    CertificationException(CertificationException::ErrorCode errorCode, std::string where)
    {
    	this->where = where;
    	this->errorCode = errorCode;
    }
	virtual ~CertificationException() throw () {}
	virtual std::string getMessage() const
	{
		return (CertificationException::errorCode2Message(this->errorCode));
	}
    virtual std::string toString() const
    {
    	std::string ret;
    	if (this->errorCode == CertificationException::UNKNOWN)
    	{
    		ret = "CertificationException. Called by: " + this->where + ".";
    	}
    	else
    	{
    		ret = "CertificationException: " + CertificationException::errorCode2Message(this->errorCode) + ". Called by: " + this->where + ".";
    	}
    	return ret;
    }
    virtual CertificationException::ErrorCode getErrorCode()
    {
    	return this->errorCode;
    }
    static std::string errorCode2Message(CertificationException::ErrorCode errorCode)
    {
    	std::string ret;
    	switch (errorCode)
    	{
    		case CertificationException::UNKNOWN:
    			ret = "Unknown error";
    			break;
    		case CertificationException::INVALID_CERTIFICATE:
    			ret = "Invalid certificate object";
    			break;
    		case CertificationException::INVALID_CRL:
    			ret = "Invalid CRL object";
    			break;
    		case CertificationException::INVALID_EXTENSION:
    			ret = "Invalid extension";
    			break;
    		case CertificationException::SET_NO_VALUE:
    			ret = "Set no value";
    			break;
    		case CertificationException::INTERNAL_ERROR:
    			ret = "Internal error";
    			break;
    		case CertificationException::UNSUPPORTED_ASYMMETRIC_KEY_TYPE:
    			ret = "Unsupported asymmetric key type";
    			break;
    		case CertificationException::INVALID_TYPE:
    			ret = "Invalid type";
    			break;
    		case CertificationException::ADDING_EXTENSION:
    			ret = "Adding extension";
    			break;
    		case CertificationException::UNKNOWN_OID:
    			ret = "Unknown OID";
    			break;
    		case CertificationException::KNOWN_OID:
    			ret = "Known OID";
    			break;
//    		case CertificationException:::
//    			ret = "";
//    			break;
//    		case CertificationException:::
//    			ret = "";
//    			break;
//    		case CertificationException:::
//    			ret = "";
//    			break;
    	}
    	return ret;
    }
    
protected:
	CertificationException::ErrorCode errorCode;
};

#endif /*CERTIFICATIONEXCEPTION_H_*/
