#ifndef SMARTCARDMODULEEXCEPTION_H_
#define SMARTCARDMODULEEXCEPTION_H_

#include "LibCryptoSecException.h"

class SmartcardModuleException : public LibCryptoSecException
{
public:
	enum ErrorCode
	{
		UNKNOWN = 1,
		ENUMERATING_CERTIFICATES = 2,
		ENUMERATING_PRIVATE_KEYS = 3,
		DECRYPTING_DATA = 4,
		SMARTCARD_NOT_AVAILABLE = 5,
		SMARTCARD_READER_NOT_AVAILABLE = 6,
		INVALID_PIN = 0x000000A0,
		INVALID_PKCS11_MODULE = 8,
		BLOCKED_PIN = 0x000000A4,
		ID_NOT_FOUND = 9,
	};
	SmartcardModuleException(std::string where)
    {
    	this->where = where;
    	this->errorCode = SmartcardModuleException::UNKNOWN;
    	this->details = "";
    }
    SmartcardModuleException(SmartcardModuleException::ErrorCode errorCode, std::string where)
    {
    	this->where = where;
    	this->errorCode = errorCode;
    	this->details = "";
    }
    SmartcardModuleException(SmartcardModuleException::ErrorCode errorCode, std::string where, bool opensslDetails)
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
	virtual ~SmartcardModuleException() throw () {}
	virtual std::string getMessage() const
	{
		return (SmartcardModuleException::errorCode2Message(this->errorCode));
	}
    virtual std::string toString() const
    {
    	std::string ret;
    	if (this->errorCode == SmartcardModuleException::UNKNOWN)
    	{
    		ret = "SmartcardModuleException. Called by: " + this->where + ".";
    	}
    	else
    	{
    		ret = "SmartcardModuleException: " + SmartcardModuleException::errorCode2Message(this->errorCode) + ". Called by: " + this->where + ".";
    	}
    	if (this->details != "")
    	{
    		ret += " More details:\n" + this->details + ".";
    	}
    	return ret;
	}
	virtual SmartcardModuleException::ErrorCode getErrorCode()
	{
		return this->errorCode;
	}
	static std::string errorCode2Message(SmartcardModuleException::ErrorCode errorCode)
	{
		std::string ret;
    	switch (errorCode)
    	{
    		case SmartcardModuleException::UNKNOWN:
    			ret = "Unknown error";
    			break;
    		case SmartcardModuleException::ENUMERATING_CERTIFICATES:
    			ret = "Enumerating certificates";
    			break;
    		case SmartcardModuleException::ENUMERATING_PRIVATE_KEYS:
    			ret = "Enumerating private keys";
    			break;
    		case SmartcardModuleException::DECRYPTING_DATA:
    			ret = "Decrypting data";
    			break;
    		case SmartcardModuleException::SMARTCARD_NOT_AVAILABLE:
    			ret = "Smartcard not available";
    			break;
    		case SmartcardModuleException::SMARTCARD_READER_NOT_AVAILABLE:
    			ret = "Smartcard reader not available";
    			break;
    		case SmartcardModuleException::INVALID_PIN:
    			ret = "Invalid PIN";
    			break;
    		case SmartcardModuleException::INVALID_PKCS11_MODULE:
    			ret = "Invalid PKCS11 module";
    			break;
			case SmartcardModuleException::BLOCKED_PIN:
    			ret = "Blocked PIN";
    			break;
    		case SmartcardModuleException::ID_NOT_FOUND:
    			ret = "ID not found";
    			break;
//    		case SmartcardModuleException:::
//    			ret = "";
//    			break;
		}
		return ret;
	}
protected:
	SmartcardModuleException::ErrorCode errorCode;
};

#endif /*SMARTCARDMODULEEXCEPTION_H_*/
