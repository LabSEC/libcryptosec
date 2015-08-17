#ifndef SYMMETRICCIPHEREXCEPTION_H_
#define SYMMETRICCIPHEREXCEPTION_H_

#include "LibCryptoSecException.h"

class SymmetricCipherException : public LibCryptoSecException
{
public:
	enum ErrorCode
	{
		UNKNOWN,
		INVALID_CIPHER,
		CTX_INIT,
		CTX_UPDATE,
		CTX_FINISH,
		NO_INPUT_DATA,
	};
    SymmetricCipherException(std::string where)
    {
    	this->where = where;
    	this->errorCode = SymmetricCipherException::UNKNOWN;
    }
    SymmetricCipherException(SymmetricCipherException::ErrorCode errorCode, std::string where)
    {
    	this->where = where;
    	this->errorCode = errorCode;
    }
	virtual ~SymmetricCipherException() throw () {}
	virtual std::string getMessage() const
	{
		return (SymmetricCipherException::errorCode2Message(this->errorCode));
	}
    virtual std::string toString() const
    {
    	std::string ret;
    	if (this->errorCode == SymmetricCipherException::UNKNOWN)
    	{
    		ret = "SymmetricCipherException. Called by: " + this->where + ".";
    	}
    	else
    	{
    		ret = "SymmetricCipherException: " + SymmetricCipherException::errorCode2Message(this->errorCode) + ". Called by: " + this->where + ".";
    	}
    	return ret;
    }
    virtual SymmetricCipherException::ErrorCode getErrorCode()
    {
    	return this->errorCode;
    }
    static std::string errorCode2Message(SymmetricCipherException::ErrorCode errorCode)
    {
    	std::string ret;
    	switch (errorCode)
    	{
    		case SymmetricCipherException::UNKNOWN:
    			ret = "Unknown error";
    			break;
    		case SymmetricCipherException::INVALID_CIPHER:
    			ret = "Invalid symmetric cipher";
    			break;
    		case SymmetricCipherException::CTX_INIT:
    			ret = "Creating symmetric cipher context";
    			break;
    		case SymmetricCipherException::CTX_UPDATE:
    			ret = "Updating symmetric cipher context";
    			break;
    		case SymmetricCipherException::CTX_FINISH:
    			ret = "Finishing symmetric cipher context";
    			break;
    		case SymmetricCipherException::NO_INPUT_DATA:
    			ret = "No input data";
    			break;
//    		case SymmetricCipherException::NO_INPUT_DATA:
//    			ret = "";
//    			break;
//    		case SymmetricCipherException::NO_INPUT_DATA:
//    			ret = "";
//    			break;
//    		case SymmetricCipherException::NO_INPUT_DATA:
//    			ret = "";
//    			break;
    	}
    	return ret;
    }
protected:
	SymmetricCipherException::ErrorCode errorCode;
};

#endif /*SYMMETRICCIPHEREXCEPTION_H_*/
