#ifndef BIGINTEGEREXCEPTION_H_
#define BIGINTEGEREXCEPTION_H_

#include <openssl/err.h>
#include "LibCryptoSecException.h"

class BigIntegerException : public LibCryptoSecException
{
public:
	enum ErrorCode
	{
		UNKNOWN = 0,
		MEMORY_ALLOC = 1,
		INTERNAL_ERROR = 3,
		UNSIGNED_LONG_OVERFLOW = 4,
		DIVISION_BY_ZERO = 5,
	};
	
	BigIntegerException(ErrorCode errorCode = UNKNOWN, std::string where = "")
	{
		this->where = where;
		this->errorCode = errorCode;
	}
	virtual ~BigIntegerException() throw() {}
	
	virtual std::string getMessage() const
	{
		return (BigIntegerException::errorCode2Message(this->errorCode));
	}
	
    virtual std::string toString() const
    {
    	std::string ret;
    	if (this->errorCode == BigIntegerException::UNKNOWN)
    	{
    		ret = "BigIntegerException. Called by: " + this->where + ".";
    	}
    	else
    	{
    		ret = "BigIntegerException: " + BigIntegerException::errorCode2Message(this->errorCode) + ". Called by: " + this->where + ".";
    	}
    	return ret;
    }
    
    virtual ErrorCode getErrorCode()
    {
    	return this->errorCode;
    }
    
    static std::string errorCode2Message(ErrorCode errorCode)
    {
    	std::string ret;
    	switch (errorCode)
    	{
    		case UNKNOWN:
    			ret = "Unknown error";
    			break;
    		case MEMORY_ALLOC:
    			ret = "Memory allocation error";
    			break;
    		case INTERNAL_ERROR:
    			ret = "OpenSSL BIGNUM operation internal error";
    			break;
    		case UNSIGNED_LONG_OVERFLOW:
    			ret = "Big Integer can not be represented as unsigned long";
    			break;
    		case DIVISION_BY_ZERO:
    		    ret = "Division by zero";
    		    break;
  
    	}
    	return ret;
    }
    
protected:
	ErrorCode errorCode;
};

#endif /*BIGINTEGEREXCEPTION_H_*/
