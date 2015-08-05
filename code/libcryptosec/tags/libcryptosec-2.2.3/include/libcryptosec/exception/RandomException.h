#ifndef RANDOMEXCEPTION_H_
#define RANDOMEXCEPTION_H_

#include "LibCryptoSecException.h"

class RandomException : public LibCryptoSecException
{
public:
	enum ErrorCode
	{
		UNKNOWN,
		NO_DATA_SEEDED,
		NO_IMPLEMENTED_FUNCTION,
		INTERNAL_ERROR,
	};
    RandomException(std::string where)
    {
    	this->where = where;
    	this->errorCode = RandomException::UNKNOWN;
    }
    RandomException(RandomException::ErrorCode errorCode, std::string where)
    {
    	this->where = where;
    	this->errorCode = errorCode;
    }
	virtual ~RandomException() throw () {}
	virtual std::string getMessage() const
	{
		return (RandomException::errorCode2Message(this->errorCode));
	}
    virtual std::string toString() const
    {
    	std::string ret;
    	if (this->errorCode == RandomException::UNKNOWN)
    	{
    		ret = "RandomException. Called by: " + this->where + ".";
    	}
    	else
    	{
    		ret = "RandomException: " + RandomException::errorCode2Message(this->errorCode) + ". Called by: " + this->where + ".";
    	}
    	return ret;
    }
    virtual RandomException::ErrorCode getErrorCode()
    {
    	return this->errorCode;
    }
    static std::string errorCode2Message(RandomException::ErrorCode errorCode)
    {
    	std::string ret;
    	switch (errorCode)
    	{
    		case RandomException::UNKNOWN:
    			ret = "Unknown error";
    			break;
    		case RandomException::NO_DATA_SEEDED:
    			ret = "No data seeded";
    			break;
    		case RandomException::NO_IMPLEMENTED_FUNCTION:
    			ret = "Default random engine has not implemented this function";
    			break;
    		case RandomException::INTERNAL_ERROR:
    			ret = "Internal error";
    			break;
//    		case RandomException:::
//    			ret = "";
//    			break;
    	}
    	return ret;
    }
    
protected:
	RandomException::ErrorCode errorCode;
};

#endif /*RANDOMEXCEPTION_H_*/
