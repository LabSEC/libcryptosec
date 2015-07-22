#ifndef NETSCAPESPKIEXCEPTION_H_
#define NETSCAPESPKIEXCEPTION_H_

#include "LibCryptoSecException.h"

class NetscapeSPKIException : public LibCryptoSecException
{
public:
	enum ErrorCode
	{
		UNKNOWN,
		SIGNING_SPKI,
		INVALID_SPKI,
		SET_NO_VALUE,
	};
    NetscapeSPKIException(std::string where)
    {
    	this->where = where;
    	this->errorCode = NetscapeSPKIException::UNKNOWN;
    }
    NetscapeSPKIException(NetscapeSPKIException::ErrorCode errorCode, std::string where)
    {
    	this->where = where;
    	this->errorCode = errorCode;
    }
	virtual ~NetscapeSPKIException() throw () {}
	virtual std::string getMessage() const
	{
		return (NetscapeSPKIException::errorCode2Message(this->errorCode));
	}
    virtual std::string toString() const
    {
    	std::string ret;
    	if (this->errorCode == NetscapeSPKIException::UNKNOWN)
    	{
    		ret = "NetscapeSPKIException. Called by: " + this->where + ".";
    	}
    	else
    	{
    		ret = "NetscapeSPKIException: " + NetscapeSPKIException::errorCode2Message(this->errorCode) + ". Called by: " + this->where + ".";
    	}
    	return ret;
    }
    virtual NetscapeSPKIException::ErrorCode getErrorCode()
    {
    	return this->errorCode;
    }
    static std::string errorCode2Message(NetscapeSPKIException::ErrorCode errorCode)
    {
    	std::string ret;
    	switch (errorCode)
    	{
    		case NetscapeSPKIException::UNKNOWN:
    			ret = "Unknown error";
    			break;
    		case NetscapeSPKIException::SIGNING_SPKI:
    			ret = "Signing SPKI";
    			break;
    		case NetscapeSPKIException::INVALID_SPKI:
    			ret = "Invalid SPKI";
    			break;
    		case NetscapeSPKIException::SET_NO_VALUE:
    			ret = "Set no value";
    			break;
//    		case NetscapeSPKIException:::
//    			ret = "";
//    			break;
    	}
    	return ret;
    }
protected:
	NetscapeSPKIException::ErrorCode errorCode;
};

#endif /*NETSCAPESPKIEXCEPTION_H_*/
