#ifndef MESSAGEDIGESTEXCEPTION_H_
#define MESSAGEDIGESTEXCEPTION_H_

#include "LibCryptoSecException.h"

class MessageDigestException : public LibCryptoSecException
{
public:
	enum ErrorCode
	{
		UNKNOWN,
		CTX_INIT,
		CTX_UPDATE,
		CTX_FINISH,
		INVALID_ALGORITHM,
	};
    MessageDigestException(std::string where)
    {
    	this->where = where;
    	this->errorCode = MessageDigestException::UNKNOWN;
    }
    MessageDigestException(MessageDigestException::ErrorCode errorCode, std::string where)
    {
    	this->where = where;
    	this->errorCode = errorCode;
    }
	virtual ~MessageDigestException() throw () {}
	virtual std::string getMessage() const
	{
		return (MessageDigestException::errorCode2Message(this->errorCode));
	}
    virtual std::string toString() const
    {
    	std::string ret;
    	if (this->errorCode == MessageDigestException::UNKNOWN)
    	{
    		ret = "MessageDigestException. Called by: " + this->where + ".";
    	}
    	else
    	{
    		ret = "MessageDigestException: " + MessageDigestException::errorCode2Message(this->errorCode) + ". Called by: " + this->where + ".";
    	}
    	return ret;
    }
    virtual MessageDigestException::ErrorCode getErrorCode()
    {
    	return this->errorCode;
    }
    static std::string errorCode2Message(MessageDigestException::ErrorCode errorCode)
    {
    	std::string ret;
    	switch (errorCode)
    	{
    		case MessageDigestException::UNKNOWN:
    			ret = "Unknown error";
    			break;
    		case MessageDigestException::INVALID_ALGORITHM:
    			ret = "Invalid message digest algorithm";
    			break;
    		case MessageDigestException::CTX_INIT:
    			ret = "Creating message digest context";
    			break;
    		case MessageDigestException::CTX_UPDATE:
    			ret = "Updating message digest context";
    			break;
    		case MessageDigestException::CTX_FINISH:
    			ret = "Finishing message digest context";
    			break;
//    		case ErrorCode:::
//    			ret = "";
//    			break;
    	}
    	return ret;
    }
    
protected:
	MessageDigestException::ErrorCode errorCode;
};

#endif /*MESSAGEDIGESTEXCEPTION_H_*/
