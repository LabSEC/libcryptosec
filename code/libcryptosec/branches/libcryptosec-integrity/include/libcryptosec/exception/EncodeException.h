#ifndef ENCODEEXCEPTION_H_
#define ENCODEEXCEPTION_H_

#include <openssl/err.h>

#include "LibCryptoSecException.h"

class EncodeException : public LibCryptoSecException
{
public:
	enum ErrorCode
	{
		UNKNOWN = 0,
		BUFFER_CREATING = 1,
		BUFFER_READING = 2,
		BUFFER_WRITING = 3,
		DER_ENCODE = 4,
		DER_DECODE = 5,
		PEM_ENCODE = 6,
		PEM_DECODE = 7,
		BASE64_ENCODE = 8,
		BASE64_DECODE = 9,
	};
	EncodeException(std::string where)
    {
    	this->where = where;
    	this->errorCode = EncodeException::UNKNOWN;
    }
    EncodeException(EncodeException::ErrorCode errorCode, std::string where)
    {
    	this->where = where;
    	this->errorCode = errorCode;
    }
	virtual ~EncodeException() throw () {}
	virtual std::string getMessage() const
	{
		return (EncodeException::errorCode2Message(this->errorCode));
	}
    virtual std::string toString() const
    {
    	std::string ret;
    	if (this->errorCode == EncodeException::UNKNOWN)
    	{
    		ret = "EncodeException. Called by: " + this->where + ".";
    	}
    	else
    	{
    		ret = "EncodeException: " + EncodeException::errorCode2Message(this->errorCode) + ". Called by: " + this->where + ".";
    	}
    	return ret;
    }
    virtual EncodeException::ErrorCode getErrorCode()
    {
    	return this->errorCode;
    }
    static std::string errorCode2Message(EncodeException::ErrorCode errorCode)
    {
    	std::string ret;
    	switch (errorCode)
    	{
    		case EncodeException::UNKNOWN:
    			ret = "Unknown error";
    			break;
    		case EncodeException::BUFFER_CREATING:
    			ret = "Creating a buffer";
    			break;
    		case EncodeException::BUFFER_READING:
    			ret = "Reading data from a buffer";
    			break;
    		case EncodeException::BUFFER_WRITING:
    			ret = "Writing data to a buffer";
    			break;
    		case EncodeException::DER_ENCODE:
    			ret = "Encoding DER format";
    			break;
    		case EncodeException::DER_DECODE:
    			ret = "Decoding DER format";
    			break;
    		case EncodeException::PEM_ENCODE:
    			ret = "Encoding PEM format";
    			break;
    		case EncodeException::PEM_DECODE:
    			ret = "Decoding PEM format";
    			break;
    		case EncodeException::BASE64_ENCODE:
    			ret = "Base64 encode";
    			break;
    		case EncodeException::BASE64_DECODE:
    			ret = "Base64 decode";
    			break;
//    		case EncodeException:::
//    			ret = "";
//    			break;
    	}
    	return ret;
    }

protected:
	EncodeException::ErrorCode errorCode;
};

#endif /*ENCODEEXCEPTION_H_*/
