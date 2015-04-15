#ifndef ENGINEEXCEPTION_H_
#define ENGINEEXCEPTION_H_

#include "LibCryptoSecException.h"

class EngineException : public LibCryptoSecException
{
public:
	enum ErrorCode
	{
		UNKNOWN,
		INVALID_ENGINE,
		INIT_FAILED,
		KEY_NOT_FOUND,
		ADD_ENGINE_TO_LIST,
		REMOVE_ENGINE_FROM_LIST,
		DYNAMIC_ENGINE_UNAVAILABLE,
		INTERNAL_ERROR,
		ENGINE_NOT_FOUND,
		SET_COMMAND,
		LOAD_ENGINE_FAILED,
	};
    EngineException(std::string where)
    {
    	this->where = where;
    	this->errorCode = EngineException::UNKNOWN;
    	this->details = "";
    }
    EngineException(EngineException::ErrorCode errorCode, std::string where)
    {
    	this->where = where;
    	this->errorCode = errorCode;
    	this->details = "";
    }
	EngineException(EngineException::ErrorCode errorCode, std::string where, std::string details)
	{
		this->where = where;
		this->errorCode = errorCode;
		this->details = details;
	}
	EngineException(EngineException::ErrorCode errorCode, std::string where, bool opensslDetails)
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
	virtual ~EngineException() throw () {}
	virtual std::string getMessage() const
	{
//		return (EngineException::errorCode2Message(this->errorCode) + ". Details: " +details);
		return EngineException::errorCode2Message(this->errorCode);
	}
	virtual std::string toString() const
	{
		std::string ret;
		if (this->errorCode == EngineException::UNKNOWN)
		{
    		ret = "EngineException. Called by: " + this->where + ".";
    	}
    	else
    	{
    		ret = "EngineException: " + EngineException::errorCode2Message(this->errorCode) + ". Called by: " + this->where + ".";
    	}
    	if (this->details != "")
    	{
    		ret += " More details:\n" + this->details + ".";
    	}
    	return ret;
    }
    virtual EngineException::ErrorCode getErrorCode()
    {
    	return this->errorCode;
    }
    static std::string errorCode2Message(EngineException::ErrorCode errorCode)
    {
    	std::string ret;
    	switch (errorCode)
    	{
    		case EngineException::UNKNOWN:
    			ret = "Unknown error";
    			break;
    		case EngineException::INIT_FAILED:
    			ret = "Engine initialization failed";
    			break;
    		case EngineException::KEY_NOT_FOUND:
    			ret = "Key id not found";
    			break;
    		case EngineException::ADD_ENGINE_TO_LIST:
    			ret = "Adding engine to engines list";
    			break;
    		case EngineException::REMOVE_ENGINE_FROM_LIST:
    			ret = "Removing engine from engines list";
    			break;
    		case EngineException::DYNAMIC_ENGINE_UNAVAILABLE:
    			ret = "Dynamic engine is not available";
    			break;
    		case EngineException::INTERNAL_ERROR:
    			ret = "Internal error";
    			break;
    		case EngineException::ENGINE_NOT_FOUND:
    			ret = "Engine not found";
    			break;
    		case EngineException::SET_COMMAND:
    			ret = "Setting command";
    			break;
    		case EngineException::INVALID_ENGINE:
    			ret = "Invalid engine";
    			break;
    		case EngineException::LOAD_ENGINE_FAILED:
    			ret = "Load engine failed";
    			break;
//    		case EngineException:::
//    			ret = "";
//    			break;
//    		case EngineException:::
//    			ret = "";
//    			break;
    	}
    	return ret;
    }
protected:
	EngineException::ErrorCode errorCode;
};

#endif /*ENGINEEXCEPTION_H_*/
