#ifndef INVALIDSTATEEXCEPTION_H_
#define INVALIDSTATEEXCEPTION_H_

#include "LibCryptoSecException.h"

class InvalidStateException : public LibCryptoSecException
{
public:
    InvalidStateException(std::string where)
    {
    	this->where = where;
    }
	virtual ~InvalidStateException() throw () {}
	virtual std::string getMessage() const
	{
		return "Invalid state exception.";
	}
    virtual std::string toString() const
    {
    	return "Invalid state exception. Called by: " + this->where + ".";
    }
};

#endif /*INVALIDSTATEEXCEPTION_H_*/
