#ifndef LIBCRYPTOSECEXCEPTION_H_
#define LIBCRYPTOSECEXCEPTION_H_

#include <exception>

#include <libcryptosec/OpenSSLErrorHandler.h>

class LibCryptoSecException : public std::exception
{
public:
	virtual ~LibCryptoSecException() throw () {}
	virtual std::string getMessage() const = 0;
    virtual std::string toString() const = 0;
    virtual const char *what() const throw ()
    {
    	return ((this->getMessage()).c_str());
    }
    virtual const std::string getDetails() const throw ()
    {
    	return this->details;
    }
protected:
    std::string where;
    std::string details;
};

#endif /*LIBCRYPTOSECEXCEPTION_H_*/
