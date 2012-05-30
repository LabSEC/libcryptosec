#ifndef OPENSSLERRORHANDLER_H_
#define OPENSSLERRORHANDLER_H_

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/dh.h>
#include <openssl/engine.h>
#include <openssl/pkcs7.h>
#include <libp11.h>

#include <string>

#include "ByteArray.h"

/**
 * Utilities to turn it easier to use some OpenSSL procedures.
 **/
class OpenSSLErrorHandler
{
public:
	enum ErrorsString
	{
		ENCODE,
		ENGINE,
		MESSAGE_DIGEST,
		SYMMETRIC_CIPHER,
		PKCS11_MODULE,
		PKCS7,
		RANDOM,
		ASYMMETRIC_KEY,
		CERTIFICATION,
	};
//	/**
//	 * Default constructor.
//	 */
//	OpenSSLErrorHandler();
//	/**
//	 * Default destructor.
//	 */
//	virtual ~OpenSSLErrorHandler();
	static void loadErrorsString(OpenSSLErrorHandler::ErrorsString errorsString);
	/**
	 * Gets OpenSSL error list as returned by ERR_print_errors.
	 */
	static std::string getErrors();
	/**
	 * Clears OpenSSL error queue by calling ERR_clear_errors and clearing internal BIO (errorBio).
	 */
	static void clearErrors();
private:
	/**
	 * Used to get OpenSSL error list.
	 */
	static BIO* errorBio;
};

#endif /*OPENSSLERRORHANDLER_H_*/
