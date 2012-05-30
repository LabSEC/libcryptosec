#ifndef ASYMMETRICCIPHER_H_
#define ASYMMETRICCIPHER_H_

/* OpenSSL includes */

#include <openssl/evp.h>

/* local includes */
#include "ByteArray.h"
#include "RSAPublicKey.h"
#include "RSAPrivateKey.h"

/* exceptions includes */
#include <libcryptosec/exception/AsymmetricCipherException.h>

/**
 * @ingroup Util 
 */

/**
 * @brief static class to perform asymmetric ciphers, using asymmetric keys (eg. RSA keys)
 */
class AsymmetricCipher
{
public:
	/**
	 * supported padding values to perform asymmetric ciphers. Default: PKCS1.
	 */
	enum Padding
	{
		NO_PADDING,
		PKCS1,
		SSLV23,
		PKCS1_OAEP,
	/*	X931  only openssl 0.9.8 support */
	};
	/**
	 * encrypt unreadable data using a asymmetric public key
	 * @param key public key to encrypt data
	 * @param data data to be encrypted
	 * @padding type of padding to use in process
	 * @return encrypted data
	 * @throws AsymmetricCipherException if any problem happen, throw this exception with a ENCRYPTING_DATA code.
	 */
	static ByteArray encrypt(RSAPublicKey &key, ByteArray &data, AsymmetricCipher::Padding padding)
			throw (AsymmetricCipherException);
	/**
	 * encrypt readable data using a asymmetric public key
	 * @param key public key to encrypt data
	 * @param data data to be encrypted
	 * @padding type of padding to use in process
	 * @return encrypted data
	 * @throws AsymmetricCipherException if any problem happen, throw this exception with a ENCRYPTING_DATA code.
	 */
	static ByteArray encrypt(RSAPublicKey &key, std::string &data, AsymmetricCipher::Padding padding)
		throw (AsymmetricCipherException);
	/**
	 * decrypt encrypted data using a asymmetric private key
	 * @param key private key to decrypt encrypted data
	 * @param data data to be decrypted
	 * @padding type of padding to use in process (must be the same used to perform the encrypting operation
	 * @return encrypted data
	 * @throws AsymmetricCipherException if any problem happen, throw this exception with a ENCRYPTING_DATA code.
	 */
	static ByteArray decrypt(RSAPrivateKey &key, ByteArray &data, AsymmetricCipher::Padding padding)
			throw (AsymmetricCipherException);
private:
	/**
	 * Internal use. Used to convert the libcryptosec padding value to openssl padding value.
	 * @param libcryptosec padding value
	 * @return openssl padding value
	 */
	static int getPadding(AsymmetricCipher::Padding padding);
};

#endif /*ASYMMETRICCIPHER_H_*/
