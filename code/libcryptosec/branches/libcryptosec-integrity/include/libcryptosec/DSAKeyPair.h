#ifndef DSAKEYPAIR_H_
#define DSAKEYPAIR_H_

#include <openssl/evp.h>
#include "ByteArray.h"
#include "SymmetricKey.h"
#include "KeyPair.h"
#include "DSAPublicKey.h"
#include "DSAPrivateKey.h"

#include <libcryptosec/exception/EngineException.h>
#include <libcryptosec/exception/EncodeException.h>
#include <libcryptosec/exception/AsymmetricKeyException.h>

/**
* Representa um par de chaves assimétricas DSA.
 * Essa classe deve ser usada para a criação de chaves assimétricas DSA
 * É uma especialização da classe KeyPair
 * @ingroup AsymmetricKeys 
 */
 
class DSAKeyPair : public KeyPair
{
	public:
		/**
		 * create a DSAKeyPair object, creating a new key pair

		 * @param length key lenght
		 * @throws AsymmetricKeyException if the key cannot be created
		 */
		DSAKeyPair(int length)
				throw (AsymmetricKeyException);
		
		virtual ~DSAKeyPair();
		/**
		 * gets the public key from key pair
		 * @return a public key from key pair
		 */
		virtual PublicKey* getPublicKey()
				throw (AsymmetricKeyException, EncodeException);
		/**
		 * gets the private from key pair
		 * @return a private key from key pair
		 */
		virtual PrivateKey* getPrivateKey()
			throw (AsymmetricKeyException);
		/**
		 * encode the key pair in PEM format encrypted
		 * @param passphrase key for encrypt the key pair
		 * @param mode cipher operation mode
		 * @return key pair encrypted encoded in PEM format
		 */

		virtual AsymmetricKey::Algorithm getAlgorithm()
				throw (AsymmetricKeyException);
		/**
		 * gets the key size
		 * @return key size
		 */
};

#endif /*DSAKEYPAIR_H_*/
