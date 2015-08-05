#ifndef RSAKEYPAIR_H_
#define RSAKEYPAIR_H_

#include <openssl/evp.h>
#include "ByteArray.h"
#include "SymmetricKey.h"
#include "KeyPair.h"
#include "RSAPublicKey.h"
#include "RSAPrivateKey.h"

#include <libcryptosec/exception/EngineException.h>
#include <libcryptosec/exception/EncodeException.h>
#include <libcryptosec/exception/AsymmetricKeyException.h>

/**
 * Representa um par de chaves assimétricas RSA.
 * Essa classe deve ser usada para a criação de chaves assimétricas RSA
 * É uma especialização da classe KeyPair
 * @ingroup AsymmetricKeys 
 */
 
class RSAKeyPair : public KeyPair
{
	public:
		/**
		 * create a RSAKeyPair object, creating a new key pair

		 * @param length key lenght
		 * @throws AsymmetricKeyException if the key cannot be created
		 */
		RSAKeyPair(int length)
				throw (AsymmetricKeyException);
		
		virtual ~RSAKeyPair();
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

#endif /*RSAKEYPAIR_H_*/
