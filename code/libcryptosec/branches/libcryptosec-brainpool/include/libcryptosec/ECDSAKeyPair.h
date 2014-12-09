#ifndef ECDSAKEYPAIR_H_
#define ECDSAKEYPAIR_H_

#include <openssl/evp.h>

#include "ByteArray.h"
#include "SymmetricKey.h"
#include "KeyPair.h"
#include "ECDSAPublicKey.h"
#include "ECDSAPrivateKey.h"

#include <libcryptosec/exception/EngineException.h>
#include <libcryptosec/exception/EncodeException.h>
#include <libcryptosec/exception/AsymmetricKeyException.h>

/**
* Representa um par de chaves assimétricas ECDSA.
 * Essa classe deve ser usada para a criação de chaves assimétricas ECDSA
 * É uma especialização da classe KeyPair
 * @ingroup AsymmetricKeys 
 */
 
class ECDSAKeyPair : public KeyPair
{
	public:

		/**
		 * create a ECDSAKeyPair object, creating a new key pair
		 * @param length key lenght
		 * @throws AsymmetricKeyException if the key cannot be created
		 */
		ECDSAKeyPair(AsymmetricKey::Curve curve, bool named=true)
				throw (AsymmetricKeyException);
		

		virtual ~ECDSAKeyPair();

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

		virtual AsymmetricKey::Algorithm getAlgorithm()
				throw (AsymmetricKeyException);

};

#endif /*ECDSAKEYPAIR_H_*/
