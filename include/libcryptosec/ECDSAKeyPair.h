#ifndef ECDSAKEYPAIR_H_
#define ECDSAKEYPAIR_H_

#include <openssl/evp.h>
#include <openssl/bio.h>

#include "ByteArray.h"
#include "SymmetricKey.h"
#include "KeyPair.h"
#include "ECDSAPublicKey.h"
#include "ECDSAPrivateKey.h"
#include "ec/Curve.h"
#include "Base64.h"

#include <libcryptosec/exception/EngineException.h>
#include <libcryptosec/exception/EncodeException.h>
#include <libcryptosec/exception/AsymmetricKeyException.h>

/**
* Representa um par de chaves assimétricas DSA.
 * Essa classe deve ser usada para a criação de chaves assimétricas DSA
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
		
		/**
		 * Cria par por parâmetros informados em DER
		 * TODO
		 */
		ECDSAKeyPair(ByteArray &derEncoded)
				throw (AsymmetricKeyException);

		/**
		 * Cria par por parâmetros informados em PEM
		 * TODO
		 */
		ECDSAKeyPair(std::string &encoded)
				throw (AsymmetricKeyException);

		/**
		 * Cria par por parãmetros informados por um objeto Curve
		 * TODO
		 */
		ECDSAKeyPair(const Curve & curve)
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

	protected:
		void generateKey(EC_GROUP * group) throw (AsymmetricKeyException);
		EC_GROUP *createGroup(const Curve& curve);
		EC_GROUP *createGroup(ByteArray &derEncoded);
};

#endif /*ECDSAKEYPAIR_H_*/
