#ifndef KEYPAIR_H_
#define KEYPAIR_H_

#include <openssl/evp.h>
#include "ByteArray.h"
#include "Engine.h"
#include "AsymmetricKey.h"
#include "RSAPublicKey.h"
#include "DSAPublicKey.h"
#include "ECDSAPublicKey.h"
#include "EdDSAPublicKey.h"
#include "RSAPrivateKey.h"
#include "DSAPrivateKey.h"
#include "ECDSAPrivateKey.h"
#include "EdDSAPrivateKey.h"

#include <libcryptosec/exception/EngineException.h>
#include <libcryptosec/exception/EncodeException.h>
#include <libcryptosec/exception/AsymmetricKeyException.h>

/**
 * Representa um par de chaves assimétricas. 
 * Essa classe deve ser usada para a criação de chaves assimétricas
 * bem como a condificação e decodificação do par para os formatos PEM e DER.
 * @ingroup AsymmetricKeys 
 */
 
class KeyPair
{
	public:
		/**
		 * create a KeyPair object, creating a new key pair
		 * @param algorithm key pair algorithm
		 * @param length key lenght
		 * @throws AsymmetricKeyException if the key cannot be created
		 */
		//TODO Este construtor deve é obsoleto. Devem ser usados os construtores das classes especializadas RSAKeyPair, DSAKeyPair e ECDSAKeyPair
		KeyPair(AsymmetricKey::Algorithm algorithm, int length)
				throw (AsymmetricKeyException);
		
		KeyPair(Engine *engine, std::string keyId)
				throw (EngineException);
		/**
		 * create a KeyPair object, loading the key pair from encoded (PEM format), decrypting with key
		 * @param pemEncoded key pair encoded em PEM format
		 * @param passphrase passphrase to decrypt the key pair
		 */
		KeyPair(std::string pemEncoded, ByteArray passphrase)
				throw (EncodeException);
		/**
		 * create a KeyPair object, loading the key pair from encoded (PEM format)
		 * @param pemEncoded key pair encoded em PEM format
		 */
		KeyPair(std::string pemEncoded)
				throw (EncodeException);
		/**
		 * create a KeyPair object, loading the key pair from encoded (DER format)
		 * @param derEncoded key pair encoded em DER format
		 */
		KeyPair(ByteArray derEncoded)
				throw (EncodeException);
		
		KeyPair(const KeyPair &keyPair);
		
		virtual ~KeyPair();
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
		std::string getPemEncoded(SymmetricKey &passphrase, SymmetricCipher::OperationMode mode)
			throw (SymmetricCipherException, EncodeException);
		/**
		 * encode the key pair in PEM format
		 * @return key pair encoded in PEM format
		 */
		std::string getPemEncoded() throw (EncodeException);
		/**
		 * encode the key pair in DER format
		 * @return key pair encoded in DER format
		 */
		ByteArray getDerEncoded() throw (EncodeException);

		/**
		 * gets algorithm id from the key
		 * @return algorithm id
		 */
		virtual AsymmetricKey::Algorithm getAlgorithm() throw (AsymmetricKeyException);;

		/**
		 * gets the key size
		 * @return key size
		 */
		int getSize() throw (AsymmetricKeyException);
		/**
		 * gets the key size in bits
		 * @return key size in bits
		 */
		int getSizeBits() throw (AsymmetricKeyException);
		
		EVP_PKEY* getEvpPkey() const;
		
		ENGINE* getEngine() const;
		
		std::string getKeyId() const;
	protected:
		KeyPair();
		static int passphraseCallBack(char *buf, int size, int rwflag, void *u);
		std::string getPublicKeyPemEncoded() throw (EncodeException);
		/**
		 * struct from OpenSSL that represents the key pair
		 */
		EVP_PKEY *key;
		std::string keyId;
		ENGINE *engine;
};

#endif /*KEYPAIR_H_*/
