#ifndef EdDSAKEYPAIR_H_
#define EdDSAKEYPAIR_H_
#include <openssl/evp.h>
#include <openssl/bio.h>

#include "ByteArray.h"
#include "KeyPair.h"
#include "ec/EllipticCurve.h"
#include "Base64.h"

#include <libcryptosec/exception/EngineException.h>
#include <libcryptosec/exception/EncodeException.h>
#include <libcryptosec/exception/AsymmetricKeyException.h>


/**
 * Representa um par de chaves assimétricas EdDSA.
 * Essa classe deve ser usada para a criação de chaves assimétricas EdDSA
 * que não possui nome ou NID definido no OpenSSL. Par de chaves é gerada através
 * dos parâmetros da curva, enviados em ASN1 (PEM ou DER) ou pela classe EllipticCurve.
 * É uma especialização da classe KeyPair
 * @ingroup AsymmetricKeys
 *
 * @see EllipticCurve
 * @see BrainpoolCurveFactory
 */
class EdDSAKeyPair : public KeyPair {

public:

	/**
	 * Cria par por parâmetros informados em DER
	 * TODO
	 */
	EdDSAKeyPair(ByteArray &derEncoded)
			throw (AsymmetricKeyException);

	/**
	 * Cria par por parâmetros informados em PEM
	 * TODO
	 */
	EdDSAKeyPair(std::string &encoded)
			throw (AsymmetricKeyException);

	EdDSAKeyPair(AsymmetricKey::Curve curve)
			throw (AsymmetricKeyException);

	virtual ~EdDSAKeyPair();

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

#endif /* EdDSAKEYPAIR_H_ */
