#ifndef SIGNER_H_
#define SIGNER_H_

/* OpenSSL includes */
#include <openssl/dsa.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

/* local includes */
#include "ByteArray.h"
#include "MessageDigest.h"
#include "PrivateKey.h"
#include "PublicKey.h"

/* exception includes */
#include <libcryptosec/exception/SignerException.h>

/**
 * @brief Implementa funcionalidades de assinatura assimétrica, bem como a verificação dessa.
 * @ingroup Util
 */

class Signer
{
public:

	/**
	 * Realiza assinatura assimétrica.
	 * @param key chave privada.
	 * @param hash bytes que representam o hash.
	 * @param algorithm algoritmo de criptografia assimétrica.
	 * @return bytes que representam a assinatura digital.
	 * @throw SignerException caso o algoritmo solicitado não seja suportado ou caso ocorra algum erro interno durante a cifragem.
	 * @see PrivateKey
	 * @see ByteArray
	 * @see MessageDigest::Algorithm
	 */
	static ByteArray sign(PrivateKey &key, ByteArray &hash, MessageDigest::Algorithm algorithm)
			throw (SignerException);
	
	/**
	 * Verifica assinatura assimétrica.
	 * @param key chave pública.
	 * @param signature bytes que representam a assinatura assimétrica.
	 * @param hash bytes que representam o hash.
	 * @param algorithm algoritmo de criptografia assimétrica.
	 * @return true caso a assinatura seja verificada, false caso contrário.
	 * @throw SignerException caso o algoritmo solicitado não seja suportado ou caso ocorra algum erro interno durante a verificação.
	 * @see PublicKey
	 * @see ByteArray
	 * @see MessageDigest::Algorithm
	 */
	static bool verify(PublicKey &key, ByteArray &signature, ByteArray &hash, MessageDigest::Algorithm algorithm)
			throw (SignerException);
};

#endif /*SIGNER_H_*/
