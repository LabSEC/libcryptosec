#ifndef PUBLICKEY_H_
#define PUBLICKEY_H_

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <string>
#include "AsymmetricKey.h"
#include "ByteArray.h"
#include <libcryptosec/exception/EncodeException.h>
#include "MessageDigest.h"

/**
 * Representa uma chave pública.
 * Para a criação de chaves assimetricas a classe KeyPair deve ser consultada.
 * @see KeyPair
 * @ingroup AsymmetricKeys
 **/

class PublicKey : public AsymmetricKey
{
	
public:

	/**
	 * Construtor para uso interno recebendo um ponteiro para a estrutura OpenSSL EVP_PKEY.
	 * @param key ponteiro para a estrutura OpenSSL EVP_PKEY. 
	 * @throw AsymmetricKeyException caso a estrutura EVP_PKEY não seja uma estrutura
	 * OpenSSL válida ou ocorra algum problema na sua carga.
	 **/
	PublicKey(EVP_PKEY *key) throw (AsymmetricKeyException);

	/**
	 * Construtor recebendo a representação da chave pública no formato DER.
	 * @param derEncoded chave pública codificada no formato DER.
	 * @throw EncodeException caso tenha ocorrido um erro com a decodificação do DER.
	 **/
	PublicKey(ByteArray &derEncoded)
			throw (EncodeException);

	/**
	 * Construtor recebendo a representação da chave pública no formato PEM.
	 * @param pemEncoded chave pública codificada no formato PEM.
	 * @throw EncodeException caso tenha ocorrido um erro com a decodificação do PEM.
	 **/	
	PublicKey(std::string &pemEncoded)
			throw (EncodeException);

	/**
	 * Destrutor padrão, limpa a estrutura interna EVP_PKEY
	 **/
	virtual ~PublicKey();

	/**
	 * Retorna a representação da chave no formato PEM.
	 * @return a chave pública codificada em PEM.
	 * @throw EncodeException caso ocorra um erro na codificação da chave.
	 **/
	std::string getPemEncoded()
			throw (EncodeException);

	/**
	 * Retorna a representação da chave no formato DER.
	 * @return a chave pública codificada em DER.
	 * @throw EncodeException caso ocorra um erro na codificação da chave.
	 **/
	ByteArray getDerEncoded()
			throw (EncodeException);

	/**
	 * @return hash sha1 da chave. 
	 */	
	ByteArray getKeyIdentifier() throw (EncodeException);
};

#endif /*PUBLICKEY_H_*/
