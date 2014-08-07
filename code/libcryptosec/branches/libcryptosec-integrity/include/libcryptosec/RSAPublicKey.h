#ifndef RSAPUBLICKEY_H_
#define RSAPUBLICKEY_H_

#include "PublicKey.h"

/**
 * Representa uma chave pública RSA.
 * Para a criação de chaves assimetricas a classe KeyPair deve ser consultada.
 * @see KeyPair
 * @ingroup AsymmetricKeys
 **/

class RSAPublicKey : public PublicKey
{
	
public:

	/**
	 * Construtor para uso interno recebendo um ponteiro para a estrutura OpenSSL EVP_PKEY.
	 * @param key ponteiro para a estrutura OpenSSL EVP_PKEY. 
	 * @throw AsymmetricKeyException caso a estrutura EVP_PKEY não seja uma estrutura
	 * OpenSSL válida ou ocorra algum problema na sua carga.
	 **/
	RSAPublicKey(EVP_PKEY *key) throw (AsymmetricKeyException);
	
	/**
	 * Construtor recebendo a representação da chave pública no formato DER.
	 * @param derEncoded chave pública codificada no formato DER.
	 * @throw EncodeException caso tenha ocorrido um erro com a decodificação do DER.
	 * @throw AsymmetricKeyException caso ocorra um erro na criação da chave.
	 **/
	RSAPublicKey(ByteArray &derEncoded)
			throw (EncodeException, AsymmetricKeyException);
	
	/**
	 * Construtor recebendo a representação da chave pública no formato PEM.
	 * @param pemEncoded chave pública codificada no formato PEM.
	 * @throw EncodeException caso tenha ocorrido um erro com a decodificação do PEM.
	 * @throw AsymmetricKeyException caso ocorra um erro na criação da chave.
	 **/			
	RSAPublicKey(std::string &pemEncoded)
			throw (EncodeException, AsymmetricKeyException);
	
	/**
	 * Destrutor padrão, limpa a estrutura interna EVP_PKEY
	 **/		
	virtual ~RSAPublicKey();
	
};

#endif /*RSAPUBLICKEY_H_*/
