#ifndef RSAPRIVATEKEY_H_
#define RSAPRIVATEKEY_H_

#include "PrivateKey.h"

/**
 * Representa uma chave privada RSA.
 * Para a criação de chaves assimetricas a classe KeyPair deve ser consultada.
 * @see KeyPair
 * @ingroup AsymmetricKeys
 **/

class RSAPrivateKey : public PrivateKey
{
	
public:
	
	/**
	 * Construtor para uso interno recebendo um ponteiro para a estrutura OpenSSL EVP_PKEY.
	 * @param key ponteiro para a estrutura OpenSSL EVP_PKEY. 
	 * @throw AsymmetricKeyException caso a estrutura EVP_PKEY não seja uma estrutura
	 * OpenSSL válida ou ocorra algum problema na sua carga.
	 **/
	RSAPrivateKey(EVP_PKEY *key) throw (AsymmetricKeyException);
	
	/**
	 * Construtor recebendo a representação da chave privada no formato DER.
	 * @param derEncoded chave privada codificada no formato DER.
	 * @throw EncodeException caso tenha ocorrido um erro com a decodificação do DER.
	 * @throw AsymmetricKeyException caso ocorra um erro na criação da chave.
	 **/
	RSAPrivateKey(ByteArray &derEncoded)
			throw (EncodeException, AsymmetricKeyException);
	
	/**
	 * Construtor recebendo a representação da chave privada no formato PEM.
	 * @param pemEncoded chave privada codificada no formato PEM.
	 * @throw EncodeException caso tenha ocorrido um erro com a decodificação do PEM.
	 * @throw AsymmetricKeyException caso ocorra um erro na criação da chave.
	 **/
	RSAPrivateKey(std::string &pemEncoded)
			throw (EncodeException, AsymmetricKeyException);
	
	/**
	 * Construtor recebendo a representação da chave privada no formato PEM protegida 
	 * por uma senha.
	 * @param pemEncoded chave privada codificada no formato PEM protegida por uma senha.
	 * @param passphrase senha que permitirá a decodificação e abertura da chave.
	 * @throw EncodeException caso tenha ocorrido um erro com a decodificação do PEM.
	 * @throw AsymmetricKeyException caso ocorra um erro na criação da chave.
	 */		
	RSAPrivateKey(std::string &pemEncoded, ByteArray &passphrase)
			throw (EncodeException, AsymmetricKeyException);
	
	/**
	 * Destrutor padrão, limpa a estrutura interna EVP_PKEY
	 **/		
	virtual ~RSAPrivateKey();

};

#endif /*RSAPRIVATEKEY_H_*/
