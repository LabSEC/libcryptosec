#ifndef PRIVATEKEY_H_
#define PRIVATEKEY_H_

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <string>
#include "AsymmetricKey.h"
#include "ByteArray.h"
#include "SymmetricCipher.h"
#include "SymmetricKey.h"

#include <libcryptosec/exception/EncodeException.h>

/**
 * Representa uma chave privada.
 * Para a criação de chaves assimetricas a classe KeyPair deve ser consultada.
 * @see KeyPair 
 * @ingroup AsymmetricKeys
 **/

class PrivateKey : public AsymmetricKey
{
	
public:

	/**
	 * Construtor para uso interno recebendo um ponteiro para a estrutura OpenSSL EVP_PKEY.
	 * @param key ponteiro para a estrutura OpenSSL EVP_PKEY. 
	 * @throw AsymmetricKeyException caso a estrutura EVP_PKEY não seja uma estrutura
	 * OpenSSL válida ou ocorra algum problema na sua carga.
	 **/
	PrivateKey(EVP_PKEY *key) throw (AsymmetricKeyException);
	
	/**
	 * Construtor recebendo a representação da chave privada no formato DER.
	 * @param derEncoded chave privada codificada no formato DER.
	 * @throw EncodeException caso tenha ocorrido um erro com a decodificação do DER.
	 **/
	PrivateKey(ByteArray &derEncoded)
			throw (EncodeException);
		
	/**
	 * Construtor recebendo a representação da chave privada no formato PEM.
	 * @param pemEncoded chave privada codificada no formato PEM.
	 * @throw EncodeException caso tenha ocorrido um erro com a decodificação do PEM.
	 **/		
	PrivateKey(std::string &pemEncoded)
			throw (EncodeException);
			
	/**
	 * Construtor recebendo a representação da chave privada no formato PEM protegida 
	 * por uma senha.
	 * @param pemEncoded chave privada codificada no formato PEM protegida por uma senha.
	 * @param passphrase senha que permitirá a decodificação e abertura da chave.
	 * @throw EncodeException caso tenha ocorrido um erro com a decodificação do PEM.
	 */
	PrivateKey(std::string &pemEncoded, ByteArray &passphrase)
			throw (EncodeException);
			
	/**
	 * Destrutor padrão, limpa a estrutura interna EVP_PKEY
	 **/
	virtual ~PrivateKey();
	
	/**
	 * Retorna a representação da chave no formato PEM.
	 * @return a chave privada codificada em PEM.
	 * @throw EncodeException caso ocorra um erro na codificação da chave.
	 **/	
	std::string getPemEncoded()
			throw (EncodeException);
	
	/**
	 * Retorna a representação da chave no formato PEM cifrada com uma senha.
	 * @param passphrase a senha que cifrará a chave codificada em PEM.
	 * @param mode o algoritmo simétrico que será usado para proteger a chave privada. 
	 * @return a chave privada codificada em PEM.
	 * @throw EncodeException caso ocorra um erro na codificação da chave.
	 * @throw SymmetricCipherException caso o algoritmo escolhido não seja suportado ou seja
	 * inválido.
	 */
	std::string getPemEncoded(SymmetricKey &passphrase, SymmetricCipher::OperationMode mode)
			throw (SymmetricCipherException, EncodeException);
	
	/**
	 * Retorna a representação da chave no formato DER.
	 * @return a chave privada codificada em DER.
	 * @throw EncodeException caso ocorra um erro na codificação da chave.
	 **/
	ByteArray getDerEncoded()
			throw (EncodeException);

	bool operator==(PrivateKey& priv) throw();
		
protected:

	/**
	 * Método usado em formas alternativas de obter a senha para abrir a chave privada.
	 * @param buf
	 * @param size
	 * @param rwflag
	 * @param u
	 **/
	static int passphraseCallBack(char *buf, int size, int rwflag, void *u);

};

#endif /*PRIVATEKEY_H_*/
