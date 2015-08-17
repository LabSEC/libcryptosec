#ifndef NETSCAPESPKI_H_
#define NETSCAPESPKI_H_

#include <openssl/x509.h>

#include <string>

#include "RSAPublicKey.h"
#include "DSAPublicKey.h"
#include "PrivateKey.h"
#include "MessageDigest.h"

#include <libcryptosec/exception/NetscapeSPKIException.h>

/*
 * @ingroup SPKI
 */

/**
 * @brief Implementa o padrão NetscapeSPKI.
 * Este é uma estrutura que contém: estrutura SPKAC (chave pública e desafio), o algoritmo de assinatura e a assinatura em formato ASN1 String do SPKAC.
 * @ingroup SPKI
 */

class NetscapeSPKI
{
public:

	/**
	 * Construtor.
	 * Cria um objeto NetscapeSPKI a partir de uma estrutura NETSCAPE_SPKI do OpenSSL.
	 * @param netscapeSPKI estrutura NETSCAPE_SPKI.
	 */
	NetscapeSPKI(NETSCAPE_SPKI *netscapeSPKI) throw (NetscapeSPKIException);
	
	/**
	 * Construtor.
	 * Cria um objeto NetscapeSPKI a partir outro do mesmo tipo mas codificado em base64.
	 * @param netscapeSPKI estrutura NETSCAPE_SPKI.
	 */	
	NetscapeSPKI(std::string netscapeSPKIBase64) throw (EncodeException);
	
	/**
	 * Destrutor.
	 */
	virtual ~NetscapeSPKI();
	
	/**
	 * Obtem objeto NetscapeSPKI em formato base64.
	 * @return objeto NetscapeSPKI em formato base64.
	 * @throw EncodeException caso ocorra algum erro interno durante a codificação do objeto em base64.
	 */
	std::string getBase64Encoded() throw (EncodeException);
	
	/**
	 * Retorna a chave pública do objeto NetscapeSPKI.
	 * @return Retorna a chave pública do objeto NetscapeSPKI.
     * @throw NetscapeSPKIException caso a chave pública não esteja disponível no objeto NetscapeSPKI.
	 * @throw AsymmetricKeyException caso não seja possível instanciar um objeto PublicKey a partir da chave pública obtida de NetscapeSPKI. 
	 */
	PublicKey* getPublicKey()
			throw (AsymmetricKeyException, NetscapeSPKIException);
	
	/**
	 * Retorna desafio do objeto NetscapeSPKI.
	 * @return desafio do objeto NetscapeSPKI.
	 */
	std::string getChallenge();

	/**
	 * Verifica a assinatura do NetscapeSPKI.
	 * @return true caso a assinatura seja verificada com sucesso, false caso contrário.
	 * @throw NetscapeSPKIException caso a chave pública não esteja disponível no objeto NetscapeSPKI.
	 * @throw AsymmetricKeyException caso não seja possível instanciar um objeto PublicKey a partir da chave pública obtida de NetscapeSPKI.
	 */
	bool verify() throw (AsymmetricKeyException, NetscapeSPKIException);
	
	/**
	 * Verifica a assinatura do NetscapeSPKI.
	 * @param publicKey chave pública.
	 * @return true caso a assinatura seja verificada com sucesso, false caso contrário.
	 * @throw NetscapeSPKIException caso a chave pública não esteja disponível no objeto NetscapeSPKI.
	 * @throw AsymmetricKeyException caso não seja possível instanciar um objeto PublicKey a partir da chave pública obtida de NetscapeSPKI.
	 */
	bool verify(PublicKey &publicKey);

	bool isSigned();

protected:
	
	/**
	 * Estrutura do OpenSSL para representar um objeto NetscapeSPKI.
	 */
	NETSCAPE_SPKI *netscapeSPKI;
};

#endif /*NETSCAPESPKI_H_*/
