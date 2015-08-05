#ifndef NETSCAPESPKIBUILDER_H_
#define NETSCAPESPKIBUILDER_H_

#include <openssl/evp.h>

#include "NetscapeSPKI.h"
#include <libcryptosec/exception/EncodeException.h>
#include <libcryptosec/exception/NetscapeSPKIException.h>

/**
 * @defgroup SPKI Classes Relacionadas ao Padrão Netscape SPKI
 */
 
 /**
  * @brief Implementa o padrão builder para a criação de objetos NetscapeSPKI.
  * Estes implementam o padrão de chave pública SPKI da Netscape. 
  * @see NetscapeSPKI.
  *  
  * @ingroup SPKI
  */
 
class NetscapeSPKIBuilder
{
public:

	/**
	 * Construtor padrão.
	 * Constroi um objeto NetscapeSPKIBuilder.
	 */
	NetscapeSPKIBuilder();
	
	/**
	 * Construtor.
	 * Constroi um objeto NetscapeSPKIBuilder a partir de um objeto NetscapeSPKI.
	 * @param NetscapeSPKIBuilder objeto NetscapeSPKI em formato base64.
	 */
	NetscapeSPKIBuilder(std::string netscapeSPKIBase64)
			throw (EncodeException);
			
	/**
	 * Destrutor.
	 */		
	virtual ~NetscapeSPKIBuilder();
	
	/**
	 * Obtem objeto NetscapeSPKI em formato base64.
	 * @return objeto NetscapeSPKI em formato base64.
	 * @throw EncodeException caso ocorra algum erro interno durante a codificação do objeto em base64.
	 */
	std::string getBase64Encoded() throw (EncodeException);
	
	/**
	 * Define chave pública para o objeto NetscapeSPKI.
	 * @param publicKey objeto que representa uma chave pública.
	 */
	void setPublicKey(PublicKey &publicKey);
	
	
	/**
	 * Retorna a chave pública do objeto NetscapeSPKI.
	 * @return Retorna a chave pública do objeto NetscapeSPKI.
     * @throw NetscapeSPKIException caso a chave pública não esteja disponível no objeto NetscapeSPKI.
	 * @throw AsymmetricKeyException caso não seja possível instanciar um objeto PublicKey a partir da chave pública obtida de NetscapeSPKI. 
	 */
	PublicKey* getPublicKey()
			throw (AsymmetricKeyException, NetscapeSPKIException);
	
	/**
	 * Define o desafio do objeto NetscapeSPKI
	 * @param challenge desafio.
	 */
	void setChallenge(std::string challenge);
	
	/**
	 * Retorna desafio do objeto NetscapeSPKI.
	 * @return desafio do objeto NetscapeSPKI.
	 */
	std::string getChallenge();
	
	/**
	 * Cria um objeto NetscapeSPKI
	 * @param privateKey chave privada.
	 * @param messageDigest algoritmo de resumo.
	 * @throw NetscapeSPKIException caso ocorra erro interno do OpenSSL ao assinar o objeto NetscapePKI
	 */
	NetscapeSPKI* sign(PrivateKey &privateKey, MessageDigest::Algorithm messageDigest)
			throw (NetscapeSPKIException);
protected:
	/**
	 * Estrutura do OpenSSL para representar um objeto NetscapeSPKI.
	 */
	NETSCAPE_SPKI *netscapeSPKI;
};

#endif /*NETSCAPESPKIBUILDER_H_*/
