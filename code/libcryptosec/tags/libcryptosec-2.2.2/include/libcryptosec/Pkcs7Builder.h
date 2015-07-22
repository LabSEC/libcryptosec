#ifndef PKCS7BUILDER_H_
#define PKCS7BUILDER_H_

#include <openssl/bio.h>
#include <openssl/pkcs7.h>
#include <openssl/pem.h>

#include <string>

#include "ByteArray.h"
#include <libcryptosec/exception/EncodeException.h>
#include <libcryptosec/exception/Pkcs7Exception.h>
#include <libcryptosec/exception/InvalidStateException.h>

/**
 * Implementa o padrão builder para a criação de um pacote PKCS7. Essa classe
 * deve ser usada como uma classe abstrata, pois não pussui um método init. 
 * 
 * @see Pkcs7EnvelopedDataBuilder
 * @see Pkcs7SignedDataBuilder
 * @ingroup PKCS7
 **/
class Pkcs7Builder
{
	
public:

	/**
	 * Construtor padrão.
	 * Cria uma nova estrutura PKCS7.
	 **/	
	Pkcs7Builder();
	
	/**
	 * Destrutor padrão. 
	 * Limpa a estrutura PKCS7.
	 **/
	~Pkcs7Builder();
	
	/**
	 * Concatena novos dados ao pacote PKCS7.
	 * @param data os dados a serem concatenados ao conteúdo prévio do pacote. 
	 * @throw InvalidStateException se o builder não estiver em um estado apropriado
	 * para receber dados, como no estado não inicializado.
	 * @throw Pkcs7Exception caso ocorra algum erro no procedimento de empacotamento.
	 * @see Pkcs7Builder::State
	 * @see Pkcs7EnvelopedDataBuilder::init()
	 * @see Pkcs7SignedDataBuilder::init()
	 **/
	void update(std::string &data) throw (InvalidStateException, Pkcs7Exception);
	
	/**
	 * Concatena novos dados ao pacote PKCS7.
	 * @param data os dados a serem concatenados ao conteúdo prévio do pacote. 
	 * @throw InvalidStateException se o builder não estiver em um estado apropriado
	 * para receber dados, como no estado não inicializado.
	 * @throw Pkcs7Exception caso ocorra algum erro no procedimento de empacotamento.
	 * @see State
	 * @see Pkcs7EnvelopedDataBuilder::init()
	 * @see Pkcs7SignedDataBuilder::init()
	 **/
	void update(ByteArray &data) throw (InvalidStateException, Pkcs7Exception);
	
	/**
	 * Gera um pacote PKCS7 a partir de de um stream de entrada e põe o resultado
	 * no formato PEM em um stream de saída.
	 * @param in stream de entrada cujo conteúdo será adicionado ao pacote PKCS7
	 * @param out stream que vai receber o pacote PKCS7 no formato PEM
	 * @throw InvalidStateException se o builder não estiver em um estado apropriado
	 * para receber dados, como no estado não inicializado.
	 * @throw Pkcs7Exception caso ocorra algum erro no procedimento de empacotamento.
	 * @throw EncodeException caso ocorra algum erro na conversão para o formato PEM.
	 * @see State
	 * @see Pkcs7EnvelopedDataBuilder::init()
	 * @see Pkcs7SignedDataBuilder::init()
	 **/
	void doFinal(std::istream *in, std::ostream *out)
			throw (InvalidStateException, Pkcs7Exception, EncodeException);

protected:

	/**
	 * @enum State
	 **/
	/**
	 *  Possíveis estados do builder. 
	 **/
	enum State
	{
		NO_INIT, /*!< estado inicial, quando o builder ainda não foi inicializado.*/
		INIT, /*!< estado em que o builder foi inicializado, mas ainda não recebeu dados para adicionar ao pacote PKCS7.*/
		UPDATE, /*!< estado em que o builder já possui condições para finalizar a criação do pacote através da chamada Pkcs7Builder::doFinal().*/
	};
	
	/**
	 * Estado atual do builder
	 **/
	Pkcs7Builder::State state;
	
	/**
	 * Estrutura OpenSSL que representa o pacote PKCS7 
	 **/
	PKCS7 *pkcs7;
	
	/**
	 * Estrutura OpenSSL usada na geração do pacote PKCS7
	 **/
	BIO *p7bio;
	
};

#endif /*PKCS7BUILDER_H_*/
