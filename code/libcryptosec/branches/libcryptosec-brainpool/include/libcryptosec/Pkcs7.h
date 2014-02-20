#ifndef PKCS7_H_
#define PKCS7_H_

#include <openssl/pem.h>
#include <openssl/pkcs7.h>

#include <string>
#include <vector>

#include "ByteArray.h"
#include <libcryptosec/certificate/Certificate.h>
#include <libcryptosec/exception/EncodeException.h>
#include <libcryptosec/exception/Pkcs7Exception.h>

/**
 * @defgroup PKCS7 Classes relacionadas ao uso de pacotes PKCS7
 **/
 
 /** 
 * Classe abstrata que implementa a especificação PKCS#7 para empacotamento de conteúdo 
 * utilizando criptografia assimétrica. 
 * @see Pkcs7Factory
 * @see Pkcs7EnvelopedData
 * @see Pkcs7SignedData
 * @see Pkcs7Builder
 * @see Pkcs7EnvelopedDataBuilder 
 * @see Pkcs7SignedDataBuilder 
 * @ingroup PKCS7
 **/
 
class Pkcs7
{

public:

	/**
	 * @enum Type
	 **/
	/**
	 * Determina o tipo de procedimento criptográfico aplicado ao pacote, podendo ser SIGNED
	 * caso o conteúdo esteja assinado ou ENVELOPED caso o conteúdo esteja criptografado.
	 **/
	enum Type
	{
		SIGNED, /*!< O pacote é assinado */
		ENVELOPED, /*!< O pacote é envelopado */
		CERTIFICATE_BUNDLE /*!< O pacote é usado para diseminação de certificados */
	};
	
	/**
	 * Construtor recebendo um ponteiro para a estrutura PKCS7 da biblioteca OpenSSL.
	 * Esse construtor é para uso interno. Para carregar um pacote PKCS7 a classe Pkcs7Factory
	 * deverá ser consultada. Para construir um novo pacote consulte a classe Pkcs7Builder
	 * @param pkcs7 ponteiro para a estrutura PKCS7
	 **/	
	Pkcs7(PKCS7 *pkcs7);
	
	/**
	 * Destrutor padrão.
	 * Limpa a estrutura OpenSSL PKCS7 da memória. 
	 **/
	virtual ~Pkcs7();
	
	/**
	 * Método abstrato que retorna o tipo de procedimento de segurança 
	 * aplicado ao conteúdo do pacote. 
	 * @return o tipo de procedimento criptografico aplicado ao pacote, como
	 * assinatura ou cifragem. 
	 **/
	virtual Pkcs7::Type getType() = 0;
	
	/**
	 * Retorna uma representação do pacote codificada no formato PEM.
	 * @return conteúdo do pacote no formado PEM
	 * @throw EncodeException se ocorrer algum erro no procedimento de codificação
	 * do pacote para o formato PEM.
	 **/
	std::string getPemEncoded() throw (EncodeException);
	
	/**
	 * Retorna uma representação do pacote codificada no formato DER.
	 * @return conteúdo do pacote no formado DER
	 * @throw EncodeException se ocorrer algum erro no procedimento de codificação
	 * do pacote para o formato DER.
	 **/
	ByteArray getDerEncoded() throw (EncodeException);

protected:

	/**
	 * Ponteiro para a estrutura PKCS7 da biblioteca OpenSSL
	 **/
	PKCS7 *pkcs7;
	
};

#endif /*PKCS7_H_*/
