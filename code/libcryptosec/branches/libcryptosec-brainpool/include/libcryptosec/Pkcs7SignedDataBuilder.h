#ifndef PKCS7SIGNEDDATABUILDER_H_
#define PKCS7SIGNEDDATABUILDER_H_

#include "Pkcs7Builder.h"

#include "Pkcs7SignedData.h"
#include "MessageDigest.h"

#include <libcryptosec/certificate/Certificate.h>

/**
 * Implementa o padrão builder para criação de um pacote PKCS7 assinado digitalmente.
 * @ingroup PKCS7
 **/

class Pkcs7SignedDataBuilder : public Pkcs7Builder
{
	
public:

	/**
	 * Construtor recebendo os parâmetros necessários à assinatura dos dados a serem adicionados
	 * ao pacote. O método Pkcs7SignedDataBuilder::init() é invocado nesse construtor.
	 * @param mesDigAlgorithm o algoritmo de hash que será usado na assinatura do pacote.
	 * @param cert referência para o certificado que será usado para assinar o conteúdo do PKCS7
	 * e irá compor o pacote.
	 * @param privKey chave privada que será usada na assinatura do pacote. 
	 * @param attached se true, o conteúdo do pacote estará contido no mesmo, caso contrário apenas
	 * a assinatura do conteúdo estará presente.
	 * @throw Pkcs7Exception caso ocorra algum problema na geração do pacote PKCS7.
	 * @see Pkcs7SignedDataBuilder::init()
	 **/
	Pkcs7SignedDataBuilder(MessageDigest::Algorithm mesDigAlgorithm, Certificate &cert,
				PrivateKey &privKey, bool attached) throw (Pkcs7Exception);
				
	
	/**
	 * Destrutor padrão.
	 **/			
	virtual ~Pkcs7SignedDataBuilder();
	
	/**
	 * Método responsável pela inicialização do builder. Após sua invocação, o builder estará pronto
	 * para receber os dados a serem empacotados. Pode ser usado também para reinicializar o mesmo
	 * com a mudança de um ou mais parâmetros.
	 * @param mesDigAlgorithm o algoritmo de hash que será usado na assinatura do pacote.
	 * @param cert referência para o certificado que será usado para assinar o conteúdo do PKCS7
	 * e irá compor o pacote.
	 * @param privKey chave privada que será usada na assinatura do pacote. 
	 * @param attached se true, o conteúdo do pacote estará contido no mesmo, caso contrário apenas
	 * a assinatura do conteúdo estará presente.
	 * @throw Pkcs7Exception caso ocorra algum problema na criação do pacote PKCS7.
	 **/	
	void init(MessageDigest::Algorithm mesDigAlgorithm, Certificate &cert,
				PrivateKey &privKey, bool attached) throw (Pkcs7Exception);
				
	/**
	 * Permite a co-assinatura do pacote por mais de uma chave privada.  
	 * @param mesDigAlgorithm o algoritmo de hash que será usado na assinatura do pacote.
	 * @param cert referência para o novo certificado que será adicionado como 
	 * assinador do pacote.
	 * @param privKey chave privada que será usada na co-assinatura do pacote.
	 * @throw InvalidStateException no caso do builder não ter sido inicializado ainda.
	 * @throw Pkcs7Exception caso tenha ocorrido um erro ao adicionar o certificado ao pacote PKCS7.
	 **/	
	void addSigner(MessageDigest::Algorithm mesDigAlgorithm, Certificate &cert, PrivateKey &privKey)
			throw (Pkcs7Exception, InvalidStateException);
			
	
	/**
	 * Permite adicionar certificados adicionais
	 * @param cert referência para certificado que será adicionado
	 * @throw InvalidStateException no caso do builder não ter sido inicializado ainda.
	 * @throw Pkcs7Exception caso tenha ocorrido um erro ao adicionar o certificado ao pacote PKCS7.
	 */
	void addCertificate(Certificate &cert) throw (Pkcs7Exception, InvalidStateException);	
	
	/**
	* Permite adicionar lista de certificados revogados
	* @param crl referência para a CRL que será adicionada
	* @throw InvalidStateException no caso do builder não ter sido inicializado ainda.
	* @throw Pkcs7Exception caso tenha ocorrido um erro ao adicionar o certificado ao pacote PKCS7.
	*/
	void addCrl(CertificateRevocationList &crl) throw (Pkcs7Exception, InvalidStateException);
	
	/**
	 * Especifica o uso das funções da superclasse Pkcs7Builder::doFinal(), recebendo um inputstream e
	 * um outputstream como parâmetros. 
	 * @see Pkcs7Builder::doFinal()
	 **/
	using Pkcs7Builder::doFinal;


	/**
	 * Implementa uma versão distinta do método Pkcs7Builder::doFinal() para gerar o pacote assinado.
	 * @return Pkcs7EnvelopedData o pacote PKCS7 criado.
	 * @throw InvalidStateException caso o builder não esteja no estado apropriado no momento da invocação.
 	 * @throw Pkcs7Exception caso tenha ocorrido um erro na geração do pacote PKCS7.
	 **/	
	Pkcs7SignedData* doFinal()
			throw (InvalidStateException, Pkcs7Exception);
	
	/**
	 * Implementa uma versão distinta do método Pkcs7Builder::doFinal() para gerar o pacote assinado.
	 * @param data contendo dados a serem concatenados ao conteudo do pacote antes da sua criação definitiva.
	 * @return Pkcs7EnvelopedData o pacote PKCS7 criado.
	 * @throw InvalidStateException caso o builder não esteja no estado apropriado no momento da invocação.
 	 * @throw Pkcs7Exception caso tenha ocorrido um erro na geração do pacote PKCS7.
	 **/	
	Pkcs7SignedData* doFinal(std::string &data)
			throw (InvalidStateException, Pkcs7Exception);
			
	/**
	 * Implementa uma versão distinta do método Pkcs7Builder::doFinal() para gerar o pacote assinado.
	 * @param data contendo dados a serem concatenados ao conteudo do pacote antes da sua criação definitiva.
	 * @return Pkcs7EnvelopedData o pacote PKCS7 criado.
	 * @throw InvalidStateException caso o builder não esteja no estado apropriado no momento da invocação.
 	 * @throw Pkcs7Exception caso tenha ocorrido um erro na geração do pacote PKCS7.
	 **/		
			
	Pkcs7SignedData* doFinal(ByteArray &data)
			throw (InvalidStateException, Pkcs7Exception);
};

#endif /*PKCS7SIGNEDDATABUILDER_H_*/
