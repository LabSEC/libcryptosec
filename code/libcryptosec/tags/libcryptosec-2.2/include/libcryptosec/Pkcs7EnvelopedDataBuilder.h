#ifndef PKCS7ENVELOPEDDATABUILDER_H_
#define PKCS7ENVELOPEDDATABUILDER_H_

#include <string>

#include "ByteArray.h"
#include "SymmetricKey.h"
#include "SymmetricCipher.h"
#include "Pkcs7Builder.h"
#include "Pkcs7EnvelopedData.h"

#include <libcryptosec/exception/Pkcs7Exception.h>
#include <libcryptosec/exception/InvalidStateException.h>
#include <libcryptosec/certificate/Certificate.h>

/**
 * Implementa o padrão builder para criação de um pacote PKCS7 envelopado com o uso de criptografia.
 * @ingroup PKCS7
 **/
class Pkcs7EnvelopedDataBuilder : public Pkcs7Builder
{
	
public:

	/**
	 * Construtor recebendo os parâmetros necessários à envelopagem dos dados a serem adicionados
	 * ao pacote. O método Pkcs7EnvelopedDataBuilder::init() é invocado nesse construtor.
	 * @param cert referência para o certificado que será usado para proteger o conteúdo do PKCS7
	 * e irá compor o pacote.
	 * @param symAlgorithm o algoritmo simétrico que everá ser usado na envelopagem do pacote.
	 * @param symOperationMode o modo de operação necessário para alguns cifradores, deve ser 
	 * SymmetricCipher::NO_MODE para algoritmos que não precisem desse parâmetro.
	 * @throw Pkcs7Exception caso ocorra algum problema na criação do pacote PKCS7.
	 * @throw SymmetricCipherException caso ocorra algum problema na envelopagem do pacote PKCS7.
	 * @see Pkcs7EnvelopedDataBuilder::init()
	 **/	 
	Pkcs7EnvelopedDataBuilder(Certificate &cert, SymmetricKey::Algorithm symAlgorithm,
				SymmetricCipher::OperationMode symOperationMode)
			throw (Pkcs7Exception, SymmetricCipherException);
			
	/**
	 * Destrutor padrão.
	 **/		
	virtual ~Pkcs7EnvelopedDataBuilder();
		
	/**
	 * Método responsável pela inicialização do builder. Após sua invocação, o builder estará pronto
	 * para receber os dados a serem empacotados. Pode ser usado também para reinicializar o mesmo
	 * com a mudança de um ou mais parâmetros.
	 * @param cert referência para o certificado que será usado para proteger o conteúdo do PKCS7.
	 * @param symAlgorithm o algoritmo simétrico que everá ser usado na envelopagem do pacote.
	 * @param symOperationMode o modo de operação necessário para alguns cifradores, deve ser 
	 * SymmetricCipher::NO_MODE para algoritmos que não precisem desse parâmetro.
	 * @throw Pkcs7Exception caso ocorra algum problema na criação do pacote PKCS7.
	 * @throw SymmetricCipherException caso ocorra algum problema na envelopagem do pacote PKCS7.
	 * @see Pkcs7EnvelopedDataBuilder::init()
	 **/	
	void init(Certificate &cert, SymmetricKey::Algorithm symAlgorithm,
				SymmetricCipher::OperationMode symOperationMode)
			throw (Pkcs7Exception, SymmetricCipherException);
	
	/**
	 * Permite a adição de novos certificados cujas chaves privadas correspondentes estarão aptas a 
	 * abrir o pacote PKCS7.
	 * @param certificate referência para o novo certificado que estará apto a abrir o pacote.
	 * @throw InvalidStateException no caso do builder não ter sido inicializado ainda.
	 * @throw Pkcs7Exception caso tenha ocorrido um erro ao adicionar o certificado ao pacote PKCS7.
	 **/		
	void addCipher(Certificate &certificate) throw (InvalidStateException, Pkcs7Exception);
	
	/**
	 * Especifica o uso das funções da superclasse Pkcs7Builder::doFinal(), recebendo um inputstream e
	 * um outputstream como parâmetros. 
	 * @see Pkcs7Builder::doFinal()
	 **/
	using Pkcs7Builder::doFinal;
	
	/**
	 * Implementa uma versão distinta do método Pkcs7Builder::doFinal() para gerar o pacote envelopado.
	 * @return Pkcs7EnvelopedData o pacote PKCS7 criado.
	 * @throw InvalidStateException caso o builder não esteja no estado apropriado no momento da invocação.
 	 * @throw Pkcs7Exception caso tenha ocorrido um erro na geração do pacote PKCS7.
	 **/
	Pkcs7EnvelopedData* doFinal()
			throw (InvalidStateException, Pkcs7Exception);
	
	/**
	 * Implementa uma versão distinta do método Pkcs7Builder::doFinal() para gerar o pacote envelopado.
	 * @param data contendo dados a serem concatenados ao conteudo do pacote antes da sua criação definitiva.
	 * @return Pkcs7EnvelopedData o pacote PKCS7 criado.
	 * @throw InvalidStateException caso o builder não esteja no estado apropriado no momento da invocação.
 	 * @throw Pkcs7Exception caso tenha ocorrido um erro ao adicionar o certificado ao pacote PKCS7.
	 **/		
	Pkcs7EnvelopedData* doFinal(std::string &data)
			throw (InvalidStateException, Pkcs7Exception);
			
	/**
	 * Implementa uma versão distinta do método Pkcs7Builder::doFinal() para gerar o pacote envelopado.
	 * @param data contendo dados a serem concatenados ao conteudo do pacote antes da sua criação definitiva.
	 * @return Pkcs7EnvelopedData o pacote PKCS7 criado.
	 * @throw InvalidStateException caso o builder não esteja no estado apropriado no momento da invocação.
 	 * @throw Pkcs7Exception caso tenha ocorrido um erro ao adicionar o certificado ao pacote PKCS7.
	 **/
	Pkcs7EnvelopedData* doFinal(ByteArray &data)
			throw (InvalidStateException, Pkcs7Exception);
			
};

#endif /*PKCS7ENVELOPEDDATABUILDER_H_*/
