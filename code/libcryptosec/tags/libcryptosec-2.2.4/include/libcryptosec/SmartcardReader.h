#ifndef SMARTCARDREADER_H_
#define SMARTCARDREADER_H_

#include <libp11.h>

#include <string>

#include "SmartcardSlots.h"
#include <libcryptosec/exception/InvalidStateException.h>
#include <libcryptosec/exception/SmartcardModuleException.h>

/**
 * @defgroup SmartCard Classes relacionadas ao uso de Smart Cards (PKCS11).
 **/
/**
 * Representa uma leitora de Smart Card.
 * Essa classe implementa o padrão Singleton. Deve ser utilizada para acessar uma 
 * ou mais leitoras de Smart Cards e obter os respectivos serviços providos pela 
 * especificação PKCS11.
 * @see SmartcardSlots
 * @see SmartcardSlot
 * @see SmartcardCertificate
 * @ingroup SmartCard 
 **/

class SmartcardReader
{
	
public:

	/**
	 * Inicializa a leitora para uso. Deve ser invocado uma vez antes
	 * de se fazer uso da leitora.
	 * @param pkcs11ModulePath o caminho para a biblioteca dinâmica que implementa um módulo PKCS11. 
	 * @throw InvalidStateException Se a leitora já tiver sido inicializada.
	 * @throw SmartcardModuleException caso o módulo PKCS11 seja inválido ou a 
	 * leitora não esteja disponível.
	 */
	static void initialize(std::string pkcs11ModulePath)
			throw (InvalidStateException, SmartcardModuleException);
	
	/**
	 * Destrói a instância da leitora inicializada.
	 * @throw InvalidStateException se nenhuma instância da leitora tiver sido inicializada.
	 */
	static void destroy() throw (InvalidStateException);
	
	/**
	 * Retorna a instância inicializada da leitora.
	 * @return a instância da leitora disponível para uso.
	 * @throw InvalidStateException se nenhuma instância da leitora tiver sido inicializada.
	 * @throw SmartcardModuleException caso a leitora não esteja disponível.
	 */
	static SmartcardReader* getInstance() throw (InvalidStateException, SmartcardModuleException);
	
	/**
	 * Retorna os slots (instâncias lógicas das leitoras) encontradas.
	 * @return os slots encontrados pelo módulo PKCS11.
	 * @throw SmartcardModuleException caso a leitora não esteja disponível.
	 */
	SmartcardSlots* getSmartcardSlots() throw (SmartcardModuleException);
	
private:

	/**
	 * Armazena o caminho para a biblioteca dinâmica que implementa o padrão PKCS11.
	 **/
	static std::string pkcs11ModulePath;
	
	/**
	 * Controla o estado da leitora. true se a leitora foi inicializada.
	 **/
	static bool initialized;
	
	/**
	 * Instância única que caracteriza o padrão de projetos Singleton e representa a leitora
	 * de Smart Cards carregada.
	 **/
	static SmartcardReader *instance;
	
	/**
	 * Estrutura interna OpenSSL que controla o uso do módulo PKCS11.
	 **/
	PKCS11_CTX *ctx;
	
	/**
	 * Construtor privado invocado pelo método estático SmartcardReader::getInstance().
	 * @throw SmartcardModuleException caso o módulo PKCS11 seja inválido ou a 
	 * leitora não esteja disponível.
	 */
	SmartcardReader(std::string &pkcs11ModulePath)
			throw (SmartcardModuleException);
	
	/**
	 * Destrutor privado invocado pelo método SmartcardReader::destroy().
	 **/		
	virtual ~SmartcardReader();
	
};

#endif /*SMARTCARDREADER_H_*/
