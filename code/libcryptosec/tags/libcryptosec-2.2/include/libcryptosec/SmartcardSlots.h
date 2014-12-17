#ifndef SMARTCARDSLOTS_H_
#define SMARTCARDSLOTS_H_

#include <libp11.h>
#include <openssl/x509.h>

#include <string>
#include <vector>

#include "certificate/Certificate.h"

#include "SmartcardCertificate.h"
#include "SmartcardSlot.h"

#include <libcryptosec/exception/SmartcardModuleException.h>

/**
 * Representa um conjunto de slots PKCS#11.
 * Essa classe é responsável pelo acesso aos slots do módulo PKCS#11 e seus respectivos tokens.
 * @ingroup SmartCard
 **/

class SmartcardSlots
{

public:

	/**
	 * Construtor para uso interno.
	 * Para a obtenção de slots, a classe SmartcardReader deve ser utilizada.
	 * @param ctx ponteiro para a estrutura OpenSSL que compõe a implementação do padrão PKCS#11.
	 * @param scSlots ponteiro para a estrutura OpenSSL que compõe a implementação do padrão PKCS#11.
	 * @param nslots numero de slots presentes.
	 * @see SmartcardReader
	 */
	SmartcardSlots(PKCS11_CTX *ctx, PKCS11_SLOT *scSlots, unsigned int nslots);

	/**
	 * Destrutor padrão. Limpa as estruturas OpenSSL internas.
	 **/
	virtual ~SmartcardSlots();

	/**
	 * Retorna um slot específico a partir do seu serial e seu id.
	 * @param serial o número de série do slot a desejado.
	 * @param id o identificador do slot desejado.
	 * @return um slot de acordo com os parâmetros recebidos.
	 * @throw SmartcardModuleException caso o smart card não esteja disponível, caso um ou mais
	 * parâmetros tenham sido inválidos ou ainda caso tenha ocorrido um erro na carga dos possíveis
	 * certificados presentes no slot.
	 */
	SmartcardSlot* getSmartcardSlot(std::string serial, std::string id)
			throw (SmartcardModuleException);

	/**
	 * Retorna um vetor contendo os certificados presentes em cada um dos slots.
	 * @return os certificados contidos em cada um dos slots.
	 * @throw SmartcardModuleException caso o smart card não esteja disponível ou caso tenha
	 * ocorrido um erro na carga dos certificados relacionados aos slots.
	 */
	std::vector<SmartcardCertificate *> getCertificates()
			throw (SmartcardModuleException);

	/**
	 * Retorna a quantidade de Slots
	 * @return a quantidade de slots do smartcard
	 */
	unsigned int getSlotsCount();

protected:

	/**
	 * Estrutura OpenSSL para acesso ao módulo PKCS#11
	 **/
	PKCS11_CTX *ctx;

	/**
	 * Estrutura OpenSSL para acesso ao módulo PKCS#11
	 **/
	PKCS11_SLOT *scSlots;

	/**
	 * Número de slots encontrados.
	 **/
	unsigned int nslots;

};

#endif /*SMARTCARDSLOTS_H_*/
