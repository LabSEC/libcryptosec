#ifndef SMARTCARDSLOT_H_
#define SMARTCARDSLOT_H_

#include <libp11.h>

#include <string>

#include "ByteArray.h"
#include "SmartcardCertificate.h"
#include <libcryptosec/exception/SmartcardModuleException.h>

/**
 * Representa um slot PKCS#11.
 * Esta classe implementa um slot (instância lógica de uma leitora), conforme definido
 * no padrão PKCS#11. 
 * @ingroup SmartCard
 **/

class SmartcardSlot
{
	
public:

	/**
	 * Construtor para uso interno recebendo um ponteiro para uma estrutura
	 * OpenSSL que representa um slot PKCS#11.
	 * @param slot um ponteiro para a estrutura OpenSSl.
	 **/	
	SmartcardSlot(PKCS11_SLOT *slot);
	
	/**
	 * Destrutor padrão, limpa a estrutura interna OpenSSL.
	 **/
	virtual ~SmartcardSlot();
	
	/**
	 * Retorna o serial do slot.
	 * @return serial do slot.
	 **/
	std::string getSerial();
	
	/**
	 * Retorna o rótulo do slot.
	 * @return rótulo do slot.
	 **/
	std::string getLabel();
	
	/**
	 * Retorna um vetor contendo todos os certificados relacionados ao slot.
	 * @return lista de certificados encontrados no slot.
	 * @throw SmartcardModuleException caso tenha ocorrido um erro na carga dos certificados.
	 */
	std::vector<SmartcardCertificate *> getCertificates()
			throw (SmartcardModuleException);
	
	/**
	 * Usa a chave privada contida no slot para realizar a decifragem de dados.
	 * @param keyId o id da chave a ser utilizada.
	 * @param pin o PIN para permitir execução da operação.
	 * @param data referência para os dados a serem decifrados.
	 * @throw SmartcardModuleException com os seguintes códigos de erro:
	 * 	@li @c INVALID_PIN quando o PIN informado for inválido;
	 * 	@li @c ENUMERATING_PRIVATE_KEYS quando a chave privada não for encontrada;
	 * 	@li @c ID_NOT_FOUND quando o id da chave informado for inválido;
	 * 	@li @c DECRYPTING_DATA quando tiver ocorrido um erro na decifragem;
	 * 	@li @c BLOCKED_PIN quando o PIN da chave estiver no estado bloqueado.
	 */
	ByteArray decrypt(std::string &keyId, std::string &pin, ByteArray &data)
			throw (SmartcardModuleException);

private:

	/**
	 * Ponteiro para a estrutura OpenSSL que representa um slot.
	 **/
	PKCS11_SLOT *slot;

};

#endif /*SMARTCARDSLOT_H_*/
