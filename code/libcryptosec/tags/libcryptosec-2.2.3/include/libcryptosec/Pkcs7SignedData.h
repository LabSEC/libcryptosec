#ifndef PKCS7SIGNEDDATA_H_
#define PKCS7SIGNEDDATA_H_

#include "MessageDigest.h"
#include <libcryptosec/certificate/CertPathValidatorResult.h>
#include <libcryptosec/certificate/CertPathValidator.h>
#include <libcryptosec/certificate/ValidationFlags.h>
#include <libcryptosec/certificate/CertificateRevocationList.h>
#include "Pkcs7.h"
#include <libcryptosec/exception/Pkcs7Exception.h>

/**
 * @ingroup PKCS7
 * Representa um pacote PKCS7 assinado.
 **/


class Pkcs7SignedData : public Pkcs7
{
	
public:

	struct VERIFY_ERROR
	{
		
	};
	
	/**
	 * Construtor padrão recebendo um ponteiro para a estrutura OpenSSL PKCS7. Uma cópia rasa do
	 * objeto (struct) é feita, logo o ponteiro deve já ter sido alocado.
	 * @param pkcs7 um ponteiro para a estrutura OpenSSL PKCS7
	 * @throw Pkcs7Exception caso o ponteiro não contenha o endereço de uma estrutura PKCS7 válida. 
	 **/
	Pkcs7SignedData(PKCS7 *pkcs7) throw (Pkcs7Exception);
	
	/**
	 * Destrutor padrão, limpa a estrutura PKCS7 aninhada. 
	 **/	
	virtual ~Pkcs7SignedData();
	
	/**
	 * Implementa o método abstrato Pkcs7::getType(). Retorna Pkcs7::SIGNED
	 * @return o tipo de pacote PKCS7, no caso Pkcs7::SIGNED
	 **/	
	virtual Pkcs7::Type getType();
	
	/**
	 * Retorna a lista de certificados que assinaram esse pacote.
	 * @return a lista de certificados que assinaram o documento.
	 **/
	std::vector<Certificate *> getCertificates();
	
	
	/**
	 * Retorna uma lista com as crls inclusas nesse pacote.
	 * @return uma lista com as crls inclusas nesse pacote.
	 */
	std::vector<CertificateRevocationList *> getCrls();
	
	/**
	 * Verifica a integridade do pacote PKCS7.
	 * @return false se o pacote tiver sido corrompido, true caso contrário. 
	 **/
	//bool verify();
	
	
	/*
	 * Verifica a assinatura e/ou a integridade do pacote PKCS7
	 * @return true se o pacote é íntegro e/ou suas assinaturas são válidas
	 * @param checkSignerCert true para verificar as assinaturas do pacote, false caso contrário
	 * @param trusted certificados confiáveis
	 * @param cpvr objeto resultado da verificação das assinaturas
	 * @flags opções de validação (ver CertPathValidator::ValidationFlags)
	 */
	bool verify(bool checkSignerCert = false, vector<Certificate> trusted = vector<Certificate>(), CertPathValidatorResult **cpvr = NULL, vector<ValidationFlags>
		flags = vector<ValidationFlags>());
	
	/*
	 * Função callback de tratamento de erro de validação de assinaturas
	 * @param ok resultado da verificação
	 * @param ctx contexto de certificado
	 * @return 1
	 */
	static int callback(int ok, X509_STORE_CTX *ctx);
	
	
	/**
	 * Verifica a integridade do pacote PKCS7 e extrai seu conteúdo para o stream de saída
	 * passado como parâmetro.
	 * @param out o stream que receberá o conteúdo extraído.
	 * @return false se o pacote tiver sido corrompido, true caso contrário.
	 * @throw Pkcs7Exception caso a estrutura PKCS7 seja inválida.
	 **/
	bool verifyAndExtract(std::ostream *out) throw (Pkcs7Exception);
	
protected:
	static CertPathValidatorResult cpvr; 
};

//nao utilizado
//static void nodes_print(BIO *out, const char *name, STACK_OF(X509_POLICY_NODE) *nodes);
//static void policies_print(BIO *out, X509_STORE_CTX *ctx);

#endif /*PKCS7SIGNEDDATA_H_*/
