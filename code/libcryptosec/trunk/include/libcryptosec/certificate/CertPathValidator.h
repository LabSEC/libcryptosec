#ifndef CERTPATHVALIDATOR_H_
#define CERTPATHVALIDATOR_H_

#include <vector>
#include <time.h>

#include "CertPathValidatorResult.h"
#include "Certificate.h"
#include "CertificateRevocationList.h"
#include "ValidationFlags.h"
#include <libcryptosec/DateTime.h>


/**
 * @ingroup Util
 */

/**
 * @brief Valida certificados X509.
  */
class CertPathValidator
{
public:	
	
	/*
	 * Construtor.
	 * @param untrusted certificado a ser validado.
	 * @param untrustedChain vetor contendo os certificados do caminho de certificação. 
	 * @param trustedChain vetor de certificados confiáveis.
	 * @param when momento do tempo para se considerar a validade dos certificados.
	 * @param crls vetor de LCRs.
	 * @param flags vetor de flags para validação.
	 * @param @result ponteiro para objeto de diagnostico de validação em caso de erro.
	 * */
	CertPathValidator(Certificate& untrusted, vector<Certificate>& untrustedChain, vector<Certificate>& trustedChain, DateTime when = DateTime(time(NULL)), 
			vector<CertificateRevocationList> crls = vector<CertificateRevocationList>(), vector<ValidationFlags> flags = vector<ValidationFlags>()) 
				: flags(flags), when(when), untrusted(untrusted), trustedChain(trustedChain), untrustedChain(untrustedChain), crls(crls)
				{}
	
	/*
	 * Destrutor padrão.
	 * */			
	virtual ~CertPathValidator(){};
	
	/*
	 * Define momento do tempo para se considerar a validade dos certificados.
	 * @param when objeto DateTime;
	 * */
	void setTime(DateTime when);
	
	/*
	 * Define o certificado a ser validado.
	 * @param cert referência a um objeto Certificate.
	 * */
	void setUntrusted(Certificate& cert);
	
	/*
	 * Define caminho de certificação
	 * @param certs referência a um vetor de Certificados.
	 * */
	void setUnstrustedChain(vector<Certificate>& certs);
	
	/*
	 * Define certificados confiáveis.
	 * @param certs referência a um vetor de Certificados.
	 * */
	void setTrustedChain(vector<Certificate>& certs);
	
	/*
	 * Define LCRs
	 * Caso use-se a flag CRL_CHECK, deve-se definir a LCR referente ao certificado a ser validado. Já a flag CRL_CHECK_ALL exige que sejam definidas as LCRs de cada certificado do caminho de certificação, incluindo os certificados confiáveis.
	 * @param crls referência a um vetor de CertificateRevocationList.
	 * */
	void setCrls(vector<CertificateRevocationList>& crls);

	/*
	 * Define flags de validação
	 * @param flag item da enum ValidationFlags.
	 * */
	void setVerificationFlags(ValidationFlags flag);
	
	/*
	 * Define objeto de diagnóstico de validação.
	 * @param result ponteiro de ponteiro para objeto CertPathValidatorResult.
	 * */
	//void setResult(CertPathValidatorResult** result);
	
	/*
	 * Realiza validação de certificado.
	 * @return true caso o certificado seja válido. Caso o certificado seja inválido, false é retornado e o objeto CertPathValidatorResult é instanciado.
	 * */
	bool verify();
	
	/*
	 * Retorna se há avisos
	 * @return true se há avisos, false caso contrário.
	 * */
	bool getWarningsStatus();
	
	/*
	 * Retorna informações sobre a execução da validação.
	 * @return vetor de objetos CertPathValidatorResult;
	 * */
	vector<CertPathValidatorResult> getResults();
	
	/*
	 * Função callback de tratamento de erro de validação de assinaturas
	 * @param ok resultado da verificação
	 * @param ctx contexto de certificado
	 * @return 1
	 */
	static int callback(int ok, X509_STORE_CTX *ctx);
	
protected:
	
	/*
	 * Opções de validação.
	 * */
	vector<ValidationFlags> flags;
	
	/*
	 * Momento para se considerar a validade dos certificados.
	 * */	
	DateTime when;
	
	/*
	 * Certificado a ser validado.
	 * */
	Certificate& untrusted;
	
	/*
	 * Certificados confiáveis
	 * */
	vector<Certificate>& trustedChain;
	
	/*
	 * Caminho de certificação.
	 * É opcional incluir neste vetor o certificado a ser verificado e o a AC Raiz.
	 * */
	vector<Certificate>& untrustedChain;
	
	/*
	 * LCRs para verificar revogação
	 * Deve conter a LCR referente unstrusted se a opção CRL_CHECK é habilitada. 
	 * Se CRL_CHECK_ALL está habilitada, crls deve conter as LCRs referentes a cada certificado da cadeia de certificação.s
	 * */
	vector<CertificateRevocationList> crls;
	
	/*
	 * Informações sobre o resultado da validação.
	 * */
	//CertPathValidatorResult** result;
		
	/*
	 * Informações sobre o o resultado da validação.
	 * Esta var estática é utilizada para obter os dados na funcao de callback em C.
	 * Verificar problemas de concorrência com esta variável no caso de multi-threading.
	 * */
	static vector<CertPathValidatorResult> results; 

};

#endif /*CERTPATHVALIDATOR_H_*/
