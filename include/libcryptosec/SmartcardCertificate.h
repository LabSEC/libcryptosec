#ifndef SMARTCARDCERTIFICATE_H_
#define SMARTCARDCERTIFICATE_H_

#include <openssl/x509.h>

#include <string>

#include <libcryptosec/certificate/Certificate.h>

/**
 * Representa os Certificados contidos nos smart cards.
 * Essa classe contém as informações relativas a um certificado lido 
 * de um smart card. 
 * @ingroup SmartCard
 **/

class SmartcardCertificate
{
	
public:

	/**
	 * Construtor para uso interno, uma vez que os certificados são lidos de smart cards.
	 * @param id o identificador do certificado no smart card.
	 * @param label o rótulo dado ao certificado.
	 * @param serial o serial do certificado.
	 * @param cert ponteiro para a estrutura OpenSSL que representa um certificado X.509
	 **/
	SmartcardCertificate(std::string &id, std::string &label, std::string &serial, X509 *cert);
	
	/**
	 * Destrutor padrão, limpa a estrutura interna OpenSSL.
	 **/
	virtual ~SmartcardCertificate();
	
	/**
	 * Retorna o identificador do certificado.
	 * @return o identificador do certificado no smart card.
	 **/
	std::string getId();
	
	/**
	 * Retorna o rótulo do certificado.
	 * @return o rótulo do certificado no smart card.
	 **/
	std::string getLabel();
	
	/**
	 * Retorna o serial do certificado.
	 * @return o serial do certificado.
	 **/
	std::string getSerial();
	
	/**
	 * Retorna o certificado X.509 presente no smart card.
	 * @return ponteiro para o certificado X.509 
	 **/
	Certificate* getCertificate();

private:

	/**
	 * Ponteiro para a estrutura OpenSSL que representa um certificado X.509
	 **/
	X509 *cert;
	
	/**
	 * Identificador do certificado no smart card.
	 **/
	std::string id;
	
	/**
	 * Rótulo do certificado no smart card.
	 **/
	std::string label;
	
	/**
	 * Serial do certificado.
	 **/
	std::string serial;

};

#endif /*SMARTCARDCERTIFICATE_H_*/
