#ifndef PKCS7ENVELOPEDDATA_H_
#define PKCS7ENVELOPEDDATA_H_

#include <iostream>


#include "Pkcs7.h"
#include "PublicKey.h"
#include "SymmetricKey.h"
#include "SymmetricCipher.h"

#include <libcryptosec/exception/Pkcs7Exception.h>
#include <libcryptosec/certificate/Certificate.h>

/**
 * Representa um pacote PKCS7 Envelopado.
 * @ingroup PKCS7
 **/

class Pkcs7EnvelopedData : public Pkcs7
{
	
public:

	/**
	 * Construtor padrão recebendo um ponteiro para a estrutura OpenSSL PKCS7. Uma cópia rasa do
	 * objeto (struct) é feita, logo o ponteiro deve já ter sido alocado.
	 * @param pkcs7 um ponteiro para a estrutura OpenSSL PKCS7
	 * @throw Pkcs7Exception caso o ponteiro não contenha o endereço de uma estrutura PKCS7 válida. 
	 **/
	Pkcs7EnvelopedData(PKCS7 *pkcs7) throw (Pkcs7Exception);
	
	/**
	 * Destrutor padrão, limpa a estrutura PKCS7 aninhada. 
	 **/
	virtual ~Pkcs7EnvelopedData();
		
	/**
	 * Implementa o método abstrato Pkcs7::getType(). Retorna Pkcs7::ENVELOPED
	 * @return o tipo de pacote PKCS7, no caso Pkcs7::ENVELOPED
	 **/	
	virtual Pkcs7::Type getType();
	
	/**
	 * Decifra o pacote usando os parâmetros certificate e privateKey, colocando o resultado 
	 * no stream de saída out.
	 * @param certificate o certificado contendo a chave ou uma das chaves que cifraram o pacote.
	 * @param privateKey a chave privada correspondente ao certificado.
	 * @param out o stream de saída onde será colocado o resultado da decifragem. O stream deve ser
	 * alocado previamente.
	 **/
	void decrypt(Certificate &certificate, PrivateKey &privateKey, std::ostream *out)
			throw (Pkcs7Exception);
};

#endif /*PKCS7ENVELOPEDDATA_H_*/
