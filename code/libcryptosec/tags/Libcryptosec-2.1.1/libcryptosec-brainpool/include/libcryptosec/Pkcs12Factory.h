#ifndef PKCS12FACTORY_H_
#define PKCS12FACTORY_H_

#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/asn1.h>

#include <string>

#include "ByteArray.h"
#include "Pkcs12.h"

#include <libcryptosec/exception/EncodeException.h>

class Pkcs12Factory
{
public:
	
	/**
	 * Método estático que carrega um pacote PKCS12 a partir de seu equivalente codificado em DER.
	 * @param derEncoded pacote PKCS12 no formato binário DER.
	 * @return o pacote PKCS12 correspondente ao lido a partir de sua codificação em DER.
	 * @throw Pkcs7Exception se ocorrer algum probelma na geração do pacote PKCS7.
	 * @throw EncodeException se ocorrer algum problema na decodificação do pacote DER.
	 **/
	static Pkcs12* fromDerEncoded(ByteArray &derEncoded)
			throw (EncodeException);
};

#endif /*PKCS12FACTORY_H_*/
