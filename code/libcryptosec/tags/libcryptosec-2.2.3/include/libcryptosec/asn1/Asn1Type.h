#ifndef ASN1TYPE_H_
#define ASN1TYPE_H_

#include <libcryptosec/ByteArray.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/ossl_typ.h>
#include <openssl/objects.h> 

class Asn1Type
{
public:
	
	enum Type
	{
		BOOLEAN,
		//STRING, //parece que ASN1_STRING é um tipo generico especializado por OCTET_STRING, UTF8STRING, etc 
		OBJECT,
		INTEGER,
		ENUMERATED,
		BIT_STRING,
		OCTET_STRING,
		PRINTABLESTRING,
		T61STRING,
		IA5STRING,
		GENERALSTRING,
		BMPSTRING,
		UNIVERSALSTRING,
		UTCTIME,
		GENERALIZEDTIME,
		VISIBLESTRING,
		UTF8STRING,
		SEQUENCE,
		SET,
	};
	
	virtual ~Asn1Type();
	
	Type getType() const throw();
	
	//nao faz copia
	const ASN1_TYPE* getAsn1Type() const throw();
	bool operator==(Asn1Type const& c) const throw();
	bool operator!=(Asn1Type const& c) const throw();

protected:
	Asn1Type();
	Asn1Type(ASN1_TYPE* asn1Type);
		
	ASN1_TYPE* asn1Type;
};

#endif /*ASN1TYPE_H_*/
