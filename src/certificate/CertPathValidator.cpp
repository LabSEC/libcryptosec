#include <libcryptosec/certificate/CertPathValidator.h>

/*instancia variavel estatica*/
vector<CertPathValidatorResult> CertPathValidator::results;

/*CertPathValidator::CertPathValidator()
{
}*/

/*CertPathValidator::~CertPathValidator()
{
}*/

void CertPathValidator::setTime(DateTime when)
{
	this->when = when;
}

void CertPathValidator::setUntrusted(Certificate& cert)
{
	this->untrusted = cert;
}

void CertPathValidator::setUnstrustedChain(vector<Certificate>& certs)
{
	this->untrustedChain = certs;
}

void CertPathValidator::setTrustedChain(vector<Certificate>& certs)
{
	this->trustedChain = certs;
}

void CertPathValidator::setCrls(vector<CertificateRevocationList>& crls)
{
	this->crls = crls;
}

void CertPathValidator::setVerificationFlags(ValidationFlags flag)
{
	this->flags.push_back(flag);
}

/*void CertPathValidator::setResult(CertPathValidatorResult** result)
{
	this->result = result;
}*/

bool CertPathValidator::verify()
{
	//BIO *p7bio;
	bool ret;
	int rc;	
	X509_STORE *store = NULL;
	X509_STORE_CTX *cert_ctx;
	STACK_OF(X509) *certs = NULL;

	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	
	/*instancia store de certificados
	 * ignorou-se a possibilidade de falta de memoria
	 */
	store = X509_STORE_new();
	
	/*instancia contexto
	 * ignorou-se a possibilidade de falta de memoria
	 */
	cert_ctx = X509_STORE_CTX_new();
	
	/*instancia pilha de certificados para conter caminho de certificacao
	 * ignorou-se a possibilidade de falta de memoria
	 */
	certs = sk_X509_new_null();
	
	//popula pilha
	for(unsigned int k = 0 ; k < this->untrustedChain.size() ; k++)
	{
		/* ignorou-se o retorno do push na pilha. 
		 * Retorno de erro (0) ocorreria no caso de falta de memoria. 
		 * Ver funcao sk_insert do openssl
		 */
		sk_X509_push(certs, this->untrustedChain.at(k).getX509());
	}
	
	//define funcao de callback
	X509_STORE_set_verify_cb_func(store, CertPathValidator::callback);
	
	//define certificados confiaveis
	for(unsigned int i = 0 ;  i < this->trustedChain.size(); i++)
	{
		X509_STORE_add_cert(store, trustedChain.at(i).getX509());
	}			
	
	//define flags
	for(unsigned int i = 0 ; i < this->flags.size() ; i++)
	{
		switch(this->flags.at(i))
		{
			case CRL_CHECK:
				X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
				break;
			
			case CRL_CHECK_ALL:
				/*precisa por CRL_CHECK tambem, caso contrario o openssl nao verifica CRL*/
				X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
				X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK_ALL);
				break;
		}
	}
	
	/*adiciona crls ao store*/
	for(unsigned int i = 0 ; i < this->crls.size() ; i++)
	{
		X509_STORE_add_crl(store, this->crls.at(i).getX509Crl());
	}
	
	/* inicializa contexto
	 * ignorou-se a possibilidade de falta de memoria
	 */
	X509_STORE_CTX_init(cert_ctx, store, this->untrusted.getX509(), certs);
	
	
	/* define a data para verificar os certificados da cadeia
	* obs: o segundo parametro da funcao 
	* void X509_STORE_CTX_set_time(X509_STORE_CTX *ctx, unsigned long flags, time_t t)
	* nao eh utilizado, segundo verificou-se no arquivo crypto/x509/x509_vfy.c
	*/
	X509_STORE_CTX_set_time(cert_ctx, 0 ,this->when.getDateTime());
	
	/*Garante que não há informações de validações prévias*/
	CertPathValidator::results.clear();
	
	/*verifica certificado*/
	rc = X509_verify_cert(cert_ctx);
	if (rc == 1)
	{
		ret = true;
	}
	else
	{
		//this case can be a error 
		ret = false;
		
		//código antigo, que não previa warnings
/*		if(this->result)
		{
			faz copia do objeto
			*this->result = new CertPathValidatorResult(CertPathValidator::cpvr);
		}*/
	}
	
	/*desaloca estruturas*/
	sk_X509_free(certs);
	X509_STORE_free(store);
	X509_STORE_CTX_free(cert_ctx);
	return ret;

}

vector<CertPathValidatorResult> CertPathValidator::getResults()
{
	return CertPathValidator::results;
}

bool CertPathValidator::getWarningsStatus()
{
	bool ret = false;
	
	if(this->results.size() > 0)
	{
		ret = true;
	}
	
	return ret;
}

int CertPathValidator::callback(int ok, X509_STORE_CTX *ctx)
	{
	Certificate* cert = NULL;
	CertPathValidatorResult aResult;
	
	if (!ok)
	{
		cert = new Certificate(X509_STORE_CTX_get_current_cert(ctx));
		if (cert)
		{
			aResult.setInvalidCertificate(cert);
		}

		aResult.setDepth(X509_STORE_CTX_get_error_depth(ctx));
		int error = X509_STORE_CTX_get_error(ctx);
		aResult.setErrorCode(CertPathValidatorResult::long2ErrorCode(error));

		/*
		* O aplicativo apps/verify.c do OpenSSL ignora todos os erros abaixo. 
		* Porem discorda-se nos erros X509_V_ERR_CERT_HAS_EXPIRED e X509_V_ERR_INVALID_CA
		* ok = 0 são considerados erros e interrompem a validação
		* ok = 1 são considerados como avisos e não interrompem a validação
		*/
		if (error == X509_V_ERR_CERT_HAS_EXPIRED) ok=0; 		 
		if (error == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) ok=1;
		if (error == X509_V_ERR_INVALID_CA) ok=0;
		if (error == X509_V_ERR_INVALID_NON_CA) ok=1;
		if (error == X509_V_ERR_PATH_LENGTH_EXCEEDED) ok=1;
		if (error == X509_V_ERR_INVALID_PURPOSE) ok=1;
		if (error == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) ok=1;
		if (error == X509_V_ERR_CRL_HAS_EXPIRED) ok=1;
		if (error == X509_V_ERR_CRL_NOT_YET_VALID) ok=1;
		if (error == X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION) ok=1;

		/* 
		 * Na ocorrência de erro, os avisos (warnings) antigos são descartados
		 * */
		if(!ok)
		{
			CertPathValidator::results.clear();
		}
		
		CertPathValidator::results.push_back(aResult);
		
		//TODO incluir informacoes de erro de politicas na classe CertPathValidatorResult
	/*
		if (ctx->error == X509_V_ERR_NO_EXPLICIT_POLICY)
			policies_print(NULL, ctx);
	*/
		return ok;

		}
/*	if ((ctx->error == X509_V_OK) && (ok == 2))
		policies_print(NULL, ctx);
	if (!v_verbose)
		ERR_clear_error();
*/
	return(ok);
	}
