#include <libcryptosec/Pkcs7SignedData.h>

CertPathValidatorResult Pkcs7SignedData::cpvr;

Pkcs7SignedData::Pkcs7SignedData(PKCS7 *pkcs7) throw (Pkcs7Exception) : Pkcs7(pkcs7)
{
	if (OBJ_obj2nid(this->pkcs7->type) != NID_pkcs7_signed)
	{
		throw Pkcs7Exception(Pkcs7Exception::INVALID_TYPE, "Pkcs7SignedData::Pkcs7SignedData");
	}
}

Pkcs7SignedData::~Pkcs7SignedData()
{
}

Pkcs7::Type Pkcs7SignedData::getType()
{
	return Pkcs7::SIGNED;
}

std::vector<Certificate *> Pkcs7SignedData::getCertificates()
{
	std::vector<Certificate *> ret;
	int i, num;
	X509 *oneCertificate;
	Certificate *certificate;
	num = sk_X509_num(this->pkcs7->d.sign->cert);
	for (i=0;i<num;i++)
	{
		oneCertificate = sk_X509_value(this->pkcs7->d.sign->cert, i);
		certificate = new Certificate(X509_dup(oneCertificate));
		ret.push_back(certificate);
	}
	return ret;
}

std::vector<CertificateRevocationList *> Pkcs7SignedData::getCrls()
{
	std::vector<CertificateRevocationList *> ret;
	int i, num;
	X509_CRL *oneX509Crl;
	CertificateRevocationList *crl;
	num = sk_X509_CRL_num(this->pkcs7->d.sign->crl);
	for (i=0;i<num;i++)
	{
		oneX509Crl = sk_X509_CRL_value(this->pkcs7->d.sign->crl, i);
		crl = new CertificateRevocationList(X509_CRL_dup(oneX509Crl));
		ret.push_back(crl);
	}
	return ret;	
}

/*bool Pkcs7SignedData::verify()
{
	BIO *p7bio;
	bool ret;
	int rc;
	p7bio = PKCS7_dataInit(this->pkcs7, NULL);
	rc = PKCS7_verify(this->pkcs7, NULL, NULL, p7bio, NULL, PKCS7_NOVERIFY);
	if (rc == 1)
	{
		ret = true;
	}
	else
	{
		 this case can be a error 
		ret = false;
	}
	BIO_free(p7bio);
	return ret;
}*/

bool Pkcs7SignedData::verify(bool checkSignerCert, vector<Certificate> trustedCerts, CertPathValidatorResult **cpvr, vector<ValidationFlags> vflags)
{
	BIO *p7bio;
	bool ret;
	int rc;
	int i;
	int flags = 0;	
	X509_STORE *store = NULL;
	STACK_OF(X509) *certs = NULL;

	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	
	if(checkSignerCert)
	{
		 
		i=OBJ_obj2nid(this->pkcs7->type);
		switch (i)
		{
			case NID_pkcs7_signed:
				certs = this->pkcs7->d.sign->cert;
				break;
		
			case NID_pkcs7_signedAndEnveloped:
				certs = this->pkcs7->d.signed_and_enveloped->cert;
				break;
		
			default:
				throw Pkcs7Exception(Pkcs7Exception::INVALID_TYPE, "Pkcs7SignedData::verify");				
		}
						
		//instancia store de certificados
		if(!(store = X509_STORE_new()))
		{
			throw Pkcs7Exception(Pkcs7Exception::INTERNAL_ERROR, "Pkcs7SignedData::verify");
		}
		
		//define funcao de callback
		X509_STORE_set_verify_cb_func(store, Pkcs7SignedData::callback);
		
		//define certificados confiaveis
		for(unsigned int i = 0 ;  i < trustedCerts.size(); i++)
		{
			X509_STORE_add_cert(store, trustedCerts.at(i).getX509());
		}				
		
		//define flags
		for(unsigned int i = 0 ; i < vflags.size() ; i++)
		{
			switch(vflags.at(i))
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
		
/*		if( (sk_X509_CRL_num(this->pkcs7->d.sign->crl) > 0) || 
				(sk_X509_CRL_num(this->pkcs7->d.signed_and_enveloped->crl) > 0 ))
		{
			//X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL); //obriga a haver uma crl para cada nivel da cadeia de certificacao
			X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
		}
*/	
	}
	else
	{
		flags = PKCS7_NOVERIFY;
	}
	
	p7bio = PKCS7_dataInit(this->pkcs7, NULL);
	
	rc = PKCS7_verify(this->pkcs7, certs, store, p7bio, NULL, flags);
	if (rc == 1)
	{
		ret = true;
	}
	else
	{
		//this case can be a error 
		ret = false;
		
		if(cpvr)
		{
			*cpvr = new CertPathValidatorResult(Pkcs7SignedData::cpvr);
		}
	}
	
	/*desaloca estruturas*/
	BIO_free(p7bio);
	X509_STORE_free(store);
	
	return ret;
}

bool Pkcs7SignedData::verifyAndExtract(std::ostream *out) throw (Pkcs7Exception)
{
	BIO *p7bio;
	bool ret;
	ret = this->verify();
	p7bio = PKCS7_dataInit(this->pkcs7, NULL);
	if (!p7bio)
	{
		throw Pkcs7Exception(Pkcs7Exception::INTERNAL_ERROR, "Pkcs7SignedData::verifyAndExtract");
	}
	int size, maxSize, finalSize;
	maxSize = 1024;
	size = maxSize;
	finalSize = 0;
	char buf[maxSize+1];
	while (size == maxSize)
	{
		size = BIO_read(p7bio, buf, maxSize);
		if (size == 0)
		{
			break;
		}
		out->write(buf, size);
	}
	BIO_free(p7bio);
	return ret;
}

int Pkcs7SignedData::callback(int ok, X509_STORE_CTX *ctx)
	{
	//int v_verbose = 1;
	//char buf[256];
	Certificate* cert = NULL;
	
	
	if (!ok)
	{
		if (X509_STORE_CTX_get_current_cert(ctx))
		{
			cert = new Certificate(X509_STORE_CTX_get_current_cert(ctx));
			Pkcs7SignedData::cpvr.setInvalidCertificate(cert);
/*			X509_NAME_oneline(
				X509_get_subject_name(ctx->current_cert),buf,
				sizeof buf);
			printf("%s\n",buf);
*/
			
		}


		Pkcs7SignedData::cpvr.setDepth(X509_STORE_CTX_get_error_depth(ctx));
		Pkcs7SignedData::cpvr.setErrorCode(CertPathValidatorResult::long2ErrorCode(X509_STORE_CTX_get_error(ctx)));
		
/*		printf("error %d at %d depth lookup:%s\n",ctx->error,
			ctx->error_depth,
			X509_verify_cert_error_string(ctx->error));
*/
		
		
		if (X509_STORE_CTX_get_error(ctx) == X509_V_ERR_CERT_HAS_EXPIRED) ok=1;

/*		since we are just checking the certificates, it is
		 * ok if they are self signed. But we should still warn
		 * the user.
*/
		//martin: usar switch case.
 		 
		if (X509_STORE_CTX_get_error(ctx) == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) ok=1;
		//Continue after extension errors too 
		if (X509_STORE_CTX_get_error(ctx) == X509_V_ERR_INVALID_CA) ok=1;
		if (X509_STORE_CTX_get_error(ctx) == X509_V_ERR_INVALID_NON_CA) ok=1;
		if (X509_STORE_CTX_get_error(ctx) == X509_V_ERR_PATH_LENGTH_EXCEEDED) ok=1;
		if (X509_STORE_CTX_get_error(ctx) == X509_V_ERR_INVALID_PURPOSE) ok=1;
		if (X509_STORE_CTX_get_error(ctx) == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) ok=1;
		if (X509_STORE_CTX_get_error(ctx) == X509_V_ERR_CRL_HAS_EXPIRED) ok=1;
		if (X509_STORE_CTX_get_error(ctx) == X509_V_ERR_CRL_NOT_YET_VALID) ok=1;
		if (X509_STORE_CTX_get_error(ctx) == X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION) ok=1;

		
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

//Funcoes C para imprimir informacoes sobre erro de validacao de politicas
/*
static void policies_print(BIO *out, X509_STORE_CTX *ctx)
	{
	X509_POLICY_TREE *tree;
	int explicit_policy;
	int free_out = 0;
	if (out == NULL)
		{
		out = BIO_new_fp(stderr, BIO_NOCLOSE);
		free_out = 1;
		}
	tree = X509_STORE_CTX_get0_policy_tree(ctx);
	explicit_policy = X509_STORE_CTX_get_explicit_policy(ctx);

	BIO_printf(out, "Require explicit Policy: %s\n",
				explicit_policy ? "True" : "False");

	nodes_print(out, "Authority", X509_policy_tree_get0_policies(tree));
	nodes_print(out, "User", X509_policy_tree_get0_user_policies(tree));
	if (free_out)
		BIO_free(out);
	}

static void nodes_print(BIO *out, const char *name,
	STACK_OF(X509_POLICY_NODE) *nodes)
	{
	X509_POLICY_NODE *node;
	int i;
	BIO_printf(out, "%s Policies:", name);
	if (nodes)
		{
		BIO_puts(out, "\n");
		for (i = 0; i < sk_X509_POLICY_NODE_num(nodes); i++)
			{
			node = sk_X509_POLICY_NODE_value(nodes, i);
			X509_POLICY_NODE_print(out, node, 2);
			}
		}
	else
		BIO_puts(out, " <empty>\n");
	}
*/
