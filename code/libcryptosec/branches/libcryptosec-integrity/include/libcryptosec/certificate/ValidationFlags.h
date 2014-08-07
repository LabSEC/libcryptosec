#ifndef VALIDATIONFLAGS_H_
#define VALIDATIONFLAGS_H_

	/**
	 * @enum ValidationFlags
	 **/
	/**
	 * Opções de validação de certificado X509.
	 **/
	enum ValidationFlags
	{		
		CRL_CHECK, /*!< verificar revogação do certificado a ser validado */
		CRL_CHECK_ALL /*!< verificar revogação de todos os certificados do caminho de certificação */		
	};
	
#endif /*VALIDATIONFLAGS_H_*/

/*Este include foi criado para evitar cross-reference entre as classes CertPathValidator e CertPathValidatorResult*/
