#ifndef SYMMETRICCIPHER_H_
#define SYMMETRICCIPHER_H_

#include <string>

#include <openssl/evp.h>

#include "SymmetricKey.h"
#include <libcryptosec/exception/SymmetricCipherException.h>
#include <libcryptosec/exception/InvalidStateException.h>

/**
 * @defgroup Symmetric Classes envolvidas no uso da criptografia simétrica. 
 **/

/**
 * Implementa as funcionalidades de um cifrador de bloco simétrico.
 * Essa classe implementa o padrão de projetos Builder e implementa as operações
 * de um cifrador simétrico como cifragem e decifragem de dados.
 * @ingroup Symmetric
 **/

class SymmetricCipher
{
	
public:

	/**
	 * @enum OperationMode
	 **/
	/**
	 * Modos de operação suportados pelo cifrador.
	 **/
	enum OperationMode
	{
		NO_MODE, /*!< quando o cifrador possuir um único modo de operação */
		CBC, /*!< para usar o modo cipher block chaining */
		ECB, /*!< para usar o modo eletronic code book */
		CFB, /*!< para usar o modo cipher feedback mode */
		OFB, /*!< para usar o modo output feedback mode */
	};
	
	/**
	 * @enum Operation
	 **/
	/**
	 * Tipos de operações possíveis no cifrador.
	 **/
	enum Operation
	{
		ENCRYPT, /*!< na cifragem de dados */
		DECRYPT, /*!< na decifragem de dados */
	};
	
	/**
	 * Construtor padrão.
	 **/
	SymmetricCipher();
	
	/**
	 * Construtor de cópia recebendo uma chave simétrica e o tipo de operação requerida.
	 * Esse construtor invoca a versão do método SymmetricCipher::init() de mesmos 
	 * parâmetros.
	 * @param key a chave simétrica a ser usada na operação.
	 * @param operation a operação a ser executada.
	 * @throw SymmetricCipherException caso ocorra algum erro na criação do cifrador.
	 **/
	SymmetricCipher(SymmetricKey &key, SymmetricCipher::Operation operation)
			throw (SymmetricCipherException);
	
	/**
	 * Construtor de cópia recebendo uma chave simétrica, o modo de operação
	 * e o tipo de operação requerida.
	 * Esse construtor invoca a versão do método SymmetricCipher::init() de mesmos 
	 * parâmetros.
	 * @param key a chave simétrica a ser usada na operação.
	 * @param mode o modo de operação do algoritmo.
	 * @param operation a operação a ser executada.
	 * @throw SymmetricCipherException caso ocorra algum erro na criação do cifrador.
	 **/		
	SymmetricCipher(SymmetricKey &key, SymmetricCipher::OperationMode mode, SymmetricCipher::Operation operation)
		 	throw (SymmetricCipherException);
	
	/**
	 * Destrutor padrão.
	 **/
	virtual ~SymmetricCipher();
	
	/**
	 * Inicializa o cifrador para uso. Necessário caso o builder tenha sido instanciado
	 * a partir de seu contrutor sem parâmetros.
	 * @param key a chave simétrica a ser usada na operação.
	 * @param operation a operação a ser executada.
	 * @throw SymmetricCipherException caso ocorra algum erro na criação do cifrador.
	 **/
	void init(SymmetricKey &key, SymmetricCipher::Operation operation)
			throw (SymmetricCipherException);
	
	/**
	 * Inicializa o cifrador para uso. Necessário caso o builder tenha sido instanciado
	 * a partir de seu contrutor sem parâmetros.
	 * @param key a chave simétrica a ser usada na operação.
	 * @param mode o modo de operação do algoritmo.
	 * @param operation a operação a ser executada.
	 * @throw SymmetricCipherException caso ocorra algum erro na criação do cifrador.
	 **/
	void init(SymmetricKey &key, SymmetricCipher::OperationMode mode, SymmetricCipher::Operation operation)
			throw (SymmetricCipherException);
	
	/**
	 * Concatena dados aos previamente adicionados para serem cifrados/decifrados.
	 * @param data referência para os dados no formato de texto.
	 * @throw InvalidStateException caso o builder não tenha sido inicializado.
	 * @throw SymmetricCipherException caso tenha ocorrido algum erro ao atualizar os dados.
	 **/
	void update(std::string &data) throw (InvalidStateException, SymmetricCipherException);

	/**
	 * Concatena dados aos previamente adicionados para serem cifrados/decifrados.
	 * @param data referência para os dados no formato binário.
	 * @throw InvalidStateException caso o builder não tenha sido inicializado.
	 * @throw SymmetricCipherException caso tenha ocorrido algum erro ao atualizar os dados.
	 **/	
	void update(ByteArray &data) throw (InvalidStateException, SymmetricCipherException);
	
	/**
	 * Finaliza a operação e retorna o resultado da mesma.
	 * @return o resultado da operação aplicada aos dados submetidos ao cifrador.
	 * @throw InvalidStateException não esteja no esteja no estado apropriado (State::UPDATE).
	 * @throw SymmetricCipherException caso ocorra algum erro na finalização do procedimento.
	 **/	
	ByteArray doFinal() throw (InvalidStateException, SymmetricCipherException);
	
	/**
	 * Concatena os dados passados como parâmetro, finaliza a operação e retorna o resultado da mesma.
	 * @param os dados a serem concatenados no formato de texto.
	 * @return o resultado da operação aplicada aos dados submetidos ao cifrador.
	 * @throw InvalidStateException não esteja no esteja no estado apropriado (State::UPDATE).
	 * @throw SymmetricCipherException caso ocorra algum erro na finalização do procedimento.
	 **/	
	ByteArray doFinal(std::string &data) throw (InvalidStateException, SymmetricCipherException);
	
	/**
	 * Concatena os dados passados como parâmetro, finaliza a operação e retorna o resultado da mesma.
	 * @param os dados a serem concatenados no formato binário.
	 * @return o resultado da operação aplicada aos dados submetidos ao cifrador.
	 * @throw InvalidStateException não esteja no esteja no estado apropriado (State::UPDATE).
	 * @throw SymmetricCipherException caso ocorra algum erro na finalização do procedimento.
	 **/
	ByteArray doFinal(ByteArray &data) throw (InvalidStateException, SymmetricCipherException);
	
	/**
	 * Retorna o modo de operação do cifrador.
	 * @return o modo de operação do cifrador.
	 * @throw InvalidStateException não esteja no esteja no estado apropriado (State::INIT).
	 **/
	SymmetricCipher::OperationMode getOperationMode() throw (InvalidStateException);
	
	/**
	 * Retorna o tipo de operação do cifrador.
	 * @return o tipo de operação para que o cifrador foi inicializado.
	 * @throw InvalidStateException não esteja no esteja no estado apropriado (State::INIT).
	 **/
	SymmetricCipher::Operation getOperation() throw (InvalidStateException);
	
	
	/**
	 * Retorna o nome do modo de operação passado como parâmetro.
	 * @return o nome do modo de operação passado como parâmetro.
	 **/
	static std::string getOperationModeName(SymmetricCipher::OperationMode mode);
	
	/**
	 * Retorna a estrutura OpenSSL que representa um cifrador.
	 * @param algorithm o algoritmo que o cifrador deverá utilizar.
	 * @param mode o modo de operação do algoritmo.
	 * @throw SymmetricCipherException caso ocorra algum erro na criação da estrutura.
	 **/	
	static const EVP_CIPHER* getCipher(SymmetricKey::Algorithm algorithm, SymmetricCipher::OperationMode mode)
			throw (SymmetricCipherException);
	
	/**
	 * Método utilizado para carregar os algoritmos disponíveis na biblioteca OpenSSL.
	 **/
	static void loadSymmetricCiphersAlgorithms();

private:

	/**
	 * @enum State
	 **/
	/**
	 *  Possíveis estados do builder. 
	 **/
	enum State
	{
		NO_INIT, /*!< estado inicial, quando o builder ainda não foi inicializado. */
		INIT, /*!< estado em que o builder foi inicializado, mas ainda não recebeu dados. */
		UPDATE /*!< estado em que o builder já possui condições para finalizar a operação */
	};
	
	
	/**
	 * Controla o estado do builder.
	 **/
	SymmetricCipher::State state;

	/**
	 * Modo de operação do cifrador.
	 **/
	SymmetricCipher::OperationMode mode;

	/**
	 * Estrutura interna OpenSSL.
	 **/
	EVP_CIPHER_CTX* ctx;

	/**
	 * Buffer de dados a serem processados. 
	 **/
	ByteArray *buffer;
	
	/**
	 * TODO perguntar para o túlio
	 **/
	std::pair<ByteArray*, ByteArray*> keyToKeyIv(ByteArray &key, const EVP_CIPHER *cipher);

};

#endif /*SYMMETRICCIPHER_H_*/
