#ifndef HMAC_H_
#define HMAC_H_

#include <openssl/hmac.h>
#include <libcryptosec/ByteArray.h>
#include <libcryptosec/MessageDigest.h>
#include <libcryptosec/Engine.h>
#include <libcryptosec/exception/InvalidStateException.h>
#include <libcryptosec/exception/HmacException.h>
#include <vector>

/**
 * @defgroup Util Classes Relacionadas Utilitárias de Criptografia
 */

/**
 * @brief Implementa as funcionalidades de um Hmac.
 * Antes de utilizar o Hmac, o algoritmo de resumo (hash) deve ser carregado.
 * @ingroup Util
 */
class Hmac {

public:
	/**
	 * Construtor padrão.
	 * Controi um objeto Hmac não inicializado.
	 */
	Hmac();

	/**
	 * Construtor.
	 * Constroi um objeto Hmac.
	 * @param key chave secreta.
	 * @param algorithm algoritmo de resumo.
	 * @throw HmacException caso ocorra erro ao inicializar a estrutura do hmac do OpenSSL.
	 */
	Hmac(std::string key, MessageDigest::Algorithm algorithm) throw (HmacException);

	/**
	 * Construtor.
	 * Constroi um objeto Hmac.
	 * @param key chave secreta.
	 * @param algorithm algoritmo de resumo.
	 * @throw HmacException caso ocorra erro ao inicializar a estrutura do hmac do OpenSSL.
	 */
	Hmac(ByteArray key, MessageDigest::Algorithm algorithm) throw (HmacException);

	/**
	 * Construtor.
	 * Constroi um objeto Hmac.
	 * @param key chave secreta.
	 * @param algorithm algoritmo de resumo.
	 * @param engine objeto Engine.
	 * @throw HmacException caso ocorra erro ao inicializar a estrutura do hmac do OpenSSL.
	 */
	Hmac(std::string key, MessageDigest::Algorithm algorithm, Engine &engine) throw (HmacException);

	/**
	 * Construtor.
	 * Constroi um objeto Hmac.
	 * @param key chave secreta.
	 * @param algorithm algoritmo de resumo.
	 * @param engine objeto Engine.
	 * @throw HmacException caso ocorra erro ao inicializar a estrutura do hmac do OpenSSL.
	 */
	Hmac(ByteArray key, MessageDigest::Algorithm algorithm, Engine &engine) throw (HmacException);

	/**
	 * Destrutor.
	 */
	virtual ~Hmac();

	/**
	 * Inicializar a estrutura do hmac.
	 * @param key chave secreta.
	 * @param algorithm algoritmo de resumo.
	 * @throw HmacException caso ocorra erro ao inicializar a estrutura do hmac do OpenSSL.
	 */
	void init(ByteArray &key, MessageDigest::Algorithm algorithm) throw (HmacException);

	/**
	 * Inicializar a estrutura do hmac.
	 * @param key chave secreta.
	 * @param algorithm algoritmo de resumo.
	 * @param engine objeto Engine.
	 * @throw HmacException caso ocorra erro ao inicializar a estrutura do hmac do OpenSSL.
	 */
	void init(ByteArray &key, MessageDigest::Algorithm algorithm, Engine &engine) throw (HmacException);

	/**
	 * Inicializar a estrutura do hmac.
	 * @param key chave secreta.
	 * @param algorithm algoritmo de resumo.
	 * @throw HmacException caso ocorra erro ao inicializar a estrutura do hmac do OpenSSL.
	 */
	void init(std::string key, MessageDigest::Algorithm algorithm) throw (HmacException);

	/**
	 * Inicializar a estrutura do hmac.
	 * @param key chave secreta.
	 * @param algorithm algoritmo de resumo.
	 * @param engine objeto Engine.
	 * @throw HmacException caso ocorra erro ao inicializar a estrutura do hmac do OpenSSL.
	 */
	void init(std::string key, MessageDigest::Algorithm algorithm, Engine &engine) throw (HmacException);

	/**
	 * Atualizar/concatenar o conteúdo de entrada do hmac.
	 * @param data conteúdo para geração do hmac.
	 * @throw HmacException caso ocorra erro ao atualizar o contexto do hmac do OpenSSL.
	 * @throw InvalidStateException caso o objeto Hmac não tenha sido inicializado corretamente.
	 */
	void update(ByteArray &data) throw (HmacException, InvalidStateException);

	/**
	 * Atualizar/concatenar o conteúdo de entrada do hmac.
	 * @param data conteúdo para geração do hmac.
	 * @throw HmacException caso ocorra erro ao atualizar o contexto do hmac do OpenSSL.
	 * @throw InvalidStateException caso o objeto Hmac não tenha sido inicializado corretamente.
	 */
	void update(std::string data) throw (HmacException, InvalidStateException);

	/**
	 * Atualizar/concatenar o conteúdo de entrada do hmac.
	 * @param data conteúdo para geração do hmac usando vector<string>.
	 * @throw HmacException caso ocorra erro ao atualizar o contexto do hmac do OpenSSL.
	 * @throw InvalidStateException caso o objeto Hmac não tenha sido inicializado corretamente.
	 */
	void update(std::vector<std::string> &data) throw (HmacException, InvalidStateException);

	/**
	 * Atualizar/concatenar o conteúdo de entrada do hmac.
	 * @param data conteúdo para geração do hmac usando vector<ByteArray>.
	 * @throw HmacException caso ocorra erro ao atualizar o contexto do hmac do OpenSSL.
	 * @throw InvalidStateException caso o objeto Hmac não tenha sido inicializado corretamente.
	 */
	void update(std::vector<ByteArray> &data) throw (HmacException, InvalidStateException);

	/**
	 * Gerar o hmac
	 * @param data conteúdo para geração do hmac.
	 * @return bytes que representam o hmac.
	 * @throw HmacException caso ocorra erro ao finalizar o contexto do hmac do OpenSSL.
	 * @throw InvalidStateException caso o objeto Hmac não tenha sido inicializado corretamente ou caso não tenha sido passado o conteúdo para calculo do hmac.
	 */
	ByteArray doFinal(ByteArray &data) throw (HmacException, InvalidStateException);

	/**
	 * Gerar o hmac
	 * @param data conteúdo para geração do hmac.
	 * @return bytes que representam o hmac.
	 * @throw HmacException caso ocorra erro ao finalizar o contexto do hmac do OpenSSL.
	 * @throw InvalidStateException caso o objeto Hmac não tenha sido inicializado corretamente ou caso não tenha sido passado o conteúdo para calculo do hmac.
	 */
	ByteArray doFinal(std::string data) throw (HmacException, InvalidStateException);

	/**
	 * Gerar o hmac
	 * @return bytes que representam o hmac.
	 * @throw HmacException caso ocorra erro ao finalizar o contexto do hmac do OpenSSL.
	 * @throw InvalidStateException caso o objeto Hmac não tenha sido inicializado corretamente ou caso não tenha sido passado o conteúdo para calculo do hmac.
	 */
	ByteArray doFinal() throw (HmacException, InvalidStateException);

protected:
	/**
	 * @enum Hmac::State
	 * Define o estado do objeto Hmac.
	 * @var NO_INIT estado inicial, enquanto a estrutura do Hmac ainda não foi inicializada.
	 * @var INIT estado intermediário, após a estrutura do Hmac ser inicializada, porém o conteúdo para cálculo do Hmac ainda não foi passado.
	 * @var UPDATE estado final, todas os requisitos cumpridos para se calcular o Hmac.
	 * @see Hmac::init(std::string key, Hmac::Algorithm algorithm).
	 * @see Hmac::update(ByteArray &data).
	 * @see Hmac::doFinal().
	 */
	enum State {
		NO_INIT,
		INIT,
		UPDATE,
	};

	/**
	 * Algoritmo selecionado.
	 */
	MessageDigest::Algorithm algorithm;

	/**
	 * Estado das estruturas de resumo.
	 */
	State state;

	/**
	 * Estrutura OpenSSL que representa o Hmac.
	 */
	HMAC_CTX* ctx;

};

#endif
