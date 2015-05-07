#ifndef ENGINE_H_
#define ENGINE_H_

#include <openssl/engine.h>
#include <vector>
#include <string>

#include <libcryptosec/exception/EngineException.h>

/**
 * @defgroup Engine Classes Relacionadas à Engine
 */
 
 /**
 * @brief Define as características funcionais de uma engine do OpenSSL.
 * @see DynamicEngine.
 * @ingroup Engine
 */
class Engine
{
public:

	/**
	 * @enum Engine::Algorithm
	 * Possíveis algoritmos suportados pela engine. 
	 */
	enum Algorithm
	{
		RSA,
		DSA,
//		DH,
		RAND,
//		ECDH,
		ECDSA,
		CIPHERS,
		DIGESTS,
//		STORE,
		ALL,
		NONE
	};
	
	/**
	 * @enum Engine::CmdType
	 * Possíveis comandos suportados pela engine.
	 */
	enum CmdType
	{
		STRING,
		LONG,
		NO_PARAMETERS,
		INTERNAL_USE
	};
	
	/**
	 * Construtor.
	 * Cria um objeto Engine.
	 * @param engine estrutura ENGINE
	 * */
	Engine(ENGINE *engine);
	
	
	/**
	 * Construtor de cópia.
	 * Cria um objeto Engine a partir de outro do mesmo tipo.
	 * @param engine objeto Engine.
	 */
	Engine(const Engine &engine);
	
	
	/**
	 * Destrutor.
	 * Destroi objeto Engine.
	 */
	virtual ~Engine();
	
	/**
	 * Retorna o identificador do objeto Engine.
	 * @return Identificador do objeto Engine.
	 * @throw EngineException caso não haja uma estrutura ENGINE associada ou iniciada de maneira correta.
	 */
	std::string getId() throw (EngineException);
	
	/**
	 * Verifica se a engine pode ser inicializa com sucesso.
	 * @return Verdadeiro para sucesso e falso para fracasso.
	 */
	bool testInit();
	
	/**
	 * Retorna os algoritmos suportados pela engine.
	 * @return Vetor de algoritmos.
	 */
	std::vector<Engine::Algorithm> getCapabilities();
	
	/**
	 * Executa comando na Engine.
	 * @param Comando.
	 * @throw EngineException no caso de falha ao adicionar comando na Engine. 
	 */
	void setCommand(std::string key) throw (EngineException);
	
	/**
	 * Executa comando na Engine.
	 * @param Comando.
	 * @param Valor do comando.
	 * @throw EngineException no caso de falha ao adicionar comando na Engine.
	 */	
	void setCommand(std::string key, std::string value) throw (EngineException);
	
	/**
	 * Executa comando na Engine.
	 * @param Comando.
	 * @param Valor do comando.
	 * @throw EngineException no caso de falha ao executar comando na Engine.
	 */
	void setCommand(std::string key, long value) throw (EngineException);
	
	/**
	 * Retorna os comandos disponíveis pela engine.
	 * @return vetor de pares tipo de comando e de seu respectivo nome.
	 */
	std::vector<std::pair<Engine::CmdType, std::string> > getAvaliableCmds();
	
	/**
	 * Adiciona engine na lista de engines do Openssl. Essa engine será carregado por getEngineById().
	 * Este método é implementado pelas subclasses de Engine.
	 * @throw EngineException se ocorrer algum erro durante a adição da engine.
	 * @see DynamicEngine.
	 */
	virtual void addToEnginesList() throw (EngineException);

	/**
	 * Remove engine da lista de engines do OpenSSL. Essa engine não será carregada por getEngineById().
	 * Este método é implementado pelas subclasses de Engine. 
	 * @throw EngineException se ocorrer algum erro durante a remoção da engine.
	 * @see DynamicEngine.
	 */
	virtual void removeFromEnginesList() throw (EngineException);
	
	/**
	 * Retorna atributo ENGINE do objeto Engine.
	 * @return objeto ENGINE.
	 */
	ENGINE* getEngine() const;
	
	/**
	 * Retorna string que identifica um algoritmo da engine.
	 * @return string referente a um dado algoritmo da engine.
	 */
	static std::string algorithm2Name(Engine::Algorithm algorithm);

protected:

	/**
	 * Estrutura ENGINE do OpenSSL que representa uma engine.
	 */
	ENGINE *engine;
};

#endif /*ENGINE_H_*/
