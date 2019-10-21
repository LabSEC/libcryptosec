#ifndef DYNAMICENGINE_H_
#define DYNAMICENGINE_H_

#include <string>
#include "Engine.h"
#include <libcryptosec/exception/EngineException.h>

/**
 * @ingroup Engine
 */

/**
 * @brief Implementa uma engine dinâmica que pode ser carregada e utilizada no OpenSSL.
 * Deve ser utilizada por desenvolvedores que desejam implementar suas próprias engines no padrão do OpenSSL.
 * @Engine.
 */
class DynamicEngine : public Engine
{
public:

	/**
	 * Construtor.
	 * @param enginePath caminho para a Engine.
	 * @throw EngineException caso a Engine esteja indisponível ou ocorra erro ao carregá-la.
	 */
	DynamicEngine(std::string &enginePath)
			throw (EngineException);

	/**
	 * Construtor.
	 * @param enginePath caminho para a Engine.
	 * @param engineId identificador da Engine.
	 * @throw EngineException caso a Engine esteja indisponível ou ocorra erro ao carregá-la.
	 */
	DynamicEngine(std::string &enginePath, std::string &engineId)
			throw (EngineException);

	/**
	 * Construtor.
	 * @param enginePath caminho para a Engine.
	 * @param engineId identificador da Engine.
	 * @param extraCommands vetor de pares de comando e seu respectivo valor.
	 * @throw EngineException caso a Engine esteja indisponível ou ocorra erro ao carregá-la.
	 */
	DynamicEngine(std::string &enginePath, std::string &engineId, std::vector<std::pair<std::string, std::string> > &extraCommands)
			throw (EngineException);

	/**
	 * Destrutor.
	 */
	virtual ~DynamicEngine();

	/**
	 * @see Engine::addToEnginesList().
	 */
	void addToEnginesList() throw (EngineException);

	/**
	 * @see Engine::removeFromEnginesList().
	 */
	void removeFromEnginesList() throw (EngineException);
	
	/**
	 * Carrega a Engine e seus algoritmos.
	 * @throw EngineException caso a Engine esteja indisponível ou ocorra erro ao carregá-la.
	 * @return True se a Engine foi carregada com sucesso, senão False
	 */
	bool load() throw (EngineException);
	
	/**
	 * Libera a Engine e seus algoritmos.
	 * @throw EngineException caso a Engine esteja indisponível.
	 * @return True se a Engine foi liberada com sucesso, senão False
	 */
	bool release() throw (EngineException);
};

#endif /*DYNAMICENGINE_H_*/
