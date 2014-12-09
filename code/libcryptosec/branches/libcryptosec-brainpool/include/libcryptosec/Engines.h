#ifndef ENGINES_H_
#define ENGINES_H_

#include <string>
#include <vector>
#include <openssl/engine.h>

#include "Engine.h"

#include <libcryptosec/exception/EngineException.h>

/**
 * @ingroup Engine
 */
 
 /**
 * @brief Disponibiliza uma série de funcionalidades para manipular engines do OpenSSL. 
 * @Engine.
 */ 

class Engines
{
public:
	
	/**
	 * Retorna o nome de todas as engines disponíveis.
	 * @return vetor de nomes de engines.
	 * @throw EngineException caso não haja engines disponíveis.
	 */
	static std::vector<std::string> getEnginesList() throw (EngineException);
	
	/**
	 * Define uma engine padrão para determinado algoritmo.
	 * @param engine objeto Engine.
	 * @param algorithm algoritmo da Engine.
	 * @EngineException caso a engine passada seja inválida ou ocorra erro interno do OpenSSL.
	 * @see Engine
	 */
	static void setEngineDefault(Engine &engine, Engine::Algorithm algorithm) throw (EngineException);
	
	/**
	 * Retorna a engine padrão para determinado algoritmo.
	 * @param algorithm algoritmo para pesquisa.
	 * @return objeto Engine encontrado.
	 * @throw EngineException caso não seja encontrada a engine padrão para o algoritmo desejado.
	 */
	static Engine* getEngineDefault(Engine::Algorithm algorithm) throw (EngineException);
	
	
	/**
	 * Retorna a engine relacionada a um dado nome.
	 * @param id nome da engine.
	 * @return objeto Engine relacionado ao nome.
	 * @throw EngineException caso não seja encontrada engine relacionada ao nome passado.
	 */
	static Engine* getEngineById(std::string id) throw (EngineException);
	
	/**
	 * Carrega todas as engines estáticas do OpenSSL.
	 */
	static void loadAllStaticEngines();
	
	/**
	 * Carrega estrutura de suporte para engines dinamicas.
	 */
	static void loadDynamicEngineSupport();

private:

	/**
	 * Faz a tradução entre a representação de algoritmo da LibCryptoSec e do OpenSSL.
	 * @param flag algoritmo a ser traduzido.
	 * @returns inteiro que identifica algoritmo no OpenSSL. 
	 */
	static unsigned int getAlgorithmFlags(Engine::Algorithm flag);
};

#endif /*ENGINES_H_*/
