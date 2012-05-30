#ifndef SYMMETRICKEYGENERATOR_H_
#define SYMMETRICKEYGENERATOR_H_

#include <openssl/evp.h>

#include "Random.h"
#include "SymmetricKey.h"

#include <libcryptosec/exception/RandomException.h>

/**
 * Funciona como uma fábica de chaves simétricas.
 * Essa classe possui métodos estáticos para a criação de novas chaves simétricas a partir
 * de alguns parâmetros como tipo de algoritmo e o tamanho da chave. 
 * @ingroup Symmetric
 **/

class SymmetricKeyGenerator
{

public:

	/**
	 * Gera uma chave simétrica do maior tamanho suportado pelo algoritmo.
	 * @param alg algoritmo simétrico em que a chave será usada.
	 * @return um ponteiro para a chave simétrica gerada.
	 * @throw RandomException caso haja um problema na geração da chave.
	 **/
	static SymmetricKey* generateKey(SymmetricKey::Algorithm alg) throw (RandomException);
	
	/**
	 * Gera uma chave simétrica do tamanho estipolado pelo parâmetro size.
	 * @param alg algoritmo simétrico em que a chave será usada.
	 * @param size o tamanho da chave simétrica a ser gerada.
	 * @return um ponteiro para a chave simétrica gerada.
	 * @throw RandomException caso haja um problema na geração da chave.
	 **/
	static SymmetricKey* generateKey(SymmetricKey::Algorithm alg, int size) throw (RandomException);

};

#endif /*SYMMETRICKEYGENERATOR_H_*/
