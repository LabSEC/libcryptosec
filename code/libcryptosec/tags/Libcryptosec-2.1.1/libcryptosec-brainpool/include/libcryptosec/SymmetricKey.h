#ifndef SYMMETRICKEY_H_
#define SYMMETRICKEY_H_

#include "ByteArray.h"

/**
 * Representa chaves simétricas.
 * Objetos dessa classe implementam funcionalidades de chaves simétricas
 * usadas nos diferentes tipos de algorítmos de mesmo tipo.
 * @ingroup Symmetric
 **/

class SymmetricKey
{
	
public:

	/**
	 * @enum Algorithm
	 **/
	/**
	 * Tipos de algoritmos simétricos suportados.
	 **/	 
	enum Algorithm
	{
		AES_128, /*!< para chaves AES de 128 bytes */
		AES_192, /*!< para chaves AES de 192 bytes */
		AES_256, /*!< para chaves AES de 256 bytes */
		DES, /*!< para chaves DES */
		DES_EDE, /*!< para chaves DES no modo EDE */
		DES_EDE3, /*!< para chaves DES no modo EDE3 (Triple DES) */
		RC2, /*!< para chaves RC2 */
		RC4, /*!< para chaves RC4 */
	};
	
	/**
	 * Construtor recebendo a chave no seu formato binário e o seu tipo.
	 * @param key a chave no formato binário.
	 * @param algorithm o algoritmo ao qual a chave se destina.
	 * @see SymmetricKeyGenerator para a geração de chaves simétricas.
	 **/
	SymmetricKey(ByteArray &key, SymmetricKey::Algorithm algorithm);
	
	/**
	 * Construtor de cópia.
	 * @param symmetricKey referência para a chave simétrica a ser copiada.
	 **/
	SymmetricKey(const SymmetricKey &symmetricKey);
	
	/**
	 * Destrutor padrão.
	 **/
	virtual ~SymmetricKey();
	
	/**
	 * Retorna a chave no formato binário.
	 * @return a chave na sua representação binária.
	 **/
	ByteArray getEncoded() const;
	
	/**
	 * Retorna o algoritmo da chave.
	 * @return o algoritmo ao qual a chave se destina.
	 **/
	SymmetricKey::Algorithm getAlgorithm() const;
	
	/**
	 * Retorna co tamanho da chave.
	 * @return o tamanho da chave. 
	 **/
	int getSize();
	
	/**
	 * Operador de atribuição sobrescrito.
	 * @param value a chave a ser atribuída.
	 * @return uma cópia da chave representada pela referência value.
	 **/
	SymmetricKey& operator =(const SymmetricKey& value);
	
	/**
	 * Retorna o nome do algoritmo simétrico na sua forma textual.
	 * @param algorithm o algoritmo cujo nome se deseja obter.
	 * @return o nome do algoritmo passado como parâmetro na forma de texto.
	 **/
	static std::string getAlgorithmName(SymmetricKey::Algorithm algorithm);

private:

	/**
	 * Chave no formato binário.
	 **/
	ByteArray key;
	
	/**
	 * Tipo de algoritmo a que a chave se destina.
	 **/
	SymmetricKey::Algorithm algorithm;
};

#endif /*SYMMETRICKEY_H_*/
