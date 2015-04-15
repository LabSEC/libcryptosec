#ifndef BYTEARRAY_H_
#define BYTEARRAY_H_

#include <string>
#include <stdexcept>
#include <iostream>
#include <sstream>
#include <vector>
#include <string.h>
#include <stdio.h>

using namespace std;

/**
 * @ingroup Util
 */

/**
 * @brief Classe usada para transportar dados binários pelo sistema. Pode ser usada para conversão de 
 * texto em array de bytes e vice-versa.
 * Usar esta classe ao invés do QByteArray por causa do uso de "unsigned char", e pela possibilidade
 * de fazer "cópias profundas" dos dados.
 */
class ByteArray
{
public:
	/**
	 * Default constructor.
	 */
    ByteArray();

	/**
	 * ByteArray com tamanho definido.
	 * 
	 * @param length Tamanho do novo ByteArray.
	 */
	ByteArray(unsigned int length);

	/**
	 * ByteArray a partir do buffer desejado, copiando os dados.
	 * 
	 * @param data Buffer de origem dos bytes.
	 * @param length Tamanho do buffer.
	 */
    ByteArray(const unsigned char* data, unsigned int length);

	/**
	 * ByteArray a partir de ostringstream copiando os dados.
	 * 
	 * @param buffer ostream com os dados para colocar no ByteArray
	 */
    ByteArray(std::ostringstream *buffer);

	/**
	 * ByteArray a partir de dados legíveis.
	 * 
	 * @param data dados que serão colocados no objeto
	 */
    ByteArray(std::string data);

	ByteArray(char *data);
	/**
	 * ByteArray com tamanho definido.
	 * 
	 * @param length Tamanho do novo ByteArray.
	 */
    ByteArray(int length);

	/**
	 * ByteArray a partir de outro ByteArray (que será copiado).
	 * 
	 * @param value ByteArray de origem.
	 */
    ByteArray(const ByteArray& value);

	/**
	 * Deafult destructor.
	 */
	virtual ~ByteArray();
    
    /**
     * Ler o byte da posição desejada.
     * 
     * @param pos Posição desejada.
     */
    char at(int pos) const throw (out_of_range);
    
    /**
     * Fazer uma cópia profunda ao invés de copiar a referência
     * 
     * @param value ByteArray a ser copiado.
     */
    ByteArray& operator =(const ByteArray& value);
    
    /**
     * Permitir comparação booleana de ByteArray's
     * 
     * @param left Primeiro ByteArray da comparação.
     * @param right Segundo ByteArray da comparação.
     */
    friend bool operator ==(const ByteArray& left, const ByteArray& right);
    
    /**
     * Permitir diferença booleana de ByteArray's
     * 
     * @param left Primeiro ByteArray da comparação.
     * @param right Segundo ByteArray da comparação.
     */
    friend bool operator !=(const ByteArray& left, const ByteArray& right);

    /**
     * Ler o byte da posição desejada.
     * 
     * @param pos Posição desejada.
     */
    unsigned char& operator [](int pos) throw (out_of_range);

    /**
     * Fazer ou-exclusivo entre dois ByteArray's.
     * 
     * @param left Primeiro ByteArray da operação.
     * @param right Segundo ByteArray da operação.
     */
    friend ByteArray& operator xor(const ByteArray& left, const ByteArray& right);

    /**
     * Copy bytes from desired memory location.
     * 
     * @param data Desired memory location.
     * @param length Amount to copy.
     */
    void copyFrom(unsigned char* data, unsigned int length);

    /**
     * Copy bytes from desired ByteArray, considering an offset.
     * 
     * @param offset Offset to consider for copying.
     * @param length Amount to copy.
     * @param data Desired ByteArray.
     * @param offset2 Offset to consider for copy begin in data.
     */
    void copyFrom(int offset, int length, ByteArray& data, int offset2);

    /**
     * Returns an istringstream representing current byte array.
     */
	std::istringstream * toStream();

    /**
     * Set the content of ByteArray to be an already allocated memory space.
     * 
     * @param data Desired memory location.
     * @param length Length of allocated memory.
     */
    void setDataPointer(unsigned char* data, unsigned int length);

    /**
     * Returns the memory location of byte array content.
     */
    unsigned char* getDataPointer();

    /**
     * Returns the memory location of byte array content.
     */
//    char* data();

    /**
     * Returns the byte array content encoded as base 64 characters.
     */
//    std::string toBase64();
    
    /**
     * Returns the size of current byte array.
     */
    unsigned int size() const;
    
    /**
     * Consider that current byte array is a char array, and retuirns it as a QString.
     */
    virtual std::string toString();
    
    /**
     * Converts the content of this bytearray to hexadecimal value.
     */    
    virtual std::string toHex();
    
    /**
     * Converts the content of this bytearray to hexadecimal value separated using the char informed as argument.
     */    
    virtual std::string toHex(char separator);
    
    /**
     * Computes multiple xor of vector elements.
     */
    static ByteArray xOr(vector<ByteArray> &array);

private:
    unsigned char* m_data;
    unsigned int length;
};

#endif /*BYTEARRAY_H_*/
