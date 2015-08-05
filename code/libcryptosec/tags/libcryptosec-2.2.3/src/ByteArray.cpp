#include <libcryptosec/ByteArray.h>

ByteArray::ByteArray()
{
    this->m_data = NULL;
    this->length = 0;
}

ByteArray::ByteArray(unsigned int length)
{
    this->length = length;
    this->m_data = new unsigned char[length + 1];
    
    for(unsigned int i = 0; i <= length; i++)
    {
        this->m_data[i] = '\0';   
    }
}

ByteArray::ByteArray(const unsigned char* data, unsigned int length)
{
    this->length = length;
    this->m_data = new unsigned char[length + 1];
    
    memcpy(this->m_data, data, length);
    
    this->m_data[length] = '\0';
}

ByteArray::ByteArray(std::ostringstream *buffer)
{
	std::string data = buffer->str();
	this->length = data.size();
    this->m_data = new unsigned char[length + 1];
    memcpy(this->m_data, (const unsigned char *)data.c_str(), length);
    this->m_data[length] = '\0';
}

ByteArray::ByteArray(std::string data)
{
	this->length = data.size();
    this->m_data = new unsigned char[this->length + 1]; 
    memcpy(this->m_data, data.c_str(), length);
    this->m_data[this->length] = '\0';
}

ByteArray::ByteArray(char *data)
{
	this->length = strlen(data);
    this->m_data = new unsigned char[this->length + 1]; 
    memcpy(this->m_data, data, length);
    this->m_data[this->length] = '\0';
}

ByteArray::ByteArray(int length)
{
    this->length = (unsigned int)length;
    this->m_data = new unsigned char[length + 1];
    
    for(unsigned int i = 0; i <= this->length; i++)
    {
        this->m_data[i] = '\0';   
    }
}

ByteArray::ByteArray(const ByteArray& value)
{
    this->length = value.length;
    this->m_data = new unsigned char[this->length + 1];
    
    memcpy(this->m_data, value.m_data, value.length);
    
    this->m_data[length] = '\0';
}

ByteArray::~ByteArray()
{
    delete[] this->m_data;
}

ByteArray& ByteArray::operator =(const ByteArray& value)
{
    if(this->m_data){ delete this->m_data; }
    
    this->length = value.length;
    this->m_data = new unsigned char[this->length + 1]; 
    
    memcpy(this->m_data, value.m_data, this->length);
    
    this->m_data[this->length] = '\0';
    
    return (*this);
}

bool operator ==(const ByteArray& left, const ByteArray& right)
{
    if(left.length != right.length)
    {
        return false;
    }
    
    int res = memcmp(left.m_data, right.m_data, left.length);
    
    return (res ? false : true);
}

bool operator !=(const ByteArray& left, const ByteArray& right)
{
    if(left.length != right.length)
    {
        return true;
    }
    
    int res = memcmp(left.m_data, right.m_data, left.length);
    
    return (res ? true : false);
}

unsigned char& ByteArray::operator [](int pos) throw (out_of_range)
{
    if(pos < 0 || pos >= (int)this->length)
    {
        throw out_of_range("");
    }
    return this->m_data[pos];
}

char ByteArray::at(int pos) const throw (out_of_range) {
    if(pos < 0 || pos >= (int)this->length)     {
        throw out_of_range("");
    }
    return this->m_data[pos];
}

void ByteArray::copyFrom(unsigned char* d, unsigned int length)
{
    if(this->m_data){ delete this->m_data; }
    
    this->length = length;
    this->m_data   = new unsigned char[this->length + 1]; 
    
    memcpy(this->m_data, d, length);
    
    this->m_data[length] = '\0';
}

void ByteArray::setDataPointer(unsigned char* d, unsigned int length)
{
    if(this->m_data){ delete this->m_data; }
    
    this->length = length;
    this->m_data = d;
}

unsigned char* ByteArray::getDataPointer()
{
    return this->m_data;
}

//char* ByteArray::data()
//{
//    return reinterpret_cast<char*>(this->m_data);
//}

unsigned int ByteArray::size() const
{
    return this->length;
}

//std::string ByteArray::toBase64()
//{	
////	BIO *b64, *buffer;
////	char* result; 
//    string temp = B64Codec::encode(this->m_data, this->length);
////	QString base64String(temp);
////	
////	buffer = BIO_new(BIO_s_mem()); 
////	b64 = BIO_new(BIO_f_base64()); 
////	BIO_push(b64, buffer);  
////	BIO_write(b64, this->m_data, this->length); 
////	BIO_flush(b64);
////	BIO_get_mem_data(buffer, &result); 
////	base64String.append(result);
////	BIO_free_all(b64);
////
//	return temp;
//}

std::string ByteArray::toString()
{
	std::string data;
	data = (char *)this->m_data;
    return data;
}

std::string ByteArray::toHex()
{
	//sets the hexadecimal lenght for twice the lenght of the bytearray
	//because each byte contains 2 hexadecimals characters	
	//go trought the bytearray m_data, coping each byte to two hex in the hex_data
	std::string data;	
    char *hex_data = new char[this->length*2 +1];
    
    int j = 0;
    for(unsigned int i = 0; i < this->length; i++)
    {    	
		sprintf(&hex_data[j], "%02X", this->m_data[i]);
		j+=2;		
    }
    hex_data[j] = '\0';
	data = hex_data;
	delete[] hex_data;
    return data;
}

std::string ByteArray::toHex(char separator)
{
	//sets the hexadecimal lenght for twice the lenght of the bytearray
	//because each byte contains 2 hexadecimals characters	
	//go trought the bytearray m_data, coping each byte to two hex in the hex_data
	std::stringstream data;	
    char* hex_data = new char[2];
    
    for(unsigned int i = 0; i < this->length; i++)
    {    	
		sprintf(&hex_data[0], "%02X", this->m_data[i]);
		data << hex_data;
		if(i < this->length-1)
			data << separator;
    }
	delete[] hex_data; 
    return data.str();
}

void ByteArray::copyFrom(int offset, int length, ByteArray& data, int offset2) 
{
    for (int top = offset + length; offset < top; offset++, offset2++) {
        data.m_data[offset2] = this->m_data[offset];
    }
}

std::istringstream* ByteArray::toStream()
{
	std::string data((const char *)this->m_data, this->length);
	std::istringstream *stream = new std::istringstream(data);
	return stream;
}

ByteArray& operator xor(const ByteArray& left, const ByteArray& right)
{
    const ByteArray* biggest;
    const ByteArray* smallest;
    if (left.size() > right.size()) {
        biggest = &left;
        smallest = &right;
    } else {
        biggest = &right;
        smallest = &left;
    }
    
    ByteArray* xored = new ByteArray(*biggest);
    for (unsigned int i = 0; i < smallest->size(); i++) {
        (*xored)[i] = (*xored)[i] xor smallest->at(i);
    }
    return *xored;
}

ByteArray ByteArray::xOr(vector<ByteArray> &array) {
    ByteArray ba(array.at(0));
    ByteArray temp;
    
    for (unsigned int i = 1; i < array.size(); i++) {
        temp = (ba xor array.at(i));
        ba = temp;
    }
    return ba;
}
