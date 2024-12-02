#pragma once
#include <string>
#include <stdexcept>
#include <codecvt>
class AlphaCipher
{
private:
    int key;
public:
    AlphaCipher() = delete; // запрет конструктора по умолчанию
    AlphaCipher(const std::wstring& key_str);   // конструктор класса
    std::wstring encrypt(const std::wstring& text);
    std::wstring decrypt(const std::wstring& encrypted_text);
     int getValidKey(const std::wstring& key_str);
    std::wstring getValidOpenText(const std::wstring & s);
    std::wstring getValidCipherText(const std::wstring & s);
};

class cipher_error : public std::invalid_argument
{
public:
    explicit cipher_error(const std::string& what_arg)
        : std::invalid_argument(what_arg)
    {
    }

    explicit cipher_error(const char* what_arg)
        : std::invalid_argument(what_arg)
    {
    }
};
