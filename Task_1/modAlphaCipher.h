#pragma once
#include <iostream>
#include <cstring>
#include <cctype>
#include <string>
#include <locale>
#include <codecvt>
#include <vector>
#include <map>
#include <locale.h>
using namespace std;
//class locale;
class modAlphaCipher
{
private:
    //wstring_convert<codecvt_utf8<wchar_t>, wchar_t> codec;
    wstring numAlpha =L"АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"; //алфавит по порядку
    map <char, int> alphaNum; //ассоциативный массив "номер по символу"
    vector <int> key; //ключ
    vector <int> convert(const string& s); //преобразование строка-вектор
    string convert(const vector<int>& v); //преобразование вектор-строка
    string getValidKey (const string & s);
    string getValidOpenText (const string & s);
    string getValidCipherText (const string & s);
public:
    modAlphaCipher()=delete; //запретим конструктор без параметров
    modAlphaCipher(const std::string& skey); //конструктор для установки ключа
    std::string encrypt(const std::string& open_text); //зашифрование
    std::string decrypt(const std::string& cipher_text);//расшифрование
};
class cipher_error: public std::invalid_argument
{
public:
    explicit cipher_error (const std::string& what_arg):
        std::invalid_argument(what_arg) {}
    explicit cipher_error (const char* what_arg):
        std::invalid_argument(what_arg) {}
}; 
