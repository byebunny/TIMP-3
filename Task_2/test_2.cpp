#include "modAlphaCipher.h"
#include <UnitTest++/UnitTest++.h>
#include <iostream>
#include <limits>
#include <locale>
#include <string>
#include <codecvt>


using namespace std;
wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> codec;
SUITE(KeyTest)
{
    TEST(ValidKey) {
        CHECK_EQUAL("EL*HLO", codec.to_bytes((AlphaCipher(L"2").encrypt(L"HELLO"))));
    }
    TEST(NegativeKey) {
        CHECK_THROW(AlphaCipher cp(L".5"),cipher_error);
    }
    TEST(WhitespaceInKey) {
        CHECK_THROW(AlphaCipher cp(L"10 0"),cipher_error);
    }
    TEST(EmptyKey) {
        CHECK_THROW(AlphaCipher cp(L""),cipher_error);
    }
    TEST(NotNumbers) {
        CHECK_THROW(AlphaCipher cp(L"Б1"),cipher_error);
    }
	TEST(TheKeyExceedsHalfTheText) {
	    AlphaCipher cp(L"3");
        CHECK_THROW(cp.encrypt(L"HELLO"),cipher_error);
    }
}

struct KeyB_fixture {
    AlphaCipher * p;
    KeyB_fixture()
    {
        p = new AlphaCipher(L"3");
    }
    ~KeyB_fixture()
    {
        delete p;
    }
};

SUITE(EncryptTest)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        CHECK_EQUAL("LWL*EOR*HLOD",
                    codec.to_bytes(p->encrypt(L"HELLOWORLD")));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        CHECK_EQUAL("LWL*EOR*HLOD",
                    codec.to_bytes(p->encrypt(L"helloworld")));
    }
    TEST_FIXTURE(KeyB_fixture, StringWithWhitspaceAndPunct) {
        CHECK_EQUAL("L*R*EOODHLWL",
                    codec.to_bytes(p->encrypt(L"HELLO WORLD!!!")));
    }
    TEST_FIXTURE(KeyB_fixture, StringWithNumbers) {
        CHECK_EQUAL("L*ODEOWLHL*R", codec.to_bytes(p->encrypt(L"HELLO 2021 WORLD")));
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(p->encrypt(L""),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, NoAlphaString) {
        CHECK_THROW(p->encrypt(L"1234+8765=9999"),cipher_error);
    }
}

SUITE(DecryptText)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        CHECK_EQUAL("LOHDWEOLRL",
                    codec.to_bytes(p->decrypt(L"HELLOWORLD")));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        CHECK_THROW(p->decrypt(L"lrloeWDHOL"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, WhitespaceString) {
        CHECK_THROW(p->decrypt(L"LRLOE WDHOL"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, DigitsString) {
        CHECK_THROW(p->decrypt(L"LRLOE2021WDHOL"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, PunctString) {
        CHECK_THROW(p->decrypt(L"LRLOE,WDHOL"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(p->decrypt(L""),cipher_error);
    }
}


int main(int argc, char **argv)
{
    locale loc("ru_RU.UTF-8");
    locale::global(loc);
    return UnitTest::RunAllTests();
}
