#include <UnitTest++/UnitTest++.h>
#include "/home/stud/Desktop/3/Task_1/modAlphaCipher.h"
#include "/home/stud/Desktop/3/Task_1/modAlphaCipher.cpp"


SUITE(KeyTest)
{
    TEST(ValidKey) {
        CHECK_EQUAL("АБВАБ", modAlphaCipher("АБВ").encrypt("ААААА"));
    }
    TEST(LongKey) {
        CHECK_EQUAL("АБВГД",modAlphaCipher("АБВГДЕЁЖ").encrypt("ААААА"));
    }
    TEST(LowCaseKey) {
        CHECK_EQUAL("АБВАБ", modAlphaCipher("абв").encrypt("ААААА"));
    }
    TEST(DigitsInKey) {
        CHECK_THROW(modAlphaCipher cp("Б1"), cipher_error);
    }
    TEST(PunctuationInKey) {
        CHECK_THROW(modAlphaCipher cp("А,Б"), cipher_error);
    }
    TEST(WhitespaceInKey) {
        CHECK_THROW(modAlphaCipher cp("А Б"), cipher_error);
    }
    TEST(EmptyKey) {
        CHECK_THROW(modAlphaCipher cp(""), cipher_error);
    }
    TEST(WeakKey) {
        CHECK_THROW(modAlphaCipher cp("ААА"), cipher_error);
    }
}
struct KeyB_fixture {
    modAlphaCipher* p;
    KeyB_fixture()
    {
        p = new modAlphaCipher("Б");
    }
    ~KeyB_fixture()
    {
        delete p;
    }
};
SUITE(EncryptTest)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        CHECK_EQUAL("НБНБНЬМБСБНФ", p->encrypt("МАМАМЫЛАРАМУ"));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        CHECK_EQUAL("НБНБНЬМБСБНФ", p->encrypt("мамамылараму"));
    }
    TEST_FIXTURE(KeyB_fixture, StringWithWhitspaceAndPunct) {
        CHECK_EQUAL("НБНБНЬМБСБНФ", p->encrypt("Мама мыла раму"));
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(p->encrypt(""), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, NoAlphaString) {
        CHECK_THROW(p->encrypt("123123123"), cipher_error);
    }
    TEST(MaxShiftKey) {
        CHECK_EQUAL("ЛЯЛЯЛЪКЯПЯЛТ",modAlphaCipher("Я").encrypt("МАМАМЫЛАРАМУ"));
    }
}
SUITE(DecryptText)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        CHECK_EQUAL("МАМАМЫЛАРАМУ", p->decrypt("НБНБНЬМБСБНФ"));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        CHECK_THROW(p -> decrypt("нБНБНЬМБСБНФ"), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, WhitespaceString) {
        CHECK_THROW(p->decrypt("НБНБ НЬМБ СБНФ"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, DigitsString) {
        CHECK_THROW(p -> decrypt("123123123"), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, PunctString) {
        CHECK_THROW(p -> decrypt("НБНБ,НЬМБСБНФ"), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(p->decrypt(""), cipher_error);
    }
    TEST(MaxShiftKey) {
        CHECK_EQUAL("МАМАМЫЛАРАМУ",modAlphaCipher("Я").decrypt("ЛЯЛЯЛЪКЯПЯЛТ"));
    }
}
int main(int argc, char **argv)
{
    return UnitTest::RunAllTests();
}
