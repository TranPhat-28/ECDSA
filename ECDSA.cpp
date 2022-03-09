

#include <assert.h>

#include <iostream>
//xuất ra màn hình wstr,int,....
using std::cerr;
using std::cout;
using std::endl;
using std::wcin;
using std::wcout;

#include <string>
using std::string;
using std::wstring;

#include "include/cryptopp/osrng.h"
// using CryptoPP::AutoSeededX917RNG;
using CryptoPP::AutoSeededRandomPool;


#include <string>
#include <string.h>
using std::string;
//converting from UTF8 to UTF-32
using std::wstring;
#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;
#include <cstdlib>
using std::exit;
using convert_t=std::codecvt_utf8<wchar_t>;
std:: wstring_convert<convert_t> strconverter;

#include "include/cryptopp/aes.h"
using CryptoPP::AES;

#include "include/cryptopp/integer.h"
using CryptoPP::Integer;

#include "include/cryptopp/sha3.h"
using CryptoPP::SHA3_512;

#include "include/cryptopp/filters.h"
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::ArraySink;
using CryptoPP::SignerFilter;
using CryptoPP::SignatureVerificationFilter;
using CryptoPP::byte;
#include "include/cryptopp/files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include "include/cryptopp/eccrypto.h"
using CryptoPP::ECDSA;
using CryptoPP::ECP;
using CryptoPP::DL_GroupParameters_EC;


#include "include/cryptopp/oids.h"
using CryptoPP::OID;

// _setmode()
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif

string mess;
string sn;
bool GeneratePrivateKey( const OID& oid, ECDSA<ECP, SHA3_512>::PrivateKey& key );
bool GeneratePublicKey( const ECDSA<ECP, SHA3_512>::PrivateKey& privateKey, ECDSA<ECP, SHA3_512>::PublicKey& publicKey );

void SavePrivateKey( const string& filename, const ECDSA<ECP, SHA3_512>::PrivateKey& key );
void SavePublicKey( const string& filename, const ECDSA<ECP, SHA3_512>::PublicKey& key );
void LoadPrivateKey( const string& filename, ECDSA<ECP, SHA3_512>::PrivateKey& key );
void LoadPublicKey( const string& filename, ECDSA<ECP, SHA3_512>::PublicKey& key );

void PrintDomainParameters( const ECDSA<ECP, SHA3_512>::PrivateKey& key );
void PrintDomainParameters( const ECDSA<ECP, SHA3_512>::PublicKey& key );
void PrintDomainParameters( const DL_GroupParameters_EC<ECP>& params );
void PrintPrivateKey( const ECDSA<ECP, SHA3_512>::PrivateKey& key );
void PrintPublicKey( const ECDSA<ECP, SHA3_512>::PublicKey& key );
int SelectOption();
void SaveMessage(string Message);
void SaveSignedMessage(string SignedMessage);

string wstring_to_string(const wstring &str);
wstring string_to_wstring(const string &str);
void CreatSignature( const ECDSA<ECP, SHA3_512>::PrivateKey& key, const string& message, string& signature );
bool SignMessage( const ECDSA<ECP, SHA3_512>::PrivateKey& key, const string& message, string& signature );
bool VerifyMessage( const ECDSA<ECP, SHA3_512>::PublicKey& key, const string& message, const string& signature);

//////////////////////////////////////////
// In 2010, use SHA-256 and P-256 curve
//////////////////////////////////////////

int main(int argc, char* argv[])
{
    try
    {
        //sử dụng wcout/wcin
    #ifdef __linux__
            setlocale(LC_ALL, "");
    #elif _WIN32
            _setmode(_fileno(stdin), _O_U16TEXT);
            _setmode(_fileno(stdout), _O_U16TEXT);
    #else
    #endif

    // Khai báo biến
    bool result = false;   
    
    // Khai báo Private và Public keys
    ECDSA<ECP, SHA3_512>::PrivateKey privateKey;
    ECDSA<ECP, SHA3_512>::PublicKey publicKey;
    
    // Tạo Private key
    result = GeneratePrivateKey( CryptoPP::ASN1::secp256r1(), privateKey );
    assert( true == result );
    // Nếu lỗi sẽ return -1
    if( !result ) 
    { 
        wcout << "Error generating Private key!";
        return -1; 
    }
    // Tạo Public Key
    result = GeneratePublicKey( privateKey, publicKey );
    assert( true == result );
    // Nếu lỗi sẽ return -1
    if( !result ) 
    { 
        wcout << "Error generating Public key!";
        return -2; 
    }
    
    /////////////////////////////////////////////
    // Print Domain Parameters and Keys   
    //PrintDomainParameters( publicKey );
    //PrintPrivateKey( privateKey );
    //PrintPublicKey( publicKey );
    
    /////////////////////////////////////////////
    // Lần đầu chạy code thì phải lưu key ra file
    // Save key in PKCS#9 and X.509 format    
    //SavePrivateKey( "ec.private.key", privateKey );
    //SavePublicKey( "ec.public.key", publicKey );
    
    /////////////////////////////////////////////
    // Load key in PKCS#9 and X.509 format     
    LoadPrivateKey( "ec.private.key", privateKey );
    LoadPublicKey( "ec.public.key", publicKey );

    /////////////////////////////////////////////
    // Print Domain Parameters and Keys    
    // PrintDomainParameters( publicKey );
    // PrintPrivateKey( privateKey );
    // PrintPublicKey( publicKey );

    std::fstream file; 
    string message;
    string signature;
    
    // Đọc dữ liệu từ file
    file.open("Message.txt", std::ios::in);
    fflush(stdin);;
    getline(file, message);  
    wcout << string_to_wstring(message) << endl;
    
    /*
    //Đọc dữ liệu từ file lưu vào biến signature
    f.open("SignedMessage.txt",std::ios::in);
    fflush(stdin);
    getline(f,signature);
    wcout << "signature: "<<string_to_wstring(signature)<<endl;
    */

    
    // Người dùng input lựa chọn
    int input;
    wcout << "1. Sign Message" << endl << "2. Verify Message" << endl;
    wcin >> input;

        switch (input)
        {
        case 1:
            // Kí văn bản
            result = SignMessage( privateKey, message, signature );
            assert( true == result );
            // Kí thành công
            if (result == true)
            {
                wcout << "Signed successfully!" <<endl;
            }
            // Kí thất bại
            else
            {
                wcout << "Signed failed!" <<endl;
            }
            break;
        case 2:
            // Kiểm tra văn bản
            CreatSignature( privateKey, message, signature );
            result = VerifyMessage( publicKey,message,signature );
            assert( true == result );
            // Văn bản được xác nhận là chính xác
            if (result == true)
            {
                wcout << "Verification successfully!" <<endl;
            }
            // Văn bản không được xác nhận
            else
            {
                wcout << "Verification failed!" <<endl;
            }
            break;
        default:
            break;
        }
    }
    catch(CryptoPP::Exception &e)
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
    }
    return 0;
}
// Hàm tạo Private key
bool GeneratePrivateKey( const OID& oid, ECDSA<ECP, SHA3_512>::PrivateKey& key )
{
    AutoSeededRandomPool prng;

    key.Initialize( prng, oid );
    assert( key.Validate( prng, 3 ) );
     
    return key.Validate( prng, 3 );
}
// Hàm tạo Public key
bool GeneratePublicKey( const ECDSA<ECP, SHA3_512>::PrivateKey& privateKey, ECDSA<ECP, SHA3_512>::PublicKey& publicKey )
{
    AutoSeededRandomPool prng;

    // Sanity check
    assert( privateKey.Validate( prng, 3 ) );

    privateKey.MakePublicKey(publicKey);
    assert( publicKey.Validate( prng, 3 ) );

    return publicKey.Validate( prng, 3 );
}

void PrintDomainParameters( const ECDSA<ECP, SHA3_512>::PrivateKey& key )
{
    PrintDomainParameters( key.GetGroupParameters() );
}

void PrintDomainParameters( const ECDSA<ECP, SHA3_512>::PublicKey& key )
{
    PrintDomainParameters( key.GetGroupParameters() );
}
// Hàm in các thông số Curve
void PrintDomainParameters( const DL_GroupParameters_EC<ECP>& params )
{
    cout << endl;
 
    cout << "Modulus:" << endl;
    cout << " " << params.GetCurve().GetField().GetModulus() << endl;
    
    cout << "Coefficient A:" << endl;
    cout << " " << params.GetCurve().GetA() << endl;
    
    cout << "Coefficient B:" << endl;
    cout << " " << params.GetCurve().GetB() << endl;
    
    cout << "Base Point:" << endl;
    cout << " X: " << params.GetSubgroupGenerator().x << endl; 
    cout << " Y: " << params.GetSubgroupGenerator().y << endl;
    
    cout << "Subgroup Order:" << endl;
    cout << " " << params.GetSubgroupOrder() << endl;
    
    cout << "Cofactor:" << endl;
    cout << " " << params.GetCofactor() << endl;    
}
// Hàm in Private key
void PrintPrivateKey( const ECDSA<ECP, SHA3_512>::PrivateKey& key )
{   
    cout << endl;
    cout << "Private Exponent:" << endl;
    cout << " " << key.GetPrivateExponent() << endl; 
}
// Hàm in Public key
void PrintPublicKey( const ECDSA<ECP, SHA3_512>::PublicKey& key )
{   
    cout << endl;
    cout << "Public Element:" << endl;
    cout << " X: " << key.GetPublicElement().x << endl; 
    cout << " Y: " << key.GetPublicElement().y << endl;
}
// Hàm lưu Private key ra file
void SavePrivateKey( const string& filename, const ECDSA<ECP, SHA3_512>::PrivateKey& key )
{
    key.Save( FileSink( filename.c_str(), true /*binary*/ ).Ref() );
}
// Hàm lưu Public key ra file
void SavePublicKey( const string& filename, const ECDSA<ECP, SHA3_512>::PublicKey& key )
{   
    key.Save( FileSink( filename.c_str(), true /*binary*/ ).Ref() );
}
// Hàm load Private key từ file
void LoadPrivateKey( const string& filename, ECDSA<ECP, SHA3_512>::PrivateKey& key )
{   
    key.Load( FileSource( filename.c_str(), true /*pump all*/ ).Ref() );
}
// Hàm load Public key từ file
void LoadPublicKey( const string& filename, ECDSA<ECP, SHA3_512>::PublicKey& key )
{
    key.Load( FileSource( filename.c_str(), true /*pump all*/ ).Ref() );
}

//Lưu văn bản ra file
void SaveMessage(string Message)
{
    std:: fstream file;
    file.open("Message.txt",std::ios_base::out);
    file << Message;
    file.close();
}
//Lưu văn bản đã được kí ra file
void SaveSignedMessage(string SignedMessage)
{
    std:: fstream file;
    file.open("SignedMessage.txt",std::ios_base::out);
    file << SignedMessage;
    file.close();
}
//convert string to wstring
wstring string_to_wstring(const std::string &str)
{
    return strconverter.from_bytes(str);
}
//convert wstring to string
string wstring_to_string(const std::wstring &str)
{
    return strconverter.to_bytes(str);
}

bool SignMessage( const ECDSA<ECP, SHA3_512>::PrivateKey& key, const string& message, string& signature )
{
    // Biến đo thời gian
    int startTime = 0, stopTime = 0;
    double execTime = 0;
    AutoSeededRandomPool prng;

    signature.erase();    
    try
    {
        // Chạy 1000 vòng để tính trung bình
        for (int j = 1; j <= 1000; j++)
        {
            startTime = clock();
            StringSource( message, true,
                new SignerFilter( prng,
                    ECDSA<ECP,SHA3_512>::Signer(key),
                    new StringSink( signature )
                ) // SignerFilter
            ); // StringSource
            stopTime = clock();
            execTime = execTime + (stopTime - startTime) / double(CLOCKS_PER_SEC) * 1000;
        }
        wcout << "Execution time: "<< execTime/1000 << " ms" << endl;
    }
    //Catch lỗi
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    
    //Lưu signature
    //SaveSignedMessage(mess);
    return !signature.empty();
}
//Tạo chữ kí dùng cho bước xác nhận
void CreatSignature( const ECDSA<ECP, SHA3_512>::PrivateKey& key, const string& message, string& signature )
{
    //Khai báo biến
    AutoSeededRandomPool prng;
    //Xóa dữ liệu của signature
    signature.erase();    

    //Tạo chữ kí
    StringSource( message, true,
        new SignerFilter( prng,
            ECDSA<ECP,SHA3_512>::Signer(key),
            new StringSink( signature )
        ) // SignerFilter
    ); // StringSource
}
//Xác nhận chữ kí
bool VerifyMessage( const ECDSA<ECP, SHA3_512>::PublicKey& key, const string& message , const string& signature)
{
    // Biến đo thời gian
    int startTime = 0, stopTime = 0;
    double execTime = 0;
    bool result = false;
    try
    {
        // Chạy 1000 vòng để tính thời gian trung bình
        for (int j = 1; j <= 1000; j++)
        {
            startTime = clock();

            StringSource( signature+message, true,
                new SignatureVerificationFilter(
                    ECDSA<ECP,SHA3_512>::Verifier(key),
                    new ArraySink( (byte*)&result, sizeof(result) )
                ) // SignatureVerificationFilter
            );
            stopTime = clock();
            execTime = execTime + (stopTime - startTime) / double(CLOCKS_PER_SEC) * 1000;
            
        }
        wcout << "Execution time: " << execTime/1000 << " ms" << endl;
    }
    //Catch lỗi
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    return result;
}
