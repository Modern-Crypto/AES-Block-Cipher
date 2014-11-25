/*
 * Title: Project 2 (Cryptography: encrypting files before storage in the cloud).
 * Purpose: The project consists of a software implementation of a method to pre-process a file before storing it on a cloud storage server 
 *			so that the server cannot read the file content but a desired peer can.
 * Author: Pooja Patil and Mayur Kale 
 * Date: 11/23/2014
 * Version: 1.0
 */

#include "stdafx.h"
#include <fstream>
#include <iostream>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <time.h>  
#include <sstream>
#include "osrng.h"
#include "cryptlib.h"
#include "filters.h"
#include "des.h"
#include "modes.h"
#include "secblock.h"
#include "modes.h"
#include "aes.h"
#include "filters.h"
#include "hex.h"
#include "cbcmac.h"
#include "sha.h"
#include "hmac.h"
#include <iostream>
#include <string>
#include <stdexcept>
#include <queue.h>
#include <files.h>
#include "rsa.h"
#include <cryptlib.h>
#include "hex.h"

using std::cout;
using std::cerr;
using std::endl;
using std::string;
using std::exit;
using std::cin;
using CryptoPP::SHA256;
using CryptoPP::HMAC;
using CryptoPP::Exception;
using CryptoPP::HexEncoder;
using CryptoPP::CBC_Mode;
using CryptoPP::SecByteBlock;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::DES_EDE2;
using CryptoPP::AutoSeededRandomPool;
using namespace CryptoPP;
using std::cout;
using std::cerr;
using std::endl;
using std::string;
using std::runtime_error;
using CryptoPP::ByteQueue;
using CryptoPP::FileSource;
using CryptoPP::FileSink;
using CryptoPP::RSA;
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::BufferedTransformation;
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;
using CryptoPP::StringSource;


void AesBlockCipher(string temp,string keyfile, string mkeyfile);
void EncryptKey_UsingRSA(string keyfile);
void SavePrivateKey(const string& filename, const PrivateKey& key);
void SavePublicKey(const string& filename, const PublicKey& key);
void Save(const string& filename, const BufferedTransformation& bt);
void LoadPrivateKey(const string& filename, PrivateKey& key);
void LoadPublicKey(const string& filename, PublicKey& key);
void Load(const string& filename, BufferedTransformation& bt);
void SaveHexPrivateKey(const string& filename, const PrivateKey& key);
void SaveHexPublicKey(const string& filename, const PublicKey& key);
void SaveHex(const string& filename, const BufferedTransformation& bt);

// Main entry of this application.
int main(int argc, char* argv[]) 
	{
		if (argc !=4) {
			cout <<"*** Error: Missing Parameters *** \n"
				 <<"Usage: filename <key_file_path> <plain_file_path> <MacKey_file_path> \n";
			system("pause");
			return 0;
		} 
		else {
				// first file is the key and second is the plain text.
				std::ifstream key_file(argv[1],std::ios::binary);
				std::ifstream plain_file(argv[2],std::ios::binary);
				std::ifstream mkey_file(argv[3],std::ios::binary);
				string keyfile,plaintext = "",mkeyfile, temp;
				
				// Check to see if file opening succeeded
				if (!key_file.is_open() && !plain_file.is_open() && !mkey_file.is_open())
						cout<<"Could not open file\n";
				else 
					{
						// key_file.get ( key ) returns false if the end of the file
						//  is reached or an error occurs
						while (key_file && mkey_file) {
								getline(key_file,keyfile);
								getline(mkey_file,mkeyfile);
							}
						while (getline(plain_file,temp)) {
								plaintext.append(temp);
							}
					}

					 << "[3] Exit the program" << endl;
				cout << "Please select the function you would like to perform : (1/2/3) \n> ";
				cin >> selection;

				switch (selection)
				{
					case 1:   
						AesBlockCipher(plaintext,keyfile,mkeyfile);
						break;
					case 2:   
						EncryptKey_UsingRSA(keyfile);
						AesBlockCipher(plaintext,keyfile,mkeyfile);
						break;
					case 3:
						cout << "\nThank You !!\n";
					default: break;
				}  
				key_file.close();
				plain_file.close();

				cin.get(); 
				system("pause");
			 }
	return 0;				
	}




		
		cout << "Encryption begins... \n------------------------------------------------------\n" ;

		CryptoPP::AES::Encryption aesEncryption((byte *)key.c_str(), CryptoPP::AES::DEFAULT_KEYLENGTH);
		CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption , (byte *)iv.c_str() );

		CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink( ciphertext ) );
		stfEncryptor.Put( reinterpret_cast<const unsigned char*>( InputText.c_str() ), InputText.length() + 1 );
		stfEncryptor.MessageEnd();
		 std::fstream myfile;
		myfile.open ("ciphertext.txt");
	
    string encoded;
	StringSource(ciphertext, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource

	cout<< '\n' << "The cipher text has been generated.";
		
	myfile << encoded.length()<<endl;
	myfile << encoded;
	myfile.close();

	// current date/time based on current system
   time_t now = time(0);
   // convert now to string form
   char* dt = ctime(&now);
   cout << "\nThe current date and time is: " << dt << endl;

	time_t timer1;
	time(&timer1);

	std::stringstream ss;
    ss << timer1;
    std::string ts = ss.str();

	std :: ofstream timestamp ( "timestamp.txt" );  
     // Outputs to example.txt through a_file
		 
		  timestamp<<ts;

		  timestamp.close();


	
	string beforemac=ts + encoded; 
	//cout << beforemac;
	
	//*   Encryption of Mac begins:-
	    cout << "Encryption of mac begins... \n------------------------------------------------------\n\n" ;
		string macciphertext;

		CryptoPP::AES::Encryption aesEncryption1((byte *)mkey.c_str(), CryptoPP::AES::DEFAULT_KEYLENGTH);
		CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption1(aesEncryption , (byte *)iv.c_str() );

		CryptoPP::StreamTransformationFilter stfEncryptor1(cbcEncryption1, new CryptoPP::StringSink( macciphertext ) );
		stfEncryptor1.Put( reinterpret_cast<const unsigned char*>( beforemac.c_str() ), beforemac.length() + 1 );
		stfEncryptor1.MessageEnd();

		string MacEncoded;
	StringSource(macciphertext, true,
		new HexEncoder(
			new StringSink(MacEncoded)
		) // HexEncoder
	); // StringSource
	
	cout << "This is mac encoded" << '\n'  << MacEncoded << "\n\n";
	
	std :: ofstream mac ( "mac.txt" );  
     // Outputs to example.txt through a_file
		 
	mac << MacEncoded.length()<<endl;	  
	mac << MacEncoded;


		  mac.close();
				
	}