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
#include "sha.h"
#include "filters.h"
#include "files.h"
#include "osrng.h"
#include "SecBlock.h"
#include "cryptlib.h"
#include <string>
#include <exception>
#include <iostream>
#include <assert.h>
#include <iostream>
#include <string>
#include <stdexcept>
#include <queue.h>
#include <files.h>
#include "rsa.h"
#include <cryptlib.h>
#include "hex.h"
#include <fstream> 
#include <iostream> 
  
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
using CryptoPP::HexDecoder; 
using CryptoPP::CBC_Mode; 
using CryptoPP::SecByteBlock; 
using CryptoPP::StringSink; 
using CryptoPP::StringSource; 
using CryptoPP::StreamTransformationFilter; 
using CryptoPP::DES_EDE2; 
using CryptoPP::AutoSeededRandomPool; 
using CryptoPP::SHA1;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;
using CryptoPP::FileSink;
using CryptoPP::FileSource;
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::SecByteBlock;
using CryptoPP::Exception;
using CryptoPP::DecodingResult;
using std::string;
using std::exception;
using std::cout;
using std::cerr;
using std::endl;
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


void SavePrivateKey(const string& filename, const PrivateKey& key);
void SavePublicKey(const string& filename, const PublicKey& key);
void Save(const string& filename, const BufferedTransformation& bt);
void LoadPrivateKey(const string& filename, PrivateKey& key);
void LoadPublicKey(const string& filename, PublicKey& key);
void Load(const string& filename, BufferedTransformation& bt);
void SaveHexPrivateKey(const string& filename, const PrivateKey& key);
void SaveHexPublicKey(const string& filename, const PublicKey& key);
void SaveHex(const string& filename, const BufferedTransformation& bt);

using namespace CryptoPP; 

  
void AesBlockCipher(string ciphertxt,string keyfile,string mac,string mkey) 
{ 

// From here the decryption of mac starts
char str[1000]; 
  
std::string key1 = mkey.c_str(); 
std::string iv = "0"; 

cout << "The cipher text is:-"  << '\n' ; 
cout << ciphertxt;
  
  
char *name3; 
name3 = (char*) malloc(mac.length() + 1); // don't forget to free!!!! 
strcpy(name3, mac.c_str()); 
const char* hex_str1 = name3; 
std::string result_string1 ; 
unsigned int ch1 ; 
for( ; std::sscanf( hex_str1, "%2x", &ch1 ) == 1 ; hex_str1 += 2 ) 
result_string1 += ch1 ; 

cout << endl; 
cout << endl; 
    std::string ciphertext=ciphertxt; 
    std::string decryptedmac;
	try
        { 
  
        CryptoPP::AES::Decryption aesDecryption1((byte *)mkey.c_str(), CryptoPP::AES::DEFAULT_KEYLENGTH); 
        CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption1( aesDecryption1, (byte *)iv.c_str() ); 
  
        CryptoPP::StreamTransformationFilter stfDecryptor1(cbcDecryption1, new CryptoPP::StringSink( decryptedmac ) ); 
        stfDecryptor1.Put( reinterpret_cast<const unsigned char*>( result_string1.c_str() ), result_string1.size() ); 
        stfDecryptor1.MessageEnd(); 
  
         std::cout << "Decrypted MAC is  :" <<decryptedmac << '\n'; 

	    }
	    catch(const CryptoPP::Exception& e) 
        { 
            cerr << e.what() << endl; 
            exit(1); 
		    } 
///// timer starts here




		std::string str1 = decryptedmac;
	
			str1.erase(std::remove(str1.begin(), str1.end(), '\0'), str1.end());
	
				string originaldecrpt = str1;
				string cmp= str1.substr(0,10);
				string cip=str1.substr(10,str1.length());

				//cout << '\n'  <<cmp ;
				
				//cout <<'\n' << cip ;
							
	
	time_t timer1(0);
	
	time(&timer1);
   
   
	std::stringstream ss;
    ss << timer1;
    std::string ts = ss.str();
	

	
    int current_timestamp = atoi(ts.c_str());
	int initial_timestamp = atoi(cmp.c_str());

	//cout << "The initial timestamp is :" << initial_timestamp << '\n' <<  '\n';
	//cout << "The timestamp during decryption is :" << current_timestamp << '\n' << '\n';
	
	if((current_timestamp-initial_timestamp) > 0 )
	{
    
		cout << '\n' <<"The TimeStamp is Correct" << '\n';

		if(cip.compare(ciphertext) == 0)
			{

			cout << "Mac is correct" << '\n'; 
		    
	       
			 
  
				std::string key = keyfile.c_str(); 
				//std::string iv = "aaaaaaaaaaaaaaaa";   
  
				char *name2; 
				name2 = (char*) malloc(ciphertxt.length() + 1);  
 
				strcpy(name2, ciphertxt.c_str()); 
  
				 const char* hex_str = name2; 
		
				std::string result_string ; 
				 unsigned int ch ; 
				 for( ; std::sscanf( hex_str, "%2x", &ch ) == 1 ; hex_str += 2 ) 
				result_string += ch ; 
				
				cout << endl; 
				cout << endl; 
  
      
				    
					std::string decryptedtext; 
  
			try
				{ 
  
				CryptoPP::AES::Decryption aesDecryption((byte *)key.c_str(), CryptoPP::AES::DEFAULT_KEYLENGTH); 
				CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption( aesDecryption, (byte *)iv.c_str() ); 
  
				CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink( decryptedtext ) ); 
				stfDecryptor.Put( reinterpret_cast<const unsigned char*>( result_string.c_str() ), result_string.size() ); 
				stfDecryptor.MessageEnd(); 
  
			   // cout << decryptedtext;
				//std::cout << "Decrypted Text using AES CBC mode  : "   << '\n'   <<decryptedtext << '\n'; 
    
		        std :: ofstream plaintext ( "plaintext.txt" ); 
  
		        plaintext<<decryptedtext; 

				cout <<"  The decrypted text has been printed in file:";

				 while ( decryptedtext.find ("\r") != string::npos )
                  {
    	             decryptedtext.erase ( decryptedtext.find ("\r"), 1 );
                  }

				cout << decryptedtext;
		        plaintext.close(); 
  
			    } 
			    catch(const CryptoPP::Exception& e) 
				{ 
					cerr << e.what() << endl; 
					exit(1); 
				}

			}
			else
			{
				cout << " The Mac is not correct" << '\n' ;
			}     

    }//if timestamp
	else
	{
		cout << "Incorrect timestamp: Cannot decrypt the cyphertext:" << '\n' ;

	}
}///end of function 


  
RSA::PrivateKey rsaPrivate;

void GenerateRSAPrivetKey()
{
	AutoSeededRandomPool rng,rnd,rndtest,rndtest2;
		
		rsaPrivate.GenerateRandomWithKeySize(rnd, 1024);

		//save keys in Hex format
		SaveHexPrivateKey("rsa-private.txt", rsaPrivate);
		cout << "Private key generated Succefully!";
		
}



void GenerateRSAPublicKey()
{
	    AutoSeededRandomPool rng,rnd,rndtest,rndtest2;
		string Strsecretekey;

		std::ifstream SecreatKey ("rsa-private.txt"); 
		 if (!SecreatKey.is_open() )  
           cout<<"Could not open file\n"; 


			while ( SecreatKey )
			{


			getline(SecreatKey,Strsecretekey);
			
			}

	
		RSA::PrivateKey private_key;
		RSA::PublicKey  public_key;

		StringSource file_pk(Strsecretekey,true,new HexDecoder);

		private_key.Load( file_pk );

		RSA::PublicKey rsaPublic(private_key);

		SaveHexPublicKey("rsa-public.txt", rsaPublic);

		cout << "Public key generated Succefully!";


}


string DecryptKey_usingRSA()
{
	 AutoSeededRandomPool rng,rnd,rndtest,rndtest2;
	 string Strsecretekey,RSACipher;
	 RSA::PrivateKey private_key;

	//1) Read Private Key
	std::ifstream SecreatKey ("rsa-private.txt"); 
		 if (!SecreatKey.is_open() )  
           cout<<"Could not open file\n"; 


			while ( SecreatKey )
			{

			getline(SecreatKey,Strsecretekey);
			
			}
		
	//2) Load private key
		StringSource file_pk(Strsecretekey,true,new HexDecoder);

		private_key.Load( file_pk );

		
	//3) Read the RSAcipherText file and convert it into cipher

		//C:\\Users\\swap\\Desktop\\Moedern_cryp_project\\AES_encrypt\\AES_encrypt\\AES_CryptoPP\\

			

		std::ifstream RSACipherfile ("RSAciphertext.txt"); 
		 if (!RSACipherfile.is_open() )  
           cout<<"Could not open file\n"; 


			while ( RSACipherfile )
			{

			getline(RSACipherfile,RSACipher);
			
			}

			RSACipherfile.close();

	//// 4)HEX format to ciphertext form

	

	std::string cipher,recovered;

	StringSource(RSACipher, true,
				new HexDecoder(
					new StringSink(cipher)
				) // HexDncoder
			); // StringSource


	// Decryption

         RSAES_OAEP_SHA_Decryptor d( private_key );

        StringSource( cipher, true,
            new PK_DecryptorFilter( rndtest2, d,
                new StringSink( recovered )
            ) // PK_EncryptorFilter
         ); // StringSource

		
		cout << "\nDecrypted key text \t"<< recovered ;


		return recovered;
}

void SaveHexPrivateKey(const string& filename, const PrivateKey& key)
{
    ByteQueue queue;
    key.Save(queue);

    SaveHex(filename, queue);
}

void SaveHexPublicKey(const string& filename, const PublicKey& key)
{
    ByteQueue queue;
    key.Save(queue);

    SaveHex(filename, queue);
}

void SaveHex(const string& filename, const BufferedTransformation& bt)
{
    HexEncoder encoder;

    bt.CopyTo(encoder);
    encoder.MessageEnd();

    Save(filename, encoder);
}

void Save(const string& filename, const BufferedTransformation& bt)
{
	
	FileSink file(filename.c_str());

	bt.CopyTo(file);
	file.MessageEnd();
}


int main(int argc, char* argv[])  
{ 
          
        if ( argc !=5 ) // argc should be 4 for correct execution 
        // We print argv[0] assuming it is the program name 
        { 
            cout<<"usage: "<< argv[0] <<" <filename>\n"; 
            return 0; 
        } 
          
                             char Cipherstr[3000]; 
                             char Keystr[3000]; 
                             char Macstr[3000]; 
                             char Mackey[3000]; 
								// char Timestamp[3000];
                               
                            
  
                              //Opens for reading the file 
                             std::ifstream Cipher_file ( argv[1] ); 
                             std::ifstream Key_file ( argv[2] ); 
							 std::ifstream Encrypted_Mac( argv[3] ); 
                             std::ifstream MacKey_file ( argv[4] ); 
							// std::ifstream time_stamp ( argv[5] ); 
							string keyfile,plaintext,mkeyfile,cipherfile,temp,encryptedfile,temp1;
  
                            // Always check to see if file opening succeeded 
							 if (!Cipher_file.is_open() && !Key_file.is_open() && MacKey_file.is_open() && Encrypted_Mac.is_open())  
                             cout<<"Could not open file\n"; 


							while ( Key_file && MacKey_file )
							{

								getline(Key_file,keyfile);
							   
								getline(MacKey_file,mkeyfile);

								
							}
						while ( Cipher_file)
							{
								temp.append(cipherfile);
								getline(Cipher_file,cipherfile);

						    }
								while (Encrypted_Mac)
							{
								temp1.append(encryptedfile);
								getline(Encrypted_Mac,encryptedfile);

						    }

				
				string RSAKey;
				int selection;
    
				cout << "\n************************************************************************"
					 << "\n* AES BLOCK CIPHER - DECRYPTION"
					 <<	"\n* Title  : Cryptography: encrypting files before storage in the cloud."
					 <<	"\n* Author : Pooja Patil and Mayur Kale \n* Date   : 11/23/2014 \n* Version: 1.0"
					 << "\n************************************************************************\n\n"; 

                cout << "1) Execute Part 3\n" 
					 << "2) Generate RSA Private key\n"
					 << "3) Generate RSA Public  key\n"
					 << "4) Decrypt key using privat key and Decrypt cipher text using AESBLOCKCIPHER\n"					
					 << "5) Exit the program" << endl << endl;
				cout << "Please select the function you would like to perform : ";
                cin >> selection; 

                switch (selection) 
                { 
					case 1:    
						AesBlockCipher(cipherfile.c_str(),keyfile.c_str(),encryptedfile.c_str(),mkeyfile.c_str()); 
						break; 
					case 2:    
						GenerateRSAPrivetKey();
						break; 
					case 3:   
						GenerateRSAPublicKey();
						break; 
					case 4:   
						RSAKey=DecryptKey_usingRSA();
						AesBlockCipher(cipherfile.c_str(),RSAKey.c_str(),encryptedfile.c_str(),mkeyfile.c_str());
						break; 
					default:  
						break; 
                } 

                Key_file.close(); 
                Cipher_file.close(); ;  
                system("pause"); 
    return 0; 
  
    }
