/*
 * Title: Project 2 (Cryptography: encrypting files before storage in the cloud).
 * Purpose: The project consists of a software implementation of a method to pre-process a file before storing it on a cloud storage server 
 *			so that the server cannot read the file content but a desired peer can.
 * Author: Pooja Patil and Mayur Kale 
 * Date: 11/23/2014
 * Version: 1.0
 */


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

int main(int argc, char* argv[])  
{ 
		cout << "\n************************************************************************"
			 << "\n* Welcome to AES BLOCK CIPHER - DECRYPTION"
			 <<	"\n* Title  : Cryptography: encrypting files before storage in the cloud."
			 <<	"\n* Author : Pooja Patil and Mayur Kale \n* Date   : 11/23/2014 \n* Version: 1.0"
			 << "\n************************************************************************\n\n"; 
          
			if ( argc !=5 ) // argc should be 4 for correct execution 
			// We print argv[0] assuming it is the program name 
			{ 
				cout <<"*** Error: Missing Parameters *** \n"
					 <<"Usage: filename <cipher_file_path> <key_file_path> <mac_file_path> <MacKey_file_path> \n";
				system("pause");
				return 0;
			} 
			else {
					char Cipherstr[3000], Keystr[3000], Macstr[3000], Mackey[3000]; 
  
                    //Opens for reading the file 
                    std::ifstream Cipher_file (argv[1]); 
                    std::ifstream Key_file (argv[2]); 
					std::ifstream Encrypted_Mac(argv[3]); 
                    std::ifstream MacKey_file (argv[4] ); 
					
					// std::ifstream time_stamp ( argv[5] ); 
					string keyfile,plaintext,mkeyfile,cipherfile,temp,encryptedfile,temp1;
  
                            // Always check to see if file opening succeeded 
							 if (!Cipher_file.is_open() && !Key_file.is_open() && MacKey_file.is_open() && Encrypted_Mac.is_open())  
                             cout<<"Could not open file\n"; 

							while (Key_file && MacKey_file) {
								getline(Key_file,keyfile);
								getline(MacKey_file,mkeyfile);
							}
						
							// get cipher text
							while (getline(Cipher_file,cipherfile)) {
								//temp.append(cipherfile);	
						    }
							// get encrypted mac text
							while (getline(Encrypted_Mac,encryptedfile)) {
								//temp1.append(encryptedfile);	
						    }

				
                Key_file.close();
                Cipher_file.close(); ;  
                system("pause"); 
	}
    return 0; 
}


  
void AesBlockCipher(string ciphertxt,string keyfile,string mac,string mkey) 
{ 


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

			while (SecreatKey) {
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

	 string rsa_privatekey = "rsa-private.txt";
	 string rsa_CipherPubKey = "rsa-keycipher.txt";

	//1) Read Private Key
	std::ifstream SecreatKey (rsa_privatekey); 
		 if (!SecreatKey.is_open() )  
           cout<<"Could not open file\n"; 

			while ( SecreatKey ) {
				getline(SecreatKey,Strsecretekey);
			}

		cout << "\nDecrypted key text :"<< recovered << "\n\n" ;
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
