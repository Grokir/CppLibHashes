#include <iostream>
#include <cstdint>

#include "SHA-2/sha256.hpp"
#include "SHA-2/sha512.hpp"


using namespace std;


void SHA256_example();
void SHA512_example();


int main(){

  SHA256_example();
  SHA512_example();

  return 0;
};


void SHA256_example(){
  SHA256 hasher;
  string text = "Hello world! Test hash of SHA-256.";
  hasher(text);

  cout << "sha-256('" << text << "') : " << hasher.hex() << '\n' << endl;
};

void SHA512_example(){
  SHA512 hasher;
  string text = "Hello world! Test hash of SHA-512.";
  hasher(text);

  cout << "sha-512('" << text << "') : " << hasher.hex() << '\n' << endl;
};
