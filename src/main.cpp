#include <iostream>
#include <cstdint>

#include "SHA-2/sha256.hpp"


using namespace std;


int main(){
  SHA256 hasher;
  string text = "Hello world! Test hash of SHA-256.";
  
  hasher(text);

  cout << "sha-256('" << text << "') : " << hasher.hex() << endl;

  return 0;
};