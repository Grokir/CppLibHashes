#include "sha256.hpp"

SHA256::SHA256(const std::string& message){
  this->m_chunks = this->get_chunks(message);
};

std::vector<std::string> SHA256::get_chunks(const std::string& msg){
  std::vector<std::string>  res;
  std::string               chunk;
  const uint8_t             chunk_ref_size  =  512 / 8; // bytes or count chars

  for (int i = 0; i < msg.size(); i++){
    if(chunk.size() == chunk_ref_size){
      res.push_back(chunk);
      chunk.clear();
    }
    chunk += msg[i];
  }

  if(chunk != "")
    res.push_back(chunk);

  return res;
};

std::string SHA256::hexdigest(){
  return "";
};

uint32_t SHA256::Ch(uint32_t E, uint32_t F, uint32_t G){
  return ( (E & F) ^ (~E & F) );
};

uint32_t SHA256::Ma(uint32_t A, uint32_t B, uint32_t C){
  return ( (A & B) ^ (A & C) ^ (B ^ C) );
};
uint32_t SHA256::rightrotate(uint32_t x, uint32_t n){
  return ( (x >> n) | (x << (sizeof(x) - n)) );
};
uint32_t SHA256::leftrotate (uint32_t x, uint32_t n){
  return ( (x << n) | (x >> (sizeof(x) - n)) );
};
uint32_t SHA256::rightshift (uint32_t x, uint32_t n){
  return ( x >> n );
};
uint32_t SHA256::E0 (uint32_t A){
  return ( (A >> 2) ^ (A >> 13) ^ (A >> 22) );
};
uint32_t SHA256::E1 (uint32_t E){
  return ( (E >> 6) ^ (E >> 11) ^ (E >> 25) );
};