#include "sha256.hpp"

#include <sstream>
#include <iomanip>

SHA256::SHA256(const std::string& message){
  this->m_chunks = this->get_chunks(message);
  this->compute();
};

uint32_t SHA256::to_uint32 (const std::string& chunk){
  uint32_t res =  ( ((uint32_t) chunk[0]) << 24 ) & 0xFF000000 | 
                  ( ((uint32_t) chunk[1]) << 16 ) & 0x00FF0000 | 
                  ( ((uint32_t) chunk[2]) <<  8 ) & 0x0000FF00 | 
                  ( ((uint32_t) chunk[3])       ) & 0x000000FF ;

  return res;
};

// TODO: Fix shedule chunks
std::vector<std::string>  SHA256::get_chunks(const std::string& msg){
  std::vector<std::string>  res;
  std::string               chunk;
  const uint8_t             chunk_ref_size  =  32 / 8; // bytes or count chars

  // count chunks == 512 / 8 == 64

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

std::string SHA256::hex(){
  std::stringstream ss;
  
  for(int i = 0; i < 8; i++){
    ss << std::hex << m_H[i];
  }

  return ss.str();
};
std::vector<uint32_t> SHA256::hexdigest(){
  int H_size = 8;
  std::vector<uint32_t> res(H_size);
  
  for(int i = 0; i < H_size; i++)
    res[i] = m_H[i];

  return res;
};

uint32_t SHA256::Ch(uint32_t x, uint32_t y, uint32_t z){
  return ( (x & y) ^ (~x & z) );
};

uint32_t SHA256::Maj(uint32_t x, uint32_t y, uint32_t z){
  return ( (x & y) ^ (x & z) ^ (y ^ z) );
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
uint32_t SHA256::E0 (uint32_t x){
  return ( rightrotate(x, 2) ^ rightrotate(x, 13) ^ rightrotate(x, 22) );
};
uint32_t SHA256::E1 (uint32_t x){
  return ( rightrotate(x, 6) ^ rightrotate(x, 11) ^ rightrotate(x, 25) );
};
uint32_t SHA256::D0 (uint32_t x){
  return ( rightrotate(x, 7) ^ rightrotate(x, 18) ^ rightshift(x, 3) );
};
uint32_t SHA256::D1 (uint32_t x){
  return ( rightrotate(x, 17) ^ rightrotate(x, 19) ^ rightshift(x, 10) );
};


////================================================================================

void SHA256::compute(){
  int N = this->SHA256_BLOCK_SIZE;
  uint32_t W[64];
  uint32_t a, b, c, d, e, f, g, h;
  uint32_t T1, T2;


  for(int i = 1; i < N; i++){

    for(int t = 0; t < 64; t++){
      if(t < 16)
        W[t] = to_uint32( m_chunks[t] );
      else
        W[t] = D1(W[t - 2]) + W[t - 7] + D0(W[t - 15]) + W[t - 16];
    }

    a = m_H[0];
    b = m_H[1];
    c = m_H[2];
    d = m_H[3];
    e = m_H[4];
    f = m_H[5];
    g = m_H[6];
    h = m_H[7];

    for(int t = 0; t < 64; t++){
      T1 = h + E1(e) + Ch(e, f, g) + m_K[t] + W[t];
      T2 = E0(a) + Maj(a, b, c);
      h = g;
      g = f;
      f = e;
      e = d + T1;
      d = c;
      c = b;
      b = a;
      a = T1 + T2;
    }

    m_H[0] = a + m_H[0];
    m_H[1] = b + m_H[1];
    m_H[2] = c + m_H[2];
    m_H[3] = d + m_H[3];
    m_H[4] = e + m_H[4];
    m_H[5] = f + m_H[5];
    m_H[6] = g + m_H[6];
    m_H[7] = h + m_H[7];

  }

};