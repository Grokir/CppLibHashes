#include "sha512.hpp"

#include <sstream>
#include <iomanip>
#include <bitset>


SHA512::SHA512() = default;

SHA512::SHA512(const std::string& message){
  init(message);
};

void SHA512::operator()(const std::string& message){
  init(message);
};


uint64_t SHA512::char_to_uint64 (const std::string& chunk){
  uint64_t res =  ( ((uint64_t) chunk[0]) << 56 ) & 0xFF00000000000000 | 
                  ( ((uint64_t) chunk[1]) << 48 ) & 0x00FF000000000000 | 
                  ( ((uint64_t) chunk[2]) << 40 ) & 0x0000FF0000000000 | 
                  ( ((uint64_t) chunk[3]) << 32 ) & 0x000000FF00000000 | 
                  ( ((uint64_t) chunk[4]) << 24 ) & 0x00000000FF000000 | 
                  ( ((uint64_t) chunk[5]) << 16 ) & 0x0000000000FF0000 | 
                  ( ((uint64_t) chunk[6]) <<  8 ) & 0x000000000000FF00 | 
                  ( ((uint64_t) chunk[7])       ) & 0x00000000000000FF ;

  return res;
};

uint64_t SHA512::bits_to_uint64 (const std::string& chunk){
  return (uint64_t) std::bitset<SHA512_CHUNK_BIT_SIZE>(chunk).to_ulong();
};

std::pair<uint32_t, uint32_t> SHA512::uint64_to_uint32(std::uint64_t val){
  uint32_t first, second;

  std::string tmp = std::bitset<64>(val).to_string();
  first  = std::bitset<32>(tmp.substr(0, 32)).to_ulong();
  second = std::bitset<32>(tmp.substr(32, 32)).to_ulong();

  return std::pair<uint32_t, uint32_t>(first, second);
};

std::string SHA512::padding_message(const std::string& msg){
  std::string binstr, 
              tmp;
  std::size_t binstr_sz;

  for(char ch : msg){
    binstr += std::bitset<8>(ch).to_string();
  }

  binstr += '1';

  binstr_sz = binstr.length(); // l + 1

  if(binstr_sz % SHA512_BLOCK_BIT_SIZE != 896){
    std::size_t k = 896 - ( binstr_sz % SHA512_BLOCK_BIT_SIZE );
    binstr += std::string(k, '0'); // l + 1 + k
  }

  tmp     = std::bitset<8>( (binstr_sz - 1) ).to_string();
  binstr += std::string( (128 - tmp.length()), '0' ) + tmp; // l + 1 + k + 128

  return binstr;
};


std::vector<uint64_t> SHA512::get_chunks(const std::string& binmsg){
  std::vector<uint64_t>   res;
  std::string             chunk;
  
  for (int i = 0; i < binmsg.size(); i++){
    if(chunk.size() == SHA512_CHUNK_BIT_SIZE){
      res.push_back(bits_to_uint64(chunk));
      chunk.clear();
    }
    chunk += binmsg[i];
  }

  if( !chunk.empty() )
    res.push_back(bits_to_uint64(chunk));

  return res;
};

std::string SHA512::hex(){
  std::stringstream ss;
  
  for(int i = 0; i < 8; i++){
    ss << std::hex << m_H[i];
  }

  return ss.str();
};
std::vector<uint32_t> SHA512::hexdigest(){
  int H_size = sizeof(m_H) / sizeof(m_H[0]);

  std::pair<uint32_t, uint32_t> tmp;
  std::vector<uint32_t>         res;
  
  int j = 0;
  for(int i = 0; i < H_size; i++){
    tmp = uint64_to_uint32(m_H[i]);
    res.push_back(tmp.first);
    res.push_back(tmp.second);
  }

  return res;
};

uint64_t SHA512::Ch(uint64_t x, uint64_t y, uint64_t z){
  return ( (x & y) ^ (~x & z) );
};

uint64_t SHA512::Maj(uint64_t x, uint64_t y, uint64_t z){
  return ( (x & y) ^ (x & z) ^ (y ^ z) );
};


// because sizeof return num of bytes,
// but need size in bits, 
// so we miltiple sizeof(x) on 8 (size of byte)
uint64_t SHA512::rightrotate(uint64_t x, uint64_t n){
  return ( (x >> n) | (x << (sizeof(x) * 8 - n)) );
};
uint64_t SHA512::leftrotate (uint64_t x, uint64_t n){
  return ( (x << n) | (x >> (sizeof(x) * 8 - n)) );
};


uint64_t SHA512::rightshift (uint64_t x, uint64_t n){
  return ( x >> n );
};
uint64_t SHA512::E0 (uint64_t x){
  return ( rightrotate(x, 28) ^ rightrotate(x, 34) ^ rightrotate(x, 39) );
};
uint64_t SHA512::E1 (uint64_t x){
  return ( rightrotate(x, 14) ^ rightrotate(x, 18) ^ rightrotate(x, 41) );
};
uint64_t SHA512::D0 (uint64_t x){
  return ( rightrotate(x,  1) ^ rightrotate(x,  8) ^ rightshift (x,  7) );
};
uint64_t SHA512::D1 (uint64_t x){
  return ( rightrotate(x, 19) ^ rightrotate(x, 61) ^ rightshift (x,  6) );
};


////================================================================================

void SHA512::init(const std::string& message){
  this->m_chunks = this->get_chunks(
    this->padding_message(message)
  );
  this->compute();
};

void SHA512::compute(){
  uint64_t N = ( this->m_chunks.size() * SHA512_CHUNK_BIT_SIZE ) / SHA512_BLOCK_BIT_SIZE;
  uint64_t W[80];
  uint64_t a, b, c, d, e, f, g, h;
  uint64_t T1, T2;


  for(int i = 0; i < N; i++){

    for(int t = 0; t < 64; t++){
      if(t < 16)
        W[t] = m_chunks[t];
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

    for(int t = 0; t < 80; t++){
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

    m_H[0] += a;
    m_H[1] += b;
    m_H[2] += c;
    m_H[3] += d;
    m_H[4] += e;
    m_H[5] += f;
    m_H[6] += g;
    m_H[7] += h;

  }

};