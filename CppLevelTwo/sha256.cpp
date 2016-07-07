/*************************** HEADER FILES ***************************/
#include <stdlib.h>
#include <memory.h>
#include <array>
#include <sstream>
#include <iomanip>
#include "sha256.h"

using namespace sha256;
/**************************** VARIABLES *****************************/
const std::array<unsigned int, 64> Sha256::k_ = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

/*********************** FUNCTION DEFINITIONS ***********************/

void Sha256::reinit()
{
    datalen_ = 0;
    bitlen_ = 0;
    state_[0] = state0;
    state_[1] = state1;
    state_[2] = state2;
    state_[3] = state3;
    state_[4] = state4;
    state_[5] = state5;
    state_[6] = state6;
    state_[7] = state7;
    for (auto &x : data_)
    {
        x = 0;
    }
}

void Sha256::setState(const std::array< WORD, 8 > &state)
{
    for (auto i = 0; i < 8; ++i)
        state_[i] = state[i];
}

std::array< WORD, 64 > Sha256::calculateM(const std::array<BYTE, 64> &data)
{
	std::array<WORD, 64> m{};

	for (auto i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
	for (auto i = 16; i < 64; ++i)
		m[i] = sig1(m[i - 2]) + m[i - 7] + sig0(m[i - 15]) + m[i - 16];

    return m;
}

std::array< std::array< WORD, 8>, 64 > Sha256::transformWatch(std::array<WORD, 8> &state, std::array<BYTE, 64> &data)
{
    std::array< std::array< WORD, 8 >, 64 > transformState{};
	auto a = state[0];
	auto b = state[1];
	auto c = state[2];
	auto d = state[3];
	auto e = state[4];
	auto f = state[5];
	auto g = state[6];
	auto h = state[7];

    auto m = calculateM(data);

	for (auto i = 0; i < 64; ++i)
	{
		auto t1 = h + ep1(e) + ch(e, f, g) + k_[i] + m[i];
		auto t2 = ep0(a) + maj(a, b, c);
		h = g; 
		g = f;
		f = e; 
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
        transformState[i] = std::array< WORD, 8 > {a, b, c, d, e, f, g, h};
	}

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	state[5] += f;
	state[6] += g;
	state[7] += h;


    return transformState;
}

void Sha256::transform(std::array<WORD, 8> &state, std::array<BYTE, 64> &data)
{
	auto a = state[0];
	auto b = state[1];
	auto c = state[2];
	auto d = state[3];
	auto e = state[4];
	auto f = state[5];
	auto g = state[6];
	auto h = state[7];

    auto m = calculateM(data);

	for (auto i = 0; i < 64; ++i)
	{
		auto t1 = h + ep1(e) + ch(e, f, g) + k_[i] + m[i];
		auto t2 = ep0(a) + maj(a, b, c);
		h = g; 
		g = f;
		f = e; 
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	state[5] += f;
	state[6] += g;
	state[7] += h;
}

Sha256::Sha256()
{
    reinit();
}

void Sha256::update(const std::vector<BYTE> &data, TransformFunction transformFunction)
{
	for (auto i : data)
	{
		data_[datalen_] = i;
		datalen_++;
		if (datalen_ == blocksize)
		{
			transformFunction(state_, data_);
			bitlen_ += blockbitsize;
			datalen_ = 0;
		}
	}
}

std::array< BYTE, 32> Sha256::digest() const
{
    return digest(Sha256::transform);
}

std::array< BYTE, 32> Sha256::digest(TransformFunction transformFunction) const
{
	//copy so that we can call this function as much as needed...
	//may want to optomize this away later...
	auto i = datalen_;
	auto data = data_;
	auto state = state_;
	auto bitlen = bitlen_;

	//Pad anything left in the buffer
	if (datalen_ < 56)
	{
		data[i++] = 0x80; 
		while (i < 56)
			data[i++] = 0x00;
	}
	else
	{
		data[i++] = 0x80;
		while (i < 64)
			data[i++] = 0x00;
		transformFunction(state, data);
        std::fill(data.begin(), data.begin() + 56, 0);
	}

	bitlen += datalen_ * 8;
	data[63] = static_cast<BYTE>(bitlen);
	data[62] = static_cast<BYTE>(bitlen >> 8);
	data[61] = static_cast<BYTE>(bitlen >> 16);
	data[60] = static_cast<BYTE>(bitlen >> 24);
	data[59] = static_cast<BYTE>(bitlen >> 32);
	data[58] = static_cast<BYTE>(bitlen >> 40);
	data[57] = static_cast<BYTE>(bitlen >> 48);
	data[56] = static_cast<BYTE>(bitlen >> 56);
	transformFunction(state, data);

	//this implementation is in little endian and sha uses big endian ...
	//reverse all the bytes.
	std::array<BYTE, 32> hash{};

	for (auto i = 0; i < 4; ++i)
	{
		hash[i] = (state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4] = (state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8] = (state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (state[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (state[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (state[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (state[7] >> (24 - i * 8)) & 0x000000ff;
	}

	return hash;
}

std::string Sha256::hexDigest(TransformFunction fn) const
{
	std::stringstream ss{};
	std::array<BYTE, 32> hash = digest(fn);
	ss << std::hex << std::setfill('0');
	for (auto i : hash)
		ss << std::setw(2) << static_cast<unsigned>(i);
	return ss.str();
}
