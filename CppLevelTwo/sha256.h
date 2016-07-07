#pragma once
#include <vector>
#include <array>
#include <stddef.h> 
#include <functional>

namespace sha256
{
#ifndef SWIG
	/****************************** MACROS ******************************/
	constexpr int SHA256_BLOCK_SIZE = 32;            // SHA256 outputs a 32 byte digest


	inline constexpr unsigned int rotLeft(const unsigned int &a, const unsigned int &b) { return (((a) << (b)) | ((a) >> (32 - b))); }

	inline constexpr unsigned int rotRight(const unsigned int &a, const unsigned int &b) { return (((a) >> (b)) | ((a) << (32 - b))); }

	inline constexpr unsigned int ch(const unsigned int &x, const unsigned int &y, const unsigned int &z)
	{
		return (((x)& (y)) ^ (~x) & (z));
	}

	inline constexpr unsigned int maj(const unsigned int &x, const unsigned int &y, const unsigned int &z)
	{
		return ((x)& (y)) ^ ((x)& (z)) ^ ((y)& (z));
	}

	inline constexpr unsigned int ep0(const unsigned int &x) { return rotRight(x, 2) ^ rotRight(x, 13) ^ rotRight(x, 22); }

	inline constexpr unsigned int ep1(const unsigned int &x) { return rotRight(x, 6) ^ rotRight(x, 11) ^ rotRight(x, 25); }

	inline constexpr unsigned int sig0(const unsigned int &x) { return rotRight(x, 7) ^ rotRight(x, 18) ^ ((x) >> 3); }

	inline constexpr unsigned int sig1(const unsigned int &x) { return rotRight(x, 17) ^ rotRight(x, 19) ^ ((x) >> 10); }
    

	/**************************** DATA TYPES ****************************/
#endif
	typedef unsigned char BYTE;             // 8-bit byte
	typedef unsigned int  WORD;             // 32-bit word, change to "long" for 16-bit machines
#ifndef SWIG
    constexpr auto blocksize = 64;
    constexpr auto blockbitsize = blocksize * 8; //8 bits in a byte

    constexpr auto state0 = 0x6a09e667;
    constexpr auto state1 = 0xbb67ae85;
    constexpr auto state2 = 0x3c6ef372;
    constexpr auto state3 = 0xa54ff53a;
    constexpr auto state4 = 0x510e527f;
    constexpr auto state5 = 0x9b05688c;
    constexpr auto state6 = 0x1f83d9ab;
    constexpr auto state7 = 0x5be0cd19;
#endif
    typedef std::function<void(std::array<WORD, 8>&, std::array<BYTE, 64>&)> TransformFunction;
    //using TransformFunction = std::function<void(std::array<WORD, 8>&, std::array<BYTE, 64>&)>;

	class Sha256
	{
	public:
		Sha256();
		void update(const std::vector<BYTE> &data, TransformFunction transformFuction = transform);
        std::array<BYTE, 32> digest() const;
		std::array<BYTE, 32> digest(TransformFunction transformFuction) const;
		std::string hexDigest(TransformFunction fn = transform) const;
		void reinit();

        //Functions below here are for experimentation and learning about the sha256 algorithm
        //They will break functionality if use to alter the state and internal data durring a real
        //sha256 hash.
        void setState(const std::array< WORD, 8 > &state);
        inline std::array< WORD, 8> state() const { return state_; }
        static std::array< WORD, 64> calculateM(const std::array<BYTE, 64> &data);
        static std::array< std::array<WORD, 8>, 64> transformWatch(std::array<WORD, 8> &state, std::array<BYTE, 64> &data);

	private:
        static void transform(std::array<WORD, 8> &state, std::array<BYTE, 64> &data);

		std::array< BYTE, 64 > data_;
		WORD datalen_;
		unsigned long long bitlen_;
		std::array< WORD, 8 > state_;
		static const std::array<unsigned int, 64> k_;
	};

}
