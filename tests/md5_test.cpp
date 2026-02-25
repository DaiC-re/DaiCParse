#define CATCH_CONFIG_MAIN
#include "checksums/md5.h"

#include <catch2/catch_test_macros.hpp>

TEST_CASE("md5_t: Default constructor and empty input", "[md5]") {
	md5::md5_t md5;
	unsigned char signature[MD5_SIZE];

	// Finish the hashing process
	md5.finish(signature);

	// Compare result to known MD5 of empty string
	char result_str[MD5_STRING_SIZE];
	md5::sig_to_string(signature, result_str, MD5_STRING_SIZE);

	REQUIRE(strcmp(result_str, "d41d8cd98f00b204e9800998ecf8427e") == 0);
}

TEST_CASE("md5_t: Single block input", "[md5]") {
	const char* data = "abc";  // Known MD5 hash of "abc"
	unsigned char signature[MD5_SIZE];

	// Process data and finalize
	md5::md5_t md5(data, strlen(data), signature);

	// Convert signature to string
	char result_str[MD5_STRING_SIZE];
	md5::sig_to_string(signature, result_str, MD5_STRING_SIZE);

	// Check against the known MD5 for "abc"
	REQUIRE(strcmp(result_str, "900150983cd24fb0d6963f7d28e17f72") == 0);
}

TEST_CASE("md5_t: Progressive processing", "[md5]") {
	const char* part1 = "The quick brown ";
	const char* part2 = "fox jumps over ";
	const char* part3 = "the lazy dog";  // Known MD5 of the full string
	unsigned char signature[MD5_SIZE];

	// Process parts progressively
	md5::md5_t md5;
	md5.process(part1, strlen(part1));
	md5.process(part2, strlen(part2));
	md5.process(part3, strlen(part3));
	md5.finish(signature);

	// Convert signature to string
	char result_str[MD5_STRING_SIZE];
	md5::sig_to_string(signature, result_str, MD5_STRING_SIZE);

	// Check against the known MD5 for the full string
	REQUIRE(strcmp(result_str, "9e107d9d372bb6826bd81d3542a419d6") == 0);
}

TEST_CASE("md5_t: MD5 signature to string conversion", "[md5]") {
	const char* data = "hello world";  // Known MD5 hash of "hello world"
	unsigned char signature[MD5_SIZE];

	md5::md5_t md5(data, strlen(data));
	md5.get_sig(signature);

	char result_str[MD5_STRING_SIZE];
	md5::sig_to_string(signature, result_str, MD5_STRING_SIZE);

	REQUIRE(strcmp(result_str, "5eb63bbbe01eeed093cb22bb8f5acdc3") == 0);
}

TEST_CASE("md5_t: String to MD5 signature conversion", "[md5]") {
	const char* md5_str = "5eb63bbbe01eeed093cb22bb8f5acdc3";
	unsigned char signature[MD5_SIZE];

	// Convert string back to signature
	md5::sig_from_string(signature, md5_str);

	// Convert back to string and check equivalence
	char result_str[MD5_STRING_SIZE];
	md5::sig_to_string(signature, result_str, MD5_STRING_SIZE);

	REQUIRE(strcmp(result_str, md5_str) == 0);
}