#include <iostream>
#include <string>
#include <cstring>
#include <WinSock2.h>
#include <ws2tcpip.h>

#pragma comment (lib, "ws2_32.lib")

const char* spamhaus_dnsbl = "zen.spamhaus.org";

const std::string converter(const char* ip) {
	std::string convertedAddr = "";
	for (size_t i = 0; i < strlen(ip); i++) {
		std::string part = "";

		while (ip[i] != '.' && ip[i] != '\0') {
			part += ip[i];
			i++;
		}
		part += '.';
		convertedAddr.insert(0, part);
	}
	convertedAddr.append(spamhaus_dnsbl);
	return convertedAddr;
}

const char* receivedDescription(const char* return_code) {
	if (!return_code) {
		return "";
	}
	const char* lastOctet = return_code + strlen(return_code);
	while (*(lastOctet - 1) != '.' && lastOctet > return_code) {
		--lastOctet;
	}

	if (!strcmp(lastOctet, "2")) {
		return "SBL	- Spamhaus SBL Data";
	}
	else if (!strcmp(lastOctet, "3")) {
		return "SBL - Spamhaus SBL CSS Data";
	}
	else if (!strcmp(lastOctet, "4")) {
		return "XBL - CBL Data";
	}
	else if (!strcmp(lastOctet, "9")) {
		return "SBL - Spamhaus DROP/EDROP Data";
	}
	else if (!strcmp(lastOctet, "10")) {
		return "PBL - ISP Maintained";
	}
	else if (!strcmp(lastOctet, "11")) {
		return "PBL - Spamhaus Maintained";
	}
	return "";
}



int main(int argc, char** argv) {
	if (argc < 2) {
		std::cerr << "Not enough arguments!\n";
		return 0;
	}

	WSADATA wsaData;

	if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0) {
		std::cerr << "WSAStartup failed with error";
		return 1;
	}
	
	for (int i = 1; argv[i]; ++i) {
		const std::string& converted = converter(argv[i]);

		addrinfo* ptr = nullptr;
		addrinfo hints;
		addrinfo* result = nullptr;

		std::memset(&hints, 0, sizeof(addrinfo));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_DGRAM;

		int dwRetval = getaddrinfo(converted.c_str(), nullptr, &hints, &result);
		if (dwRetval != 0) {
			std::cout << "The IP address: " << argv[i] << " is NOT found in the Spamhaus blacklists.\n";
			continue;
		}

		std::cout << "The IP address: " << argv[i] << " is found in the following Spamhaus public IP zone:\n";

		char hostname[NI_MAXHOST];
		for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
			int nameinfo = getnameinfo(ptr->ai_addr, ptr->ai_addrlen, hostname, NI_MAXHOST, nullptr, 0, NI_NUMERICHOST);
			if (nameinfo != 0) {
				std::cerr << "getnameinfo failed with error";
			}
			else {
				std::cout << "'" << hostname << " - " << receivedDescription(hostname) << "'\n";
			}
		}

		freeaddrinfo(result);
	}
	WSACleanup();
	return 0;
}
