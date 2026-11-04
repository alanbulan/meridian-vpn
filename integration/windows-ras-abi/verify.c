/* Compile-only Windows SDK ABI contract. Never link or call Rasapi32. */
#define WINVER 0x0a00
#define _WIN32_WINNT 0x0a00
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <ras.h>
#include <stddef.h>

#define CHECK(name, expression) typedef char abi_##name[(expression) ? 1 : -1]
#define OFFSET(field, expected) CHECK(field, offsetof(RASENTRYW, field) == (expected))
CHECK(entry_size, sizeof(RASENTRYW) == 6724);
CHECK(entry_name_size, sizeof(RASENTRYNAMEW) == 1048);
OFFSET(dwSize, 0);
OFFSET(dwfOptions, 4);
OFFSET(szLocalPhoneNumber, 38);
OFFSET(dwAlternateOffset, 296);
OFFSET(dwFramingProtocol, 328);
OFFSET(szScript, 332);
OFFSET(szAutodialDll, 852);
OFFSET(szAutodialFunc, 1372);
OFFSET(szDeviceType, 1892);
OFFSET(dwSubEntries, 3468);
OFFSET(dwType, 3496);
OFFSET(dwEncryptionType, 3500);
OFFSET(dwCustomAuthKey, 3504);
OFFSET(guidId, 3508);
OFFSET(szCustomDialDll, 3524);
OFFSET(dwVpnStrategy, 4044);
OFFSET(dwfOptions2, 4048);
OFFSET(dwfOptions3, 4052);
OFFSET(szPrerequisitePbk, 4572);
OFFSET(szPrerequisiteEntry, 5092);
OFFSET(szIDi, 5680);
OFFSET(szIDr, 6194);
OFFSET(fIsImsConfig, 6708);
OFFSET(fDisableIKEv2Fragmentation, 6720);
CHECK(vpn_type, RASET_Vpn == 2);
CHECK(l2tp_only, VS_L2tpOnly == 3);
CHECK(mschapv2, RASEO_RequireMsCHAP2 == 0x20000000);
CHECK(psk_mode, RASEO2_UsePreSharedKey == 0x10);
CHECK(encryption_required, ET_Require == 1);
CHECK(encryption_max, ET_RequireMax == 2);
CHECK(encryption_optional, ET_Optional == 3);
CHECK(ppp, RASFP_Ppp == 1);
CHECK(ipv4, RASNP_Ip == 4);
CHECK(ipv6, RASNP_Ipv6 == 8);

/* RASCONNW deliberately packs a pointer at offset four on x64. */
#define CONNOFF(field, expected) CHECK(conn_##field, offsetof(RASCONNW, field) == (expected))
CONNOFF(hrasconn, 4);
CONNOFF(szEntryName, 4 + sizeof(void *));
CONNOFF(szDeviceType, 518 + sizeof(void *));
CONNOFF(szDeviceName, 552 + sizeof(void *));
CONNOFF(szPhonebook, 810 + sizeof(void *));
CONNOFF(dwSubEntry, 1332 + sizeof(void *));
CONNOFF(guidEntry, 1336 + sizeof(void *));
CONNOFF(dwFlags, 1352 + sizeof(void *));
CONNOFF(luid, 1356 + sizeof(void *));
CONNOFF(guidCorrelationId, 1364 + sizeof(void *));
CHECK(connection_size, sizeof(RASCONNW) == 1380 + sizeof(void *));
#define STATUSOFF(field, expected) CHECK(status_##field, offsetof(RASCONNSTATUSW, field) == (expected))
CHECK(status_size, sizeof(RASCONNSTATUSW) == 608);
STATUSOFF(rasconnstate, 4);
STATUSOFF(dwError, 8);
STATUSOFF(szDeviceType, 12);
STATUSOFF(szDeviceName, 46);
STATUSOFF(szPhoneNumber, 304);
STATUSOFF(localEndPoint, 564);
STATUSOFF(remoteEndPoint, 584);
STATUSOFF(rasconnsubstate, 604);
CHECK(connected_state, RASCS_Connected == 0x2000);
CHECK(disconnected_state, RASCS_Disconnected == 0x2001);
CHECK(owner_known, RASCF_OwnerKnown == 0x4);
CHECK(owner_match, RASCF_OwnerMatch == 0x8);

/* Dial parameters: include the Windows 8+ encrypted-password pointer. */
#define DIALOFF(field, expected) CHECK(dial_##field, offsetof(RASDIALPARAMSW, field) == (expected))
CHECK(dial_username_limit, UNLEN == 256);
CHECK(dial_password_limit, PWLEN == 256);
CHECK(dial_domain_limit, DNLEN == 15);
DIALOFF(dwSize, 0);
DIALOFF(szEntryName, 4);
DIALOFF(szPhoneNumber, 518);
DIALOFF(szCallbackNumber, 776);
DIALOFF(szUserName, 1034);
DIALOFF(szPassword, 1548);
DIALOFF(szDomain, 2062);
DIALOFF(dwSubEntry, 2096);
DIALOFF(dwCallbackId, 2100);
DIALOFF(dwIfIndex, 2100 + sizeof(void *));
DIALOFF(szEncPassword, 2104 + sizeof(void *));
CHECK(dial_size, sizeof(RASDIALPARAMSW) == 2104 + 2 * sizeof(void *));

/* Compile-only callback assignment checks the SDK signature/calling convention.
   No definition, link, callback invocation or RAS function is needed here. */
DWORD CALLBACK meridian_callback_signature(ULONG_PTR, DWORD, HRASCONN, UINT,
                                          RASCONNSTATE, DWORD, DWORD);
RASDIALFUNC2 meridian_callback_contract = meridian_callback_signature;

/* Compile-only direct-call ABI contracts. This object is never linked/run. */
DWORD (WINAPI *meridian_dial_contract)(LPRASDIALEXTENSIONS, LPCWSTR,
    LPRASDIALPARAMSW, DWORD, LPVOID, LPHRASCONN) = RasDialW;
DWORD (WINAPI *meridian_hangup_contract)(HRASCONN) = RasHangUpW;

/* Direct-handle PPP IPv4 projection, modern Unicode structure. */
CHECK(ppp_ipv4_size, sizeof(RASPPPIPW) == 80);
CHECK(ppp_ipv4_error, offsetof(RASPPPIPW, dwError) == 4);
CHECK(ppp_ipv4_address, offsetof(RASPPPIPW, szIpAddress) == 8);
CHECK(ppp_ipv4_server, offsetof(RASPPPIPW, szServerIpAddress) == 40);
CHECK(ppp_ipv4_options, offsetof(RASPPPIPW, dwOptions) == 72);
CHECK(ppp_ipv4_server_options, offsetof(RASPPPIPW, dwServerOptions) == 76);
CHECK(ppp_ipv4_protocol, RASP_PppIp == 0x8021);
DWORD (WINAPI *meridian_projection_contract)(HRASCONN, RASPROJECTION,
    LPVOID, LPDWORD) = RasGetProjectionInfoW;

/* IP Helper uses default SDK packing, independent of ras.h's restored pack. */
CHECK(adapter_next, offsetof(IP_ADAPTER_ADDRESSES, Next) == 8);
CHECK(adapter_unicast, offsetof(IP_ADAPTER_ADDRESSES, FirstUnicastAddress) == 8 + 2 * sizeof(void *));
CHECK(adapter_type, offsetof(IP_ADAPTER_ADDRESSES, IfType) == 28 + 9 * sizeof(void *));
CHECK(adapter_oper, offsetof(IP_ADAPTER_ADDRESSES, OperStatus) == 32 + 9 * sizeof(void *));
CHECK(adapter_luid, offsetof(IP_ADAPTER_ADDRESSES, Luid) == (sizeof(void *) == 8 ? 224 : 176));
CHECK(unicast_next, offsetof(IP_ADAPTER_UNICAST_ADDRESS, Next) == 8);
CHECK(unicast_socket, offsetof(IP_ADAPTER_UNICAST_ADDRESS, Address) == 8 + sizeof(void *));
CHECK(unicast_dad, offsetof(IP_ADAPTER_UNICAST_ADDRESS, DadState) == 16 + 3 * sizeof(void *));
CHECK(unicast_prefix, offsetof(IP_ADAPTER_UNICAST_ADDRESS, OnLinkPrefixLength) == 32 + 3 * sizeof(void *));
CHECK(adapter_ppp, IF_TYPE_PPP == 23);
CHECK(adapter_up, IfOperStatusUp == 1);
CHECK(address_preferred, IpDadStatePreferred == 4);
CHECK(address_transient, IP_ADAPTER_ADDRESS_TRANSIENT == 2);
ULONG (WINAPI *meridian_adapters_contract)(ULONG, ULONG, PVOID,
    PIP_ADAPTER_ADDRESSES, PULONG) = GetAdaptersAddresses;

/* Every decoded socket/lifetime offset is checked against the actual SDK. */
CHECK(socket_pointer, offsetof(SOCKET_ADDRESS, lpSockaddr) == 0);
CHECK(socket_length, offsetof(SOCKET_ADDRESS, iSockaddrLength) == sizeof(void *));
CHECK(socket_size, sizeof(SOCKET_ADDRESS) == 2 * sizeof(void *));
CHECK(unicast_socket_length,
    offsetof(IP_ADAPTER_UNICAST_ADDRESS, Address) + offsetof(SOCKET_ADDRESS, iSockaddrLength)
    == 8 + 2 * sizeof(void *));
CHECK(unicast_valid_lifetime, offsetof(IP_ADAPTER_UNICAST_ADDRESS, ValidLifetime) == 20 + 3 * sizeof(void *));
CHECK(unicast_preferred_lifetime, offsetof(IP_ADAPTER_UNICAST_ADDRESS, PreferredLifetime) == 24 + 3 * sizeof(void *));
CHECK(sockaddr_ipv4_size, sizeof(SOCKADDR_IN) == 16);
CHECK(sockaddr_ipv4_family, offsetof(SOCKADDR_IN, sin_family) == 0);
CHECK(sockaddr_ipv4_address, offsetof(SOCKADDR_IN, sin_addr) == 4);
CHECK(sockaddr_ipv4_family_value, AF_INET == 2);
