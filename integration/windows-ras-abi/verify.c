/* Compile-only Windows SDK ABI contract. Never link or call Rasapi32. */
#define WINVER 0x0a00
#define _WIN32_WINNT 0x0a00
#include <windows.h>
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
