#include <windows.h>
#include <string.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/pubkey.h>
#include <cryptopp/rsa.h>
#include <cryptopp/base64.h>
#include "cryptopp/hex.h"
#include "cryptopp/integer.h"
#include "cryptopp/modes.h"


#define DLLIMPORT __declspec (dllexport)

#include "memory_api.h"

			
extern "C"
{
#ifdef __BORLANDC__
  #pragma argsused
#endif
  int WINAPI DllMain( HINSTANCE hInst, /* Library instance handle. */
  unsigned long reason, /* Reason this function is being called. */
  void * lpReserved ) /* Not used. */
  {
    DllInstance=hInst;
    return 1;
  }
  int WINAPI DllEntryPoint( HINSTANCE hInst, unsigned long reason, void * lpReserved )
  {
    return DllMain( hInst, reason, lpReserved );
  }


}
