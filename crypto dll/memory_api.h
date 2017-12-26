
HINSTANCE DllInstance; 

using namespace CryptoPP;

#include <windows.h>
#include <stdio.h>

PCHAR DecodeMicrosoftKey( BYTE* digitalProductId )
{
 
    /* NULL is a valid byte value, so check for it. */
    if ( digitalProductId )
    {
        /* Offset first value to 34H. */
        const int keyStartIndex = 52;
        /* Offset last value to 43H. */
        const int keyEndIndex = keyStartIndex + 15;
        /* Valid Product Key Characters. */
        char digits[] =
        {
            'B', 'C', 'D', 'F', 'G', 'H', 'J', 'K', 'M', 'P', 'Q', 'R',
            'T', 'V', 'W', 'X', 'Y', '2', '3', '4', '6', '7', '8', '9',
        };
        /* Length of decoded product key. */
        const int decodeLength  =   29;
        /* Length of decoded key in byte-form (each byte = 2 chars). */
        const int decodeStringLength = 15;
        /* Array to contain decoded key. */
        char* pDecodedChars = new char[ decodeLength + 1 ];
 
        memset( pDecodedChars, 0, decodeLength + 1 );
 
        /* Extract byte 52 to 67 inclusive. */
        byte hexPid[ keyEndIndex - keyStartIndex + 1 ];
 
        for ( int i = keyStartIndex; i <= keyEndIndex; i++ )
        {
            hexPid[ i - keyStartIndex ] = digitalProductId[ i ];
        }
 
        for ( int i = decodeLength - 1; i >= 0; i-- )
        {
            /* Every 6th character is a seperator. */
            if ( ( i + 1 ) % 6 == 0 )
            {
                *( pDecodedChars + i ) = '-';
            }
            else
            {
                /* Do the actual decoding. */
                int digitMapIndex = 0;
                for ( int j = decodeStringLength - 1; j >= 0; j-- )
                {
                    int byteValue = ( digitMapIndex << 8 ) | hexPid[ j ];
                    hexPid[ j ] = ( byte )( byteValue / 24 );
                    digitMapIndex = byteValue % 24;
                    *( pDecodedChars + i ) = digits[ digitMapIndex ];
                }
            }
        }
        /*
         * Return the decoded product key.
         */
        return pDecodedChars;
    }
    /* digitalProductID was passed as a NULL value, return NULL. */
    else
    {
        return NULL;
    }
}
 
byte* GetRegistryKeyValue(const char* RegKey, const char* pPIDName)
{
    HKEY		Registry;
    long		ReturnStatus;
    DWORD       regType	= 0;
    DWORD       regSize = 0;
    byte*		pPID = 0;
 
    /* Open Key. */
    ReturnStatus = RegOpenKeyEx( HKEY_LOCAL_MACHINE, RegKey, 0, (KEY_QUERY_VALUE|0x0100), &Registry );
 
    if ( ReturnStatus == ERROR_SUCCESS )
    {
        /* get size of key */
        ReturnStatus = RegQueryValueEx(Registry, pPIDName, 0, &regType, 0, &regSize);
        pPID = new byte[ regSize ];
 
        /* Get Value. */
        ReturnStatus = RegQueryValueEx( Registry, pPIDName, 0, &regType, pPID, &regSize );
        RegCloseKey( Registry );
 
        /*
         * Check & trim last character if ascii value is > 127.
         * Some companies (WebsuperGoo) seem to append an extended
         * ascii character
         */
         if ( pPID[regSize] > 127 || pPID[regSize] < 32 )
         {
            pPID[regSize] = '\0';
         }
 
        /* Ensure we're returning a valid result. */
        if ( regSize > 1 )
        {
            printf("Size > 1 (%d)\n", regSize);
            return pPID;
        }
        else
        {
            printf("Size not > 1 (%d)\n", regSize);
            return NULL;
        }
    }
    else
    {
        /* Close Key. */
        RegCloseKey( Registry );
        return NULL;
    }
}
 


PCHAR encyrpt(LPSTR message)
{
      
  RSAFunction rs;
   //Integer it("138058324507555049234246734000441140752323800141033219108446290424209651149061550256257123074054375779322028941830252756690799794787415386877876745524597141573809959460210645347060554401228507084399841512197648738006400503980279149209427806825118624928692857963634531857449103468249102954313978230908185591117");
     Integer it("136342089467838913572203178633753754308518322695230862561644858854246917172156426697297912453834900384789619028269192163146797287128601468308176748768692559820227319038605394585160263253974483415403290336949488219169934651437632357136400496139196507940904386260050442453399818419968593691721037571595385395907"); 
  
  rs.SetModulus(it);
  rs.SetPublicExponent(65537);
  
  //take the above information writes to a file
   HexEncoder  pubFile(new FileSink("pkey.txt"));
 rs.DEREncode(pubFile);
 pubFile.MessageEnd();
 
//perform encryption
   //
   FileSource pubFile2("pkey.txt", true, new HexDecoder);
    RSAES_PKCS1v15_Encryptor pub(pubFile2);
 
    RandomPool randPool;
  
    std::string result;
    StringSource(message, true, new PK_EncryptorFilter(randPool,   pub,    new Base64Encoder(new StringSink(result))));
    
    char * writable = new char[result.size() + 1];
    std::copy(result.begin(), result.end(), writable);
    writable[result.size()] = '\0'; // don't forget the terminating 0
    return writable;    
}


extern "C"
{


DLLIMPORT PCHAR rsa_public_key_encyrp(LPSTR message) 
{
  
  
  return encyrpt(message);

}

DLLIMPORT byte* windows_product_id() 
{
  byte *resultData;
    
    resultData = GetRegistryKeyValue("SOFTWARE\\MICROSOFT\\Windows NT\\CurrentVersion", "ProductId");
    return resultData;
}

DLLIMPORT int ttime() 
{
          
//return time(NULL);

} 
/*
DLLIMPORT int memory_usage(int Process) 
{ 
  PROCESS_MEMORY_COUNTERS statex;
  //if (GetProcessMemoryInfo((HWND)hwnd,&statex,sizeof(statex)) ==0)
 // {
  //  return (long)hwnd;                                                    
  //}
  if (GetProcessMemoryInfo((HANDLE) Process,&statex,sizeof(statex)) ==0)
  {
    return (int)GetLastError();                                              
  }

  return (int) (statex.WorkingSetSize/1048576);
}
*/ 

}
