/******************************************************************************/
/*                                                                            */
/*                   X r d S e c g s i P r o x y . c c                        */
/*                                                                            */
/* (c) 2005, G. Ganis / CERN                                                  */
/*                                                                            */
/* This file is part of the XRootD software suite.                            */
/*                                                                            */
/* XRootD is free software: you can redistribute it and/or modify it under    */
/* the terms of the GNU Lesser General Public License as published by the     */
/* Free Software Foundation, either version 3 of the License, or (at your     */
/* option) any later version.                                                 */
/*                                                                            */
/* XRootD is distributed in the hope that it will be useful, but WITHOUT      */
/* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or      */
/* FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public       */
/* License for more details.                                                  */
/*                                                                            */
/* You should have received a copy of the GNU Lesser General Public License   */
/* along with XRootD in a file called COPYING.LESSER (LGPL license) and file  */
/* COPYING (GPL license).  If not, see <http://www.gnu.org/licenses/>.        */
/*                                                                            */
/* The copyright holder's institutional names and contributor's names may not */
/* be used to endorse or promote products derived from this software without  */
/* specific prior written permission of the institution or contributor.       */
/*                                                                            */
/******************************************************************************/

/* ************************************************************************** */
/*                                                                            */
/* Parse X509 entities (certs, chains, proxies, ...)                          */
/*                                                                            */
/* ************************************************************************** */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <pwd.h>
#include <time.h>


#include "XrdOuc/XrdOucString.hh"
#include "XrdSys/XrdSysLogger.hh"
#include "XrdSys/XrdSysError.hh"
#include "XrdSys/XrdSysPwd.hh"

#include "XrdSut/XrdSutAux.hh"

#include "XrdCrypto/XrdCryptoAux.hh"
#include "XrdCrypto/XrdCryptoFactory.hh"
#include "XrdCrypto/XrdCryptoX509.hh"
#include "XrdCrypto/XrdCryptoX509Req.hh"
#include "XrdCrypto/XrdCryptoX509Chain.hh"
#include "XrdCrypto/XrdCryptoX509Crl.hh"

#include "XrdCrypto/XrdCryptogsiX509Chain.hh"

#include "XrdSecgsi/XrdSecgsiTrace.hh"

#define PRT(x) {cerr <<x <<endl;}
#define SafeDelete(x) { if (x) delete x ; x = 0; }
#define SafeDelArray(x) { if (x) delete [] x ; x = 0; }
#define SafeFree(x) { if (x) free(x) ; x = 0; }

typedef XrdOucString String;
typedef XrdCryptogsiX509Chain X509Chain;

//
// enum
enum kModes {
   kM_undef = 0,
   kM_cert = 1,
   kM_chain,
   kM_proxy,
   kM_help
};
const char *gModesStr[] = {
   "kM_undef",
   "kM_cert",
   "kM_chain",
   "kM_proxy",
   "kM_help"
};

//
// Prototypes
//
void Menu();
int  ParseArguments(int argc, char **argv);
bool CheckOption(XrdOucString opt, const char *ref, int &ival);
void Display(XrdCryptoX509 *xp);
int  VerifyChain(X509Chain *xc);

//
// Globals
//
int          Mode     = kM_undef;
bool         Debug = 0;
bool         DumpExtensions = 0;
XrdCryptoFactory *gCryptoFactory = 0;
XrdOucString CryptoMod = "ssl";
XrdCryptoX509ParseFile_t ParseFile = 0;
XrdCryptoX509GetVOMSAttr_t GetVOMSAttr = 0;
XrdCryptoProxyCertInfo_t ProxyCertInfo = 0;
XrdOucString CAdir  = "/etc/grid-security/certificates/";
XrdOucString CRLdir = "/etc/grid-security/certificates/";
XrdOucString DefEEcert = "/.globus/usercert.pem";
XrdOucString DefPXcert = "/tmp/x509up_u";
XrdOucString EEcert = "";
XrdOucString PXcert = "";
// For error logging and tracing
static XrdSysLogger Logger;
static XrdSysError eDest(0,"proxy_");
XrdOucTrace *gsiTrace = 0;

int main( int argc, char **argv )
{
   // Test implemented functionality
   XrdCryptogsiX509Chain *cPXp = 0;
   XrdCryptoX509 *xPXp = 0, *xPXPp = 0;
   int nci = 0;
   int exitrc = 0;

   // Parse arguments
   if (ParseArguments(argc,argv)) {
      exit(1);
   }

   //
   // Initiate error logging and tracing
   eDest.logger(&Logger);
   if (!gsiTrace)
      gsiTrace = new XrdOucTrace(&eDest);
   if (gsiTrace) {
      if (Debug)
        // Medium level
        gsiTrace->What |= (TRACE_Authen | TRACE_Debug);
   }
   //
   // Set debug flags in other modules
   if (Debug) {
      XrdSutSetTrace(sutTRACE_Debug);
      XrdCryptoSetTrace(cryptoTRACE_Debug);
   }

   //
   // Load the crypto factory
   if (!(gCryptoFactory = XrdCryptoFactory::GetCryptoFactory(CryptoMod.c_str()))) {
      PRT(": cannot instantiate factory "<<CryptoMod);
      exit(1);
   }
   if (Debug)
      gCryptoFactory->SetTrace(cryptoTRACE_Debug);

   // Hooks for specific functionality
   if (!(ParseFile = gCryptoFactory->X509ParseFile())) {
      PRT("cannot attach to X509ParseFile function!");
      exit(1);
   }
   if (!(ProxyCertInfo = gCryptoFactory->ProxyCertInfo())) {
      PRT("cannot attach to ProxyCertInfo function!");
      exit(1);
   }
   if (!(GetVOMSAttr = gCryptoFactory->X509GetVOMSAttr())) {
      PRT("cannot attach to X509GetVOMSAttr function!");
      exit(1);
   }

   //
   // Depending on the mode
   switch (Mode) {
   case kM_help:
      //
      // We should not get here ... print the menu and go
      Menu();
      break;
   case kM_cert:
      //
      // Display info about existing cert
      // Parse the proxy file
      cPXp = new XrdCryptogsiX509Chain();
      nci = (*ParseFile)(PXcert.c_str(), cPXp);
      if (nci < 1) {
         PRT("certificate file must have at least one certificate"
                ": found none!");
         break;
      }
      // We examine the first certificate
      xPXp = cPXp->Begin();
      if (xPXp) {
         Display(xPXp);
         if (strstr(xPXp->Subject(), "CN=limited proxy")) {
            xPXPp = cPXp->SearchBySubject(xPXp->Issuer());
            if (xPXPp) {
                Display(xPXPp);
            } else {
                PRT("WARNING: found 'limited proxy' but not the associated proxy!");
            }
         }
      } else {
         PRT( ": proxy certificate not found");
      }
      break;

   case kM_proxy:
      //
      // Examine proxies
      PRT( ": proxy option not implemented");

      break;
   case kM_chain:
      //
      // Examine the chain with and certificate the specified certificate
      // Parse the proxy file
      cPXp = new XrdCryptogsiX509Chain();
      nci = (*ParseFile)(PXcert.c_str(), cPXp);
      if (nci < 1) {
         PRT("certificate file must have at least one certificate"
                ": found none!");
         break;
      }
      // Verify
      PRT( ": chain verified? " << VerifyChain(cPXp) );
      break;
   default:
      //
      // Print menu
      Menu();
   }

   exit(exitrc);
}

XrdOucString GetCApath(const char *cahash)
{
   // Look in the paths defined by CAdir for the certificate file related to
   // 'cahash', in the form <CAdir_entry>/<cahash>.0

   XrdOucString path;
   XrdOucString ent;
   int from = 0;
   while ((from = CAdir.tokenize(ent, from, ',')) != -1) {
      if (ent.length() > 0) {
         path = ent;
         if (!path.endswith('/'))
            path += "/";
         path += cahash;
         if (!path.endswith(".0"))
            path += ".0";
         if (!access(path.c_str(), R_OK))
            break;
      }
      path = "";
   }

   // Done
   return path;
}

// Verify the chain above 'xc'
int VerifyChain(X509Chain *cca)
{
   // The proxy is the first certificate
   XrdCryptoX509 *xc = cca->Begin();
   if (!xc) {
      PRT( ": no certificate found in file");
      return 0;
   }
     
   int verified = 1;
   // Is it self-signed ?
   bool self = (!strcmp(xc->IssuerHash(), xc->SubjectHash())) ? 1 : 0;
   if (!self) {
      XrdOucString inam;
      // We are requested to verify it
      bool notdone = 1;
      // We need to load the issuer(s) CA(s)
      XrdCryptoX509 *xd = xc;
      while (notdone) {
      X509Chain *ch = 0;
      int ncis = -1;
      for (int ha = 0; ha < 2; ha++) {
         inam = GetCApath(xd->IssuerHash(ha));
         if (inam.length() <= 0) continue;
         ch = new X509Chain();
         ncis = (*ParseFile)(inam.c_str(), ch);
         if (ncis >= 1) break;
         SafeDelete(ch);
      }
      if (ncis < 1) break;
      XrdCryptoX509 *xi = ch->Begin();
      while (xi) {
         if (!strcmp(xd->IssuerHash(), xi->SubjectHash()))
            break;
         xi = ch->Next();
      }
      if (xi) {
         // Add the certificate to the requested CA chain
         ch->Remove(xi);
         cca->PutInFront(xi);
         SafeDelete(ch);
         // We may be over
         if (!strcmp(xi->IssuerHash(), xi->SubjectHash())) {
            notdone = 0;
            break;
         } else {
            // This becomes the daughter
            xd = xi;
         }
      } else {
         break;
      }
      if (!notdone) {
         // Verify the chain
         X509Chain::EX509ChainErr e;
         x509ChainVerifyOpt_t vopt = {kOptsCheckSubCA, 0, -1, 0};
         if (!(verified = cca->Verify(e, &vopt)))
            PRT("CA certificate not self-signed: verification failed ("<<xc->SubjectHash()<<")");
         } else {
            PRT("CA certificate not self-signed: cannot verify integrity ("<<xc->SubjectHash()<<")");
         }
      }
   }
   return verified;
}

int ParseArguments(int argc, char **argv)
{
   // Parse application arguments filling relevant global variables

   // Number of arguments
   if (argc < 0 || !argv[0]) {
      PRT("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
      PRT("+ Insufficient number or arguments!                        +");
      PRT("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
      // Print main menu
      Menu();
      return 1;
   }
   --argc;
   ++argv;

   //
   // Loop over arguments
   while ((argc >= 0) && (*argv)) {

      XrdOucString opt = "";
      int ival = -1;
      if(*(argv)[0] == '-') {

         opt = *argv;
         opt.erase(0,1);
         if (CheckOption(opt,"h",ival) || CheckOption(opt,"help",ival) ||
             CheckOption(opt,"menu",ival)) {
            Mode = kM_help;
         } else if (CheckOption(opt,"debug",ival)) {
            Debug = ival;
         } else if (CheckOption(opt,"f",ival)) {
            --argc;
            ++argv;
            if (argc >= 0 && (*argv && *(argv)[0] != '-')) {
               PXcert = *argv;
            } else {
               PRT("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
               PRT("+ Option '-f' requires a proxy file name: ignoring         +");
               PRT("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
               argc++;
               argv--;
            }
         } else if (CheckOption(opt,"file",ival)) {
            --argc;
            ++argv;
            if (argc >= 0 && (*argv && *(argv)[0] != '-')) {
               PXcert = *argv;
            } else {
               PRT("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
               PRT("+ Option '-file' requires a proxy file name: ignoring      +");
               PRT("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
               argc++;
               argv--;
            }
         } else if (CheckOption(opt,"cert",ival)) {
            --argc;
            ++argv;
            if (argc >= 0 && (*argv && *(argv)[0] != '-')) {
               EEcert = *argv;
            } else {
               PRT("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
               PRT("+ Option '-cert' requires a cert file name: ignoring       +");
               PRT("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
               argc++;
               argv--;
            }
         } else if (CheckOption(opt,"certdir",ival)) {
            --argc;
            ++argv;
            if (argc >= 0 && (*argv && *(argv)[0] != '-')) {
               CAdir = *argv;
            } else {
               PRT("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
               PRT("+ Option '-certdir' requires a dir path: ignoring          +");
               PRT("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
               argc++;
               argv--;
            }
         } else if (CheckOption(opt,"e",ival) || CheckOption(opt,"extensions",ival)) {
            DumpExtensions = 1;
         } else {
            PRT("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
            PRT("+ Ignoring unrecognized option: "<<*argv);
            PRT("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
         }

      } else {
         //
         // Mode keyword
         opt = *argv;
         if (CheckOption(opt,"cert",ival)) {
            Mode = kM_cert;
         } else if (CheckOption(opt,"chain",ival)) {
            Mode = kM_chain;
         } else if (CheckOption(opt,"proxy",ival)) {
            Mode = kM_proxy;
         } else if (CheckOption(opt,"help",ival)) {
            Mode = kM_help;
         } else {
            PXcert = opt;
         }
      }
      --argc;
      ++argv;
   }

   //
   // Default mode 'cert'
   Mode = (Mode == 0) ? kM_cert : Mode;

   //
   // If help mode, print menu and exit
   if (Mode == kM_help) {
      // Print main menu
      Menu();
      return 1;
   }

   //
   // we may need later
   XrdSysPwd thePwd;

   //
   // Check proxy file
   if (PXcert.length() <= 0) {
      // Cannot get info about current user
      PRT("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
      PRT("+ A cert file is required - exit ");
      PRT("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
      return 1;
   }
   //
   // Expand Path
   XrdSutExpand(PXcert);
   // Get info
   struct stat st;
   if (stat(PXcert.c_str(),&st) != 0) {
      // Path exists but we cannot access it - exit
      PRT("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
      PRT("+ file: "<<PXcert.c_str()<<" cannot be accessed (errno: " << (int) errno << ")");
      PRT("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
      return 1;
   }

   //
   // Check certificate file
   if (EEcert.length()) {
      //
      // Expand Path
      XrdSutExpand(EEcert);
      // Get info
      if (stat(EEcert.c_str(),&st) != 0) {
         PRT("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
         PRT("+ Cannot access certificate file: "<<EEcert.c_str());
         PRT("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
         return 1;
      }
   }

   return 0;
}



void Menu()
{
   // Print the menu

   PRT(" ");
   PRT(" xrdgsix509: application to examine X509 entities ");
   PRT(" ");
   PRT(" Syntax:");
   PRT(" ");
   PRT(" xrdgsix509 [-h] [<mode>] [options] ");
   PRT(" ");
   PRT(" ");
   PRT("  -h   display this menu");
   PRT(" ");
   PRT(" mode (cert, chain, proxy) [cert]");
   PRT(" ");
   PRT("       cert: examine file");
   PRT(" ");
   PRT("       chain: examine chain");
   PRT(" ");
   PRT("       proxy: examine proxy");
   PRT(" ");
   PRT(" options:");
   PRT(" ");
   PRT("    -debug                 Print more information while running this"
                                   " query (use if something goes wrong) ");
   PRT(" ");
   PRT("    -f,-file <file>        location of file to be examined (lowest entiity)");
   PRT(" ");
   PRT("    -c, -cert <file>       Location of next-levet certificate");
   PRT(" ");
   PRT("    -certdir  <dir>        Non-standard location of directory"
                                   " with information about known CAs");
   PRT("    -e, -extensions        low-level dump of certificate extensions");
   PRT(" ");
}

bool CheckOption(XrdOucString opt, const char *ref, int &ival)
{
   // Check opt against ref
   // Return 1 if ok, 0 if not
   // Fills ival = 1 if match is exact
   //       ival = 0 if match is exact with no<ref>
   //       ival = -1 in the other cases
   bool rc = 0;

   int lref = (ref) ? strlen(ref) : 0;
   if (!lref)
      return rc;
   XrdOucString noref = ref;
   noref.insert("no",0);

   ival = -1;
   if (opt == ref) {
      ival = 1;
      rc = 1;
   } else if (opt == noref) {
      ival = 0;
      rc = 1;
   }

   return rc;
}

void Display(XrdCryptoX509 *xp)
{
   // display content of proxy certificate

   PRT("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
   if (!xp) {
      PRT(" Empty certificate! ");
      return;
   }

   // File
   PRT("file        : "<<PXcert);
   // Type
   if (xp->type != XrdCryptoX509::kProxy) {
      PRT("type        : "<<xp->Type());
   } else {
      PRT("type        : "<<xp->Type()<<" ("<<xp->ProxyType()<<")");
   }

   // Issuer
   PRT("issuer      : "<<xp->Issuer());
   // Subject
   PRT("subject     : "<<xp->Subject());
   // Path length field
   int pathlen = 0; bool b;
   if(xp->GetExtension(gsiProxyCertInfo_OID))
      (*ProxyCertInfo)(xp->GetExtension(gsiProxyCertInfo_OID), pathlen, &b);
   else
      (*ProxyCertInfo)(xp->GetExtension(gsiProxyCertInfo_OLD_OID), pathlen, &b);
   PRT("path length : "<<pathlen);
   // Key strength
   PRT("bits        : "<<xp->BitStrength());
   // Time left
   int now = int(time(0)) - XrdCryptoTZCorr();
   int tl = xp->NotAfter() - now;
   int hh = (tl >= 3600) ? (tl/3600) : 0; tl -= (hh*3600);
   int mm = (tl >= 60)   ? (tl/60)   : 0; tl -= (mm*60);
   int ss = (tl >= 0)    ?  tl       : 0;
   PRT("time left   : "<<hh<<"h:"<<mm<<"m:"<<ss<<"s");
   PRT("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
   // Show VOMS attributes, if any
   XrdOucString vatts, vat;
   if ((*GetVOMSAttr)(xp, vatts) == 0) {
      int from = 0;
      while ((from = vatts.tokenize(vat, from, ',')) != -1) {
         if (vat.length() > 0) PRT("VOMS attributes: "<<vat);
      }
      PRT("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
   }
   // Dump extensions if requested
   if (DumpExtensions) {
      gCryptoFactory->SetTrace(cryptoTRACE_Debug);
      xp->DumpExtensions(0);
      PRT("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
   }
}
