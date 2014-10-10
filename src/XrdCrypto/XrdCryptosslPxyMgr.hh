#ifndef __CRYPTO_SSLPXYMGR_H__
#define __CRYPTO_SSLPXYMGR_H__
/******************************************************************************/
/*                                                                            */
/*               X r d C r y p t o s s l P x y M g r . h h                    */
/*                                                                            */
/* (c) 2014, G. Ganis / CERN                                                  */
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
/* X509 Proxy functionality interface: SSL version                            */
/*                                                                            */
/* ************************************************************************** */
#include "XrdCrypto/XrdCryptoPxyMgr.hh"

class XrdCryptosslPxyMgr : public XrdCryptoPxyMgr {
public:

   XrdCryptosslPxyMgr() : XrdCryptoPxyMgr() { }
   virtual ~XrdCryptosslPxyMgr() { }

   bool ProxyCertInfo(const void *ext, int &pathlen, bool *haspolicy = 0);
   void SetPathLenConstraint(void *ext, int pathlen);
   //
   // Create proxy certificates
   int CreateProxy(const char *, const char *, XrdProxyOpt_t *,
                      XrdCryptogsiX509Chain *, XrdCryptoRSA **, const char *);
   //
   // Create a proxy certificate request
   int CreateProxyReq(XrdCryptoX509 *, XrdCryptoX509Req **, XrdCryptoRSA **);
   //
   // Sign a proxy certificate request
   int SignProxyReq(XrdCryptoX509 *, XrdCryptoRSA *,
                                             XrdCryptoX509Req *, XrdCryptoX509 **);
   //
   // Get VOMS attributes, if any
   int GetVOMSAttr(XrdCryptoX509 *, XrdOucString &);

private:

};

#endif

