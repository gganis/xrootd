/******************************************************************************/
/*                                                                            */
/*                  X r d C r y p t o P x y M g r . c c                       */
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
/* X509 Proxy functionality interface                                         */
/*                                                                            */
/* ************************************************************************** */
#include "XrdCrypto/XrdCryptoAux.hh"
#include "XrdCrypto/XrdCryptoPxyMgr.hh"

//_____________________________________________________________________________
bool XrdCryptoPxyMgr::ProxyCertInfo(const void *, int &, bool *)
{
   // Check ProxyCertInfo extension
   ABSTRACTMETHOD("XrdCryptoPxyMgr::ProxyCertInfo");
   return false;
}

//_____________________________________________________________________________
void XrdCryptoPxyMgr::SetPathLenConstraint(void *, int)
{
   // Set path length constraint in proxy
   ABSTRACTMETHOD("XrdCryptoPxyMgr::SetPathLenConstraint");
   return;
}

//_____________________________________________________________________________
int XrdCryptoPxyMgr::CreateProxy(const char *, const char *, XrdProxyOpt_t *,
                                 XrdCryptogsiX509Chain *, XrdCryptoRSA **, const char *)
{
   // Create a proxy certificate
   ABSTRACTMETHOD("XrdCryptoPxyMgr::CreateProxy");
   return -1;
}

//_____________________________________________________________________________
int XrdCryptoPxyMgr::CreateProxyReq(XrdCryptoX509 *, XrdCryptoX509Req **, XrdCryptoRSA **)
{
   // Create a proxy certificate
   ABSTRACTMETHOD("XrdCryptoPxyMgr::CreateProxyReq");
   return -1;
}

//_____________________________________________________________________________
int XrdCryptoPxyMgr::SignProxyReq(XrdCryptoX509 *, XrdCryptoRSA *,
                                                  XrdCryptoX509Req *, XrdCryptoX509 **)
{
   // Create a proxy certificate
   ABSTRACTMETHOD("XrdCryptoPxyMgr::SignProxyReq");
   return -1;
}

//_____________________________________________________________________________
int XrdCryptoPxyMgr::GetVOMSAttr(XrdCryptoX509 *, XrdOucString &)
{
   // Create a proxy certificate
   ABSTRACTMETHOD("XrdCryptoPxyMgr::GetVOMSAttr");
   return -1;
}
