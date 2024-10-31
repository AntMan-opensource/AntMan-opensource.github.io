
















































































static const int tight2turbo_qual[10] = {
   15, 29, 41, 42, 62, 77, 79, 86, 92, 100 };

static const int tight2turbo_subsamp[10] = {
   1, 1, 1, 2, 2, 2, 0, 0, 0, 0 };


static void rfbProcessClientProtocolVersion(rfbClientPtr cl);
static void rfbProcessClientNormalMessage(rfbClientPtr cl);
static void rfbProcessClientInitMessage(rfbClientPtr cl);


void rfbIncrClientRef(rfbClientPtr cl)
{
  LOCK(cl->refCountMutex);
  cl->refCount++;
  UNLOCK(cl->refCountMutex);
}

void rfbDecrClientRef(rfbClientPtr cl)
{
  LOCK(cl->refCountMutex);
  cl->refCount--;
  if(cl->refCount<=0) 
    TSIGNAL(cl->deleteCond);
  UNLOCK(cl->refCountMutex);
}

void rfbIncrClientRef(rfbClientPtr cl) {}
void rfbDecrClientRef(rfbClientPtr cl) {}



static MUTEX(rfbClientListMutex);


struct rfbClientIterator {
  rfbClientPtr next;
  rfbScreenInfoPtr screen;
  rfbBool closedToo;
};

void rfbClientListInit(rfbScreenInfoPtr rfbScreen)
{
    if(sizeof(rfbBool)!=1) {
        
        fprintf(stderr,"rfbBool's size is not 1 (%d)!\n",(int)sizeof(rfbBool));
	
	exit(1);
    }
    rfbScreen->clientHead = NULL;
    INIT_MUTEX(rfbClientListMutex);
}

rfbClientIteratorPtr rfbGetClientIterator(rfbScreenInfoPtr rfbScreen)
{
  rfbClientIteratorPtr i = (rfbClientIteratorPtr)malloc(sizeof(struct rfbClientIterator));
  if(i) {
    i->next = NULL;
    i->screen = rfbScreen;
    i->closedToo = FALSE;
  }
  return i;
}

rfbClientIteratorPtr rfbGetClientIteratorWithClosed(rfbScreenInfoPtr rfbScreen)
{
  rfbClientIteratorPtr i = (rfbClientIteratorPtr)malloc(sizeof(struct rfbClientIterator));
  if(i) {
    i->next = NULL;
    i->screen = rfbScreen;
    i->closedToo = TRUE;
  }
  return i;
}

rfbClientPtr rfbClientIteratorHead(rfbClientIteratorPtr i)
{

  if(i->next != 0) {
    rfbDecrClientRef(i->next);
    rfbIncrClientRef(i->screen->clientHead);
  }

  LOCK(rfbClientListMutex);
  i->next = i->screen->clientHead;
  UNLOCK(rfbClientListMutex);
  return i->next;
}

rfbClientPtr rfbClientIteratorNext(rfbClientIteratorPtr i)
{
  if(i->next == 0) {
    LOCK(rfbClientListMutex);
    i->next = i->screen->clientHead;
    UNLOCK(rfbClientListMutex);
  } else {
    rfbClientPtr cl = i->next;
    i->next = i->next->next;
    rfbDecrClientRef(cl);
  }


    if(!i->closedToo)
      while(i->next && i->next->sock<0)
        i->next = i->next->next;
    if(i->next)
      rfbIncrClientRef(i->next);


    return i->next;
}

void rfbReleaseClientIterator(rfbClientIteratorPtr iterator)
{
  if(iterator->next) rfbDecrClientRef(iterator->next);
  free(iterator);
}




void rfbNewClientConnection(rfbScreenInfoPtr rfbScreen, rfbSocket sock)

{
    rfbNewClient(rfbScreen,sock);
}




rfbClientPtr rfbReverseConnection(rfbScreenInfoPtr rfbScreen, char *host, int port)


{
    rfbSocket sock;
    rfbClientPtr cl;

    if ((sock = rfbConnect(rfbScreen, host, port)) < 0)
        return (rfbClientPtr)NULL;

    cl = rfbNewClient(rfbScreen, sock);

    if (cl) {
        cl->reverseConnection = TRUE;
    }

    return cl;
}


void rfbSetProtocolVersion(rfbScreenInfoPtr rfbScreen, int major_, int minor_)
{
    
    
    if ((major_==3) && (minor_ > 2 && minor_ < 9))
    {
      rfbScreen->protocolMajorVersion = major_;
      rfbScreen->protocolMinorVersion = minor_;
    }
    else rfbLog("rfbSetProtocolVersion(%d,%d) set to invalid values\n", major_, minor_);
}



static rfbClientPtr rfbNewTCPOrUDPClient(rfbScreenInfoPtr rfbScreen, rfbSocket sock, rfbBool isUDP)


{
    rfbProtocolVersionMsg pv;
    rfbClientIteratorPtr iterator;
    rfbClientPtr cl,cl_;

    struct sockaddr_storage addr;

    struct sockaddr_in addr;

    socklen_t addrlen = sizeof(addr);
    rfbProtocolExtension* extension;

    cl = (rfbClientPtr)calloc(sizeof(rfbClientRec),1);

    if (!cl)
        return NULL;

    cl->screen = rfbScreen;
    cl->sock = sock;
    cl->viewOnly = FALSE;
    
    cl->scaledScreen = rfbScreen;
    cl->scaledScreen->scaledScreenRefCount++;

    rfbResetStats(cl);

    cl->clientData = NULL;
    cl->clientGoneHook = rfbDoNothingWithClient;

    if(isUDP) {
      rfbLog(" accepted UDP client\n");
	} else {

		char host[1024];

      int one=1;
      size_t otherClientsCount = 0;

      getpeername(sock, (struct sockaddr *)&addr, &addrlen);

      if(getnameinfo((struct sockaddr*)&addr, addrlen, host, sizeof(host), NULL, 0, NI_NUMERICHOST) != 0) {
	rfbLogPerror("rfbNewClient: error in getnameinfo");
	cl->host = strdup("");
      }
      else cl->host = strdup(host);

      cl->host = strdup(inet_ntoa(addr.sin_addr));


      iterator = rfbGetClientIterator(rfbScreen);
      while ((cl_ = rfbClientIteratorNext(iterator)) != NULL)
	  ++otherClientsCount;
      rfbReleaseClientIterator(iterator);
      rfbLog("  %lu other clients\n", (unsigned long) otherClientsCount);

      if(!rfbSetNonBlocking(sock)) {
	rfbCloseSocket(sock);
	return NULL;
      }

      if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof(one)) < 0) {
	rfbLogPerror("setsockopt failed: can't set TCP_NODELAY flag, non TCP socket?");
      }

      FD_SET(sock,&(rfbScreen->allFds));
		rfbScreen->maxFd = rfbMax(sock,rfbScreen->maxFd);

      INIT_MUTEX(cl->outputMutex);
      INIT_MUTEX(cl->refCountMutex);
      INIT_MUTEX(cl->sendMutex);
      INIT_COND(cl->deleteCond);

      cl->state = RFB_PROTOCOL_VERSION;

      cl->reverseConnection = FALSE;
      cl->readyForSetColourMapEntries = FALSE;
      cl->useCopyRect = FALSE;
      cl->preferredEncoding = -1;
      cl->correMaxWidth = 48;
      cl->correMaxHeight = 48;

      cl->zrleData = NULL;


      cl->copyRegion = sraRgnCreate();
      cl->copyDX = 0;
      cl->copyDY = 0;
   
      cl->modifiedRegion = sraRgnCreateRect(0,0,rfbScreen->width,rfbScreen->height);

      INIT_MUTEX(cl->updateMutex);
      INIT_COND(cl->updateCond);

      cl->requestedRegion = sraRgnCreate();

      cl->format = cl->screen->serverFormat;
      cl->translateFn = rfbTranslateNone;
      cl->translateLookupTable = NULL;

      LOCK(rfbClientListMutex);

      cl->refCount = 0;

      cl->next = rfbScreen->clientHead;
      cl->prev = NULL;
      if (rfbScreen->clientHead)
        rfbScreen->clientHead->prev = cl;

      rfbScreen->clientHead = cl;
      UNLOCK(rfbClientListMutex);


      cl->tightQualityLevel = -1;

      cl->tightCompressLevel = TIGHT_DEFAULT_COMPRESSION;
      cl->turboSubsampLevel = TURBO_DEFAULT_SUBSAMP;
      {
	int i;
	for (i = 0; i < 4; i++)
          cl->zsActive[i] = FALSE;
      }



      cl->fileTransfer.fd = -1;

      cl->enableCursorShapeUpdates = FALSE;
      cl->enableCursorPosUpdates = FALSE;
      cl->useRichCursorEncoding = FALSE;
      cl->enableLastRectEncoding = FALSE;
      cl->enableKeyboardLedState = FALSE;
      cl->enableSupportedMessages = FALSE;
      cl->enableSupportedEncodings = FALSE;
      cl->enableServerIdentity = FALSE;
      cl->lastKeyboardLedState = -1;
      cl->cursorX = rfbScreen->cursorX;
      cl->cursorY = rfbScreen->cursorY;
      cl->useNewFBSize = FALSE;
      cl->useExtDesktopSize = FALSE;
      cl->requestedDesktopSizeChange = 0;
      cl->lastDesktopSizeChangeError = 0;


      cl->compStreamInited = FALSE;
      cl->compStream.total_in = 0;
      cl->compStream.total_out = 0;
      cl->compStream.zalloc = Z_NULL;
      cl->compStream.zfree = Z_NULL;
      cl->compStream.opaque = Z_NULL;

      cl->zlibCompressLevel = 5;


      cl->progressiveSliceY = 0;

      cl->extensions = NULL;

      cl->lastPtrX = -1;


      cl->pipe_notify_client_thread[0] = -1;
      cl->pipe_notify_client_thread[1] = -1;



      
      if (!webSocketsCheck(cl)) {
        
        rfbCloseClient(cl);
        rfbClientConnectionGone(cl);
        return NULL;
      }


      sprintf(pv,rfbProtocolVersionFormat,rfbScreen->protocolMajorVersion,  rfbScreen->protocolMinorVersion);

      if (rfbWriteExact(cl, pv, sz_rfbProtocolVersionMsg) < 0) {
        rfbLogPerror("rfbNewClient: write");
        rfbCloseClient(cl);
	rfbClientConnectionGone(cl);
        return NULL;
      }
    }

    for(extension = rfbGetExtensionIterator(); extension;
	    extension=extension->next) {
	void* data = NULL;
	
	if(extension->newClient && extension->newClient(cl, &data))
		rfbEnableExtension(cl, extension, data);
    }
    rfbReleaseExtensionIterator();

    switch (cl->screen->newClientHook(cl)) {
    case RFB_CLIENT_ON_HOLD:
	    cl->onHold = TRUE;
	    break;
    case RFB_CLIENT_ACCEPT:
	    cl->onHold = FALSE;
	    break;
    case RFB_CLIENT_REFUSE:
	    rfbCloseClient(cl);
	    rfbClientConnectionGone(cl);
	    cl = NULL;
	    break;
    }
    return cl;
}

rfbClientPtr rfbNewClient(rfbScreenInfoPtr rfbScreen, rfbSocket sock)

{
  return(rfbNewTCPOrUDPClient(rfbScreen,sock,FALSE));
}

rfbClientPtr rfbNewUDPClient(rfbScreenInfoPtr rfbScreen)
{
  return((rfbScreen->udpClient= rfbNewTCPOrUDPClient(rfbScreen,rfbScreen->udpSock,TRUE)));
}



void rfbClientConnectionGone(rfbClientPtr cl)
{

    int i;


    LOCK(rfbClientListMutex);

    if (cl->prev)
        cl->prev->next = cl->next;
    else cl->screen->clientHead = cl->next;
    if (cl->next)
        cl->next->prev = cl->prev;

    UNLOCK(rfbClientListMutex);


    if(cl->screen->backgroundLoop != FALSE) {
      int i;
      do {
	LOCK(cl->refCountMutex);
	i=cl->refCount;
	if(i>0)
	  WAIT(cl->deleteCond,cl->refCountMutex);
	UNLOCK(cl->refCountMutex);
      } while(i>0);
    }


    if(cl->sock != RFB_INVALID_SOCKET)
	rfbCloseSocket(cl->sock);

    if (cl->scaledScreen!=NULL)
        cl->scaledScreen->scaledScreenRefCount--;


    rfbFreeZrleData(cl);


    rfbFreeUltraData(cl);

    
    free(cl->beforeEncBuf);
    free(cl->afterEncBuf);

    if(cl->sock != RFB_INVALID_SOCKET)
       FD_CLR(cl->sock,&(cl->screen->allFds));

    cl->clientGoneHook(cl);

    rfbLog("Client %s gone\n",cl->host);
    free(cl->host);


    
    if ( cl->compStreamInited ) {
	deflateEnd( &(cl->compStream) );
    }


    for (i = 0; i < 4; i++) {
	if (cl->zsActive[i])
	    deflateEnd(&cl->zsStruct[i]);
    }



    if (cl->screen->pointerClient == cl)
        cl->screen->pointerClient = NULL;

    sraRgnDestroy(cl->modifiedRegion);
    sraRgnDestroy(cl->requestedRegion);
    sraRgnDestroy(cl->copyRegion);

    if (cl->translateLookupTable) free(cl->translateLookupTable);

    TINI_COND(cl->updateCond);
    TINI_MUTEX(cl->updateMutex);

    
    LOCK(cl->outputMutex);
    UNLOCK(cl->outputMutex);
    TINI_MUTEX(cl->outputMutex);

    LOCK(cl->sendMutex);
    UNLOCK(cl->sendMutex);
    TINI_MUTEX(cl->sendMutex);


    close(cl->pipe_notify_client_thread[0]);
    close(cl->pipe_notify_client_thread[1]);


    rfbPrintStats(cl);
    rfbResetStats(cl);

    free(cl);
}




void rfbProcessClientMessage(rfbClientPtr cl)
{
    switch (cl->state) {
    case RFB_PROTOCOL_VERSION:
        rfbProcessClientProtocolVersion(cl);
        return;
    case RFB_SECURITY_TYPE:
        rfbProcessClientSecurityType(cl);
        return;
    case RFB_AUTHENTICATION:
        rfbAuthProcessClientMessage(cl);
        return;
    case RFB_INITIALISATION:
    case RFB_INITIALISATION_SHARED:
        rfbProcessClientInitMessage(cl);
        return;
    default:
        rfbProcessClientNormalMessage(cl);
        return;
    }
}




static void rfbProcessClientProtocolVersion(rfbClientPtr cl)
{
    rfbProtocolVersionMsg pv;
    int n, major_, minor_;

    if ((n = rfbReadExact(cl, pv, sz_rfbProtocolVersionMsg)) <= 0) {
        if (n == 0)
            rfbLog("rfbProcessClientProtocolVersion: client gone\n");
        else rfbLogPerror("rfbProcessClientProtocolVersion: read");
        rfbCloseClient(cl);
        return;
    }

    pv[sz_rfbProtocolVersionMsg] = 0;
    if (sscanf(pv,rfbProtocolVersionFormat,&major_,&minor_) != 2) {
	rfbErr("rfbProcessClientProtocolVersion: not a valid RFB client: %s\n", pv);
	rfbCloseClient(cl);
	return;
    }
    rfbLog("Client Protocol Version %d.%d\n", major_, minor_);

    if (major_ != rfbProtocolMajorVersion) {
        rfbErr("RFB protocol version mismatch - server %d.%d, client %d.%d", cl->screen->protocolMajorVersion, cl->screen->protocolMinorVersion, major_,minor_);

        rfbCloseClient(cl);
        return;
    }

    
    
    cl->protocolMajorVersion = major_;
    cl->protocolMinorVersion = minor_;
    
    rfbLog("Protocol version sent %d.%d, using %d.%d\n", major_, minor_, rfbProtocolMajorVersion, cl->protocolMinorVersion);

    rfbAuthNewClient(cl);
}


void rfbClientSendString(rfbClientPtr cl, const char *reason)
{
    char *buf;
    int len = strlen(reason);

    rfbLog("rfbClientSendString(\"%s\")\n", reason);

    buf = (char *)malloc(4 + len);
    if (buf) {
        ((uint32_t *)buf)[0] = Swap32IfLE(len);
        memcpy(buf + 4, reason, len);

        if (rfbWriteExact(cl, buf, 4 + len) < 0)
            rfbLogPerror("rfbClientSendString: write");
        free(buf);
    }

    rfbCloseClient(cl);
}



void rfbClientConnFailed(rfbClientPtr cl, const char *reason)

{
    char *buf;
    int len = strlen(reason);

    rfbLog("rfbClientConnFailed(\"%s\")\n", reason);

    buf = (char *)malloc(8 + len);
    if (buf) {
        ((uint32_t *)buf)[0] = Swap32IfLE(rfbConnFailed);
        ((uint32_t *)buf)[1] = Swap32IfLE(len);
        memcpy(buf + 8, reason, len);

        if (rfbWriteExact(cl, buf, 8 + len) < 0)
            rfbLogPerror("rfbClientConnFailed: write");
        free(buf);
    }

    rfbCloseClient(cl);
}




static void rfbProcessClientInitMessage(rfbClientPtr cl)
{
    rfbClientInitMsg ci;
    union {
        char buf[256];
        rfbServerInitMsg si;
    } u;
    int len, n;
    rfbClientIteratorPtr iterator;
    rfbClientPtr otherCl;
    rfbExtensionData* extension;

    if (cl->state == RFB_INITIALISATION_SHARED) {
        
        ci.shared = 1;
        
        cl->state = RFB_INITIALISATION;
    } else {
        if ((n = rfbReadExact(cl, (char *)&ci,sz_rfbClientInitMsg)) <= 0) {
            if (n == 0)
                rfbLog("rfbProcessClientInitMessage: client gone\n");
            else rfbLogPerror("rfbProcessClientInitMessage: read");
            rfbCloseClient(cl);
            return;
        }
    }

    memset(u.buf,0,sizeof(u.buf));

    u.si.framebufferWidth = Swap16IfLE(cl->screen->width);
    u.si.framebufferHeight = Swap16IfLE(cl->screen->height);
    u.si.format = cl->screen->serverFormat;
    u.si.format.redMax = Swap16IfLE(u.si.format.redMax);
    u.si.format.greenMax = Swap16IfLE(u.si.format.greenMax);
    u.si.format.blueMax = Swap16IfLE(u.si.format.blueMax);

    strncpy(u.buf + sz_rfbServerInitMsg, cl->screen->desktopName, 127);
    len = strlen(u.buf + sz_rfbServerInitMsg);
    u.si.nameLength = Swap32IfLE(len);

    if (rfbWriteExact(cl, u.buf, sz_rfbServerInitMsg + len) < 0) {
        rfbLogPerror("rfbProcessClientInitMessage: write");
        rfbCloseClient(cl);
        return;
    }

    for(extension = cl->extensions; extension;) {
	rfbExtensionData* next = extension->next;
	if(extension->extension->init && !extension->extension->init(cl, extension->data))
	    
	    rfbDisableExtension(cl, extension->extension);
	extension = next;
    }

    cl->state = RFB_NORMAL;

    if (!cl->reverseConnection && (cl->screen->neverShared || (!cl->screen->alwaysShared && !ci.shared))) {

        if (cl->screen->dontDisconnect) {
            iterator = rfbGetClientIterator(cl->screen);
            while ((otherCl = rfbClientIteratorNext(iterator)) != NULL) {
                if ((otherCl != cl) && (otherCl->state == RFB_NORMAL)) {
                    rfbLog("-dontdisconnect: Not shared & existing client\n");
                    rfbLog("  refusing new client %s\n", cl->host);
                    rfbCloseClient(cl);
                    rfbReleaseClientIterator(iterator);
                    return;
                }
            }
            rfbReleaseClientIterator(iterator);
        } else {
            iterator = rfbGetClientIterator(cl->screen);
            while ((otherCl = rfbClientIteratorNext(iterator)) != NULL) {
                if ((otherCl != cl) && (otherCl->state == RFB_NORMAL)) {
                    rfbLog("Not shared - closing connection to client %s\n", otherCl->host);
                    rfbCloseClient(otherCl);
                }
            }
            rfbReleaseClientIterator(iterator);
        }
    }
}


static rfbBool rectSwapIfLEAndClip(uint16_t* x,uint16_t* y,uint16_t* w,uint16_t* h, rfbClientPtr cl)
{
	int x1=Swap16IfLE(*x);
	int y1=Swap16IfLE(*y);
	int w1=Swap16IfLE(*w);
	int h1=Swap16IfLE(*h);

	rfbScaledCorrection(cl->scaledScreen, cl->screen, &x1, &y1, &w1, &h1, "rectSwapIfLEAndClip");
	*x = x1;
	*y = y1;
	*w = w1;
	*h = h1;

	if(*w>cl->screen->width-*x)
		*w=cl->screen->width-*x;
	
	if(*w>cl->screen->width-*x)
		return FALSE;
	if(*h>cl->screen->height-*y)
		*h=cl->screen->height-*y;
	if(*h>cl->screen->height-*y)
		return FALSE;

	return TRUE;
}



rfbBool rfbSendKeyboardLedState(rfbClientPtr cl)
{
    rfbFramebufferUpdateRectHeader rect;

    if (cl->ublen + sz_rfbFramebufferUpdateRectHeader > UPDATE_BUF_SIZE) {
        if (!rfbSendUpdateBuf(cl))
            return FALSE;
    }

    rect.encoding = Swap32IfLE(rfbEncodingKeyboardLedState);
    rect.r.x = Swap16IfLE(cl->lastKeyboardLedState);
    rect.r.y = 0;
    rect.r.w = 0;
    rect.r.h = 0;

    memcpy(&cl->updateBuf[cl->ublen], (char *)&rect, sz_rfbFramebufferUpdateRectHeader);
    cl->ublen += sz_rfbFramebufferUpdateRectHeader;

    rfbStatRecordEncodingSent(cl, rfbEncodingKeyboardLedState, sz_rfbFramebufferUpdateRectHeader, sz_rfbFramebufferUpdateRectHeader);

    if (!rfbSendUpdateBuf(cl))
        return FALSE;

    return TRUE;
}






rfbBool rfbSendSupportedMessages(rfbClientPtr cl)
{
    rfbFramebufferUpdateRectHeader rect;
    rfbSupportedMessages msgs;

    if (cl->ublen + sz_rfbFramebufferUpdateRectHeader + sz_rfbSupportedMessages > UPDATE_BUF_SIZE) {
        if (!rfbSendUpdateBuf(cl))
            return FALSE;
    }

    rect.encoding = Swap32IfLE(rfbEncodingSupportedMessages);
    rect.r.x = 0;
    rect.r.y = 0;
    rect.r.w = Swap16IfLE(sz_rfbSupportedMessages);
    rect.r.h = 0;

    memcpy(&cl->updateBuf[cl->ublen], (char *)&rect, sz_rfbFramebufferUpdateRectHeader);
    cl->ublen += sz_rfbFramebufferUpdateRectHeader;

    memset((char *)&msgs, 0, sz_rfbSupportedMessages);
    rfbSetBit(msgs.client2server, rfbSetPixelFormat);
    rfbSetBit(msgs.client2server, rfbFixColourMapEntries);
    rfbSetBit(msgs.client2server, rfbSetEncodings);
    rfbSetBit(msgs.client2server, rfbFramebufferUpdateRequest);
    rfbSetBit(msgs.client2server, rfbKeyEvent);
    rfbSetBit(msgs.client2server, rfbPointerEvent);
    rfbSetBit(msgs.client2server, rfbClientCutText);
    rfbSetBit(msgs.client2server, rfbFileTransfer);
    rfbSetBit(msgs.client2server, rfbSetScale);
    
    
    
    rfbSetBit(msgs.client2server, rfbPalmVNCSetScaleFactor);

    rfbSetBit(msgs.server2client, rfbFramebufferUpdate);
    rfbSetBit(msgs.server2client, rfbSetColourMapEntries);
    rfbSetBit(msgs.server2client, rfbBell);
    rfbSetBit(msgs.server2client, rfbServerCutText);
    rfbSetBit(msgs.server2client, rfbResizeFrameBuffer);
    rfbSetBit(msgs.server2client, rfbPalmVNCReSizeFrameBuffer);
    rfbSetBit(msgs.client2server, rfbSetDesktopSize);

    if (cl->screen->xvpHook) {
        rfbSetBit(msgs.client2server, rfbXvp);
        rfbSetBit(msgs.server2client, rfbXvp);
    }

    memcpy(&cl->updateBuf[cl->ublen], (char *)&msgs, sz_rfbSupportedMessages);
    cl->ublen += sz_rfbSupportedMessages;

    rfbStatRecordEncodingSent(cl, rfbEncodingSupportedMessages, sz_rfbFramebufferUpdateRectHeader+sz_rfbSupportedMessages, sz_rfbFramebufferUpdateRectHeader+sz_rfbSupportedMessages);

    if (!rfbSendUpdateBuf(cl))
        return FALSE;

    return TRUE;
}





rfbBool rfbSendSupportedEncodings(rfbClientPtr cl)
{
    rfbFramebufferUpdateRectHeader rect;
    static uint32_t supported[] = {
        rfbEncodingRaw, rfbEncodingCopyRect, rfbEncodingRRE, rfbEncodingCoRRE, rfbEncodingHextile,  rfbEncodingZlib, rfbEncodingZRLE, rfbEncodingZYWRLE,   rfbEncodingTight,   rfbEncodingTightPng,  rfbEncodingUltra, rfbEncodingUltraZip, rfbEncodingXCursor, rfbEncodingRichCursor, rfbEncodingPointerPos, rfbEncodingLastRect, rfbEncodingNewFBSize, rfbEncodingExtDesktopSize, rfbEncodingKeyboardLedState, rfbEncodingSupportedMessages, rfbEncodingSupportedEncodings, rfbEncodingServerIdentity, };



























    uint32_t nEncodings = sizeof(supported) / sizeof(supported[0]), i;

    

    if (cl->ublen + sz_rfbFramebufferUpdateRectHeader + (nEncodings * sizeof(uint32_t)) > UPDATE_BUF_SIZE) {
        if (!rfbSendUpdateBuf(cl))
            return FALSE;
    }

    rect.encoding = Swap32IfLE(rfbEncodingSupportedEncodings);
    rect.r.x = 0;
    rect.r.y = 0;
    rect.r.w = Swap16IfLE(nEncodings * sizeof(uint32_t));
    rect.r.h = Swap16IfLE(nEncodings);

    memcpy(&cl->updateBuf[cl->ublen], (char *)&rect, sz_rfbFramebufferUpdateRectHeader);
    cl->ublen += sz_rfbFramebufferUpdateRectHeader;

    for (i = 0; i < nEncodings; i++) {
        uint32_t encoding = Swap32IfLE(supported[i]);
	memcpy(&cl->updateBuf[cl->ublen], (char *)&encoding, sizeof(encoding));
	cl->ublen += sizeof(encoding);
    }

    rfbStatRecordEncodingSent(cl, rfbEncodingSupportedEncodings, sz_rfbFramebufferUpdateRectHeader+(nEncodings * sizeof(uint32_t)), sz_rfbFramebufferUpdateRectHeader+(nEncodings * sizeof(uint32_t)));


    if (!rfbSendUpdateBuf(cl))
        return FALSE;

    return TRUE;
}


void rfbSetServerVersionIdentity(rfbScreenInfoPtr screen, char *fmt, ...)
{
    char buffer[256];
    va_list ap;
    
    va_start(ap, fmt);
    vsnprintf(buffer, sizeof(buffer)-1, fmt, ap);
    va_end(ap);
    
    if (screen->versionString!=NULL) free(screen->versionString);
    screen->versionString = strdup(buffer);
}



rfbBool rfbSendServerIdentity(rfbClientPtr cl)
{
    rfbFramebufferUpdateRectHeader rect;
    char buffer[512];

    
    snprintf(buffer,sizeof(buffer)-1, "%s (%s)",  (cl->screen->versionString==NULL ? "unknown" : cl->screen->versionString), LIBVNCSERVER_PACKAGE_STRING);


    if (cl->ublen + sz_rfbFramebufferUpdateRectHeader + (strlen(buffer)+1) > UPDATE_BUF_SIZE) {
        if (!rfbSendUpdateBuf(cl))
            return FALSE;
    }

    rect.encoding = Swap32IfLE(rfbEncodingServerIdentity);
    rect.r.x = 0;
    rect.r.y = 0;
    rect.r.w = Swap16IfLE(strlen(buffer)+1);
    rect.r.h = 0;

    memcpy(&cl->updateBuf[cl->ublen], (char *)&rect, sz_rfbFramebufferUpdateRectHeader);
    cl->ublen += sz_rfbFramebufferUpdateRectHeader;

    memcpy(&cl->updateBuf[cl->ublen], buffer, strlen(buffer)+1);
    cl->ublen += strlen(buffer)+1;

    rfbStatRecordEncodingSent(cl, rfbEncodingServerIdentity, sz_rfbFramebufferUpdateRectHeader+strlen(buffer)+1, sz_rfbFramebufferUpdateRectHeader+strlen(buffer)+1);

    

    if (!rfbSendUpdateBuf(cl))
        return FALSE;

    return TRUE;
}



rfbBool rfbSendXvp(rfbClientPtr cl, uint8_t version, uint8_t code)
{
    rfbXvpMsg xvp;

    xvp.type = rfbXvp;
    xvp.pad = 0;
    xvp.version = version;
    xvp.code = code;

    LOCK(cl->sendMutex);
    if (rfbWriteExact(cl, (char *)&xvp, sz_rfbXvpMsg) < 0) {
      rfbLogPerror("rfbSendXvp: write");
      rfbCloseClient(cl);
    }
    UNLOCK(cl->sendMutex);

    rfbStatRecordMessageSent(cl, rfbXvp, sz_rfbXvpMsg, sz_rfbXvpMsg);

    return TRUE;
}


rfbBool rfbSendTextChatMessage(rfbClientPtr cl, uint32_t length, char *buffer)
{
    rfbTextChatMsg tc;
    int bytesToSend=0;

    memset((char *)&tc, 0, sizeof(tc)); 
    tc.type = rfbTextChat;
    tc.length = Swap32IfLE(length);
    
    switch(length) {
    case rfbTextChatOpen:
    case rfbTextChatClose:
    case rfbTextChatFinished:
        bytesToSend=0;
        break;
    default:
        bytesToSend=length;
        if (bytesToSend>rfbTextMaxSize)
            bytesToSend=rfbTextMaxSize;
    }

    if (cl->ublen + sz_rfbTextChatMsg + bytesToSend > UPDATE_BUF_SIZE) {
        if (!rfbSendUpdateBuf(cl))
            return FALSE;
    }
    
    memcpy(&cl->updateBuf[cl->ublen], (char *)&tc, sz_rfbTextChatMsg);
    cl->ublen += sz_rfbTextChatMsg;
    if (bytesToSend>0) {
        memcpy(&cl->updateBuf[cl->ublen], buffer, bytesToSend);
        cl->ublen += bytesToSend;    
    }
    rfbStatRecordMessageSent(cl, rfbTextChat, sz_rfbTextChatMsg+bytesToSend, sz_rfbTextChatMsg+bytesToSend);

    if (!rfbSendUpdateBuf(cl))
        return FALSE;
        
    return TRUE;
}









int DB = 1;

rfbBool rfbSendFileTransferMessage(rfbClientPtr cl, uint8_t contentType, uint8_t contentParam, uint32_t size, uint32_t length, const char *buffer)
{
    rfbFileTransferMsg ft;
    ft.type = rfbFileTransfer;
    ft.contentType = contentType;
    ft.contentParam = contentParam;
    ft.pad          = 0; 
    ft.size         = Swap32IfLE(size);
    ft.length       = Swap32IfLE(length);
    
    FILEXFER_ALLOWED_OR_CLOSE_AND_RETURN("", cl, FALSE);
    
    LOCK(cl->sendMutex);
    if (rfbWriteExact(cl, (char *)&ft, sz_rfbFileTransferMsg) < 0) {
        rfbLogPerror("rfbSendFileTransferMessage: write");
        rfbCloseClient(cl);
        UNLOCK(cl->sendMutex);
        return FALSE;
    }

    if (length>0)
    {
        if (rfbWriteExact(cl, buffer, length) < 0) {
            rfbLogPerror("rfbSendFileTransferMessage: write");
            rfbCloseClient(cl);
            UNLOCK(cl->sendMutex);
            return FALSE;
        }
    }
    UNLOCK(cl->sendMutex);

    rfbStatRecordMessageSent(cl, rfbFileTransfer, sz_rfbFileTransferMsg+length, sz_rfbFileTransferMsg+length);

    return TRUE;
}





typedef struct {
    uint32_t dwLowDateTime;
    uint32_t dwHighDateTime;
} RFB_FILETIME; 

typedef struct {
    uint32_t dwFileAttributes;
    RFB_FILETIME ftCreationTime;
    RFB_FILETIME ftLastAccessTime;
    RFB_FILETIME ftLastWriteTime;
    uint32_t nFileSizeHigh;
    uint32_t nFileSizeLow;
    uint32_t dwReserved0;
    uint32_t dwReserved1;
    uint8_t  cFileName[ MAX_PATH ];
    uint8_t  cAlternateFileName[ 14 ];
} RFB_FIND_DATA;










rfbBool rfbFilenameTranslate2UNIX(rfbClientPtr cl,  char *path,  char *unixPath, size_t unixPathMaxLen)
{
    int x;
    char *home=NULL;

    FILEXFER_ALLOWED_OR_CLOSE_AND_RETURN("", cl, FALSE);

    
    if (strlen(path) >= unixPathMaxLen)
      return FALSE;

    
    if (path[0]=='C' && path[1]==':')
      strcpy(unixPath, &path[2]);
    else {
      home = getenv("HOME");
      if (home!=NULL)
      {
        
        if ((strlen(path) + strlen(home) + 1) >= unixPathMaxLen)
          return FALSE;

        strcpy(unixPath, home);
        strcat(unixPath,"/");
        strcat(unixPath, path);
      }
      else strcpy(unixPath, path);
    }
    for (x=0;x<strlen(unixPath);x++)
      if (unixPath[x]=='\\') unixPath[x]='/';
    return TRUE;
}

rfbBool rfbFilenameTranslate2DOS(rfbClientPtr cl, char *unixPath, char *path)
{
    int x;

    FILEXFER_ALLOWED_OR_CLOSE_AND_RETURN("", cl, FALSE);

    sprintf(path,"C:%s", unixPath);
    for (x=2;x<strlen(path);x++)
        if (path[x]=='/') path[x]='\\';
    return TRUE;
}

rfbBool rfbSendDirContent(rfbClientPtr cl, int length, char *buffer)
{
    char retfilename[MAX_PATH];
    char path[MAX_PATH];
    struct stat statbuf;
    RFB_FIND_DATA win32filename;
    int nOptLen = 0, retval=0;

    WIN32_FIND_DATAA winFindData;
    HANDLE findHandle;
    int pathLen, basePathLength;
    char *basePath;

    DIR *dirp=NULL;
    struct dirent *direntp=NULL;


    FILEXFER_ALLOWED_OR_CLOSE_AND_RETURN("", cl, FALSE);

    
    if (!rfbFilenameTranslate2UNIX(cl, buffer, path, sizeof(path)))
        return FALSE;

    if (DB) rfbLog("rfbProcessFileTransfer() rfbDirContentRequest: rfbRDirContent: \"%s\"->\"%s\"\n",buffer, path);


    

    pathLen = strlen(path);
    basePath = malloc(pathLen + 3);
    memcpy(basePath, path, pathLen);
    basePathLength = pathLen;
    basePath[basePathLength] = '\\';
    basePath[basePathLength + 1] = '*';
    basePath[basePathLength + 2] = '\0';

    
    memset(&winFindData, 0, sizeof(winFindData));
    findHandle = FindFirstFileA(path, &winFindData);
    free(basePath);

    if (findHandle == INVALID_HANDLE_VALUE)

    dirp=opendir(path);
    if (dirp==NULL)

        return rfbSendFileTransferMessage(cl, rfbDirPacket, rfbADirectory, 0, 0, NULL);

    
    if (rfbSendFileTransferMessage(cl, rfbDirPacket, rfbADirectory, 0, length, buffer)==FALSE) return FALSE;


    while (findHandle != INVALID_HANDLE_VALUE)

    for (direntp=readdir(dirp); direntp!=NULL; direntp=readdir(dirp))

    {
        

    snprintf(retfilename,sizeof(retfilename),"%s/%s", path, winFindData.cFileName);

    snprintf(retfilename,sizeof(retfilename),"%s/%s", path, direntp->d_name);

        retval = stat(retfilename, &statbuf);

        if (retval==0)
        {
            memset((char *)&win32filename, 0, sizeof(win32filename));

            win32filename.dwFileAttributes = winFindData.dwFileAttributes;
            win32filename.ftCreationTime.dwLowDateTime = winFindData.ftCreationTime.dwLowDateTime;
            win32filename.ftCreationTime.dwHighDateTime = winFindData.ftCreationTime.dwHighDateTime;
            win32filename.ftLastAccessTime.dwLowDateTime = winFindData.ftLastAccessTime.dwLowDateTime;
            win32filename.ftLastAccessTime.dwHighDateTime = winFindData.ftLastAccessTime.dwHighDateTime;
            win32filename.ftLastWriteTime.dwLowDateTime = winFindData.ftLastWriteTime.dwLowDateTime;
            win32filename.ftLastWriteTime.dwHighDateTime = winFindData.ftLastWriteTime.dwHighDateTime;
            win32filename.nFileSizeLow = winFindData.nFileSizeLow;
            win32filename.nFileSizeHigh = winFindData.nFileSizeHigh;
            win32filename.dwReserved0 = winFindData.dwReserved0;
            win32filename.dwReserved1 = winFindData.dwReserved1;
            strcpy((char *)win32filename.cFileName, winFindData.cFileName);
            strcpy((char *)win32filename.cAlternateFileName, winFindData.cAlternateFileName);

            win32filename.dwFileAttributes = Swap32IfBE(RFB_FILE_ATTRIBUTE_NORMAL);
            if (S_ISDIR(statbuf.st_mode))
                win32filename.dwFileAttributes = Swap32IfBE(RFB_FILE_ATTRIBUTE_DIRECTORY);
            win32filename.ftCreationTime.dwLowDateTime = Swap32IfBE(statbuf.st_ctime);   
            win32filename.ftCreationTime.dwHighDateTime = 0;
            win32filename.ftLastAccessTime.dwLowDateTime = Swap32IfBE(statbuf.st_atime); 
            win32filename.ftLastAccessTime.dwHighDateTime = 0;
            win32filename.ftLastWriteTime.dwLowDateTime = Swap32IfBE(statbuf.st_mtime);  
            win32filename.ftLastWriteTime.dwHighDateTime = 0;
            win32filename.nFileSizeLow = Swap32IfBE(statbuf.st_size); 
            win32filename.nFileSizeHigh = 0;
            win32filename.dwReserved0 = 0;
            win32filename.dwReserved1 = 0;

            
            
            strcpy((char *)win32filename.cFileName, direntp->d_name);

            
            
            if ((strcmp((char *)win32filename.cFileName, "..")==0) || (win32filename.cFileName[0]!='.'))
            {
                nOptLen = sizeof(RFB_FIND_DATA) - MAX_PATH - 14 + strlen((char *)win32filename.cFileName);
                
                if (rfbSendFileTransferMessage(cl, rfbDirPacket, rfbADirectory, 0, nOptLen, (char *)&win32filename)==FALSE)
                {

                    FindClose(findHandle);

                    closedir(dirp);

                    return FALSE;
                }
            }
        }


        if (FindNextFileA(findHandle, &winFindData) == 0)
        {
            FindClose(findHandle);
            findHandle = INVALID_HANDLE_VALUE;
        }

    }

    if (findHandle != INVALID_HANDLE_VALUE)
    {
        FindClose(findHandle);
    }

    closedir(dirp);

    
    return rfbSendFileTransferMessage(cl, rfbDirPacket, 0, 0, 0, NULL);
}


char *rfbProcessFileTransferReadBuffer(rfbClientPtr cl, uint32_t length)
{
    char *buffer=NULL;
    int   n=0;

    FILEXFER_ALLOWED_OR_CLOSE_AND_RETURN("", cl, NULL);

    
    if(length == SIZE_MAX || length > INT_MAX) {
	rfbErr("rfbProcessFileTransferReadBuffer: too big file transfer length requested: %u", (unsigned int)length);
	rfbCloseClient(cl);
	return NULL;
    }

    if (length>0) {
        buffer=malloc((size_t)length+1);
        if (buffer!=NULL) {
            if ((n = rfbReadExact(cl, (char *)buffer, length)) <= 0) {
                if (n != 0)
                    rfbLogPerror("rfbProcessFileTransferReadBuffer: read");
                rfbCloseClient(cl);
                
                if (buffer!=NULL) free(buffer);
                return NULL;
            }
            
            buffer[length]=0;
        }
    }
    return buffer;
}


rfbBool rfbSendFileTransferChunk(rfbClientPtr cl)
{
    
    char readBuf[sz_rfbBlockSize];
    int bytesRead=0;
    int retval=0;
    fd_set wfds;
    struct timeval tv;
    int n;

    unsigned char compBuf[sz_rfbBlockSize + 1024];
    unsigned long nMaxCompSize = sizeof(compBuf);
    int nRetC = 0;


    
    if (cl->screen->permitFileTransfer != TRUE || (cl->screen->getFileTransferPermission != NULL && cl->screen->getFileTransferPermission(cl) != TRUE)) {

		return TRUE;
    }

    
    if ((cl->fileTransfer.fd!=-1) && (cl->fileTransfer.sending==1))
    {
	FD_ZERO(&wfds);
        FD_SET(cl->sock, &wfds);

        
	tv.tv_sec = 0; 
	tv.tv_usec = 0;
	n = select(cl->sock + 1, NULL, &wfds, NULL, &tv);

	if (n<0) {

	    errno=WSAGetLastError();

            rfbLog("rfbSendFileTransferChunk() select failed: %s\n", strerror(errno));
	}
        
	if (n > 0)
	{
            bytesRead = read(cl->fileTransfer.fd, readBuf, sz_rfbBlockSize);
            switch (bytesRead) {
            case 0:
                
                retval = rfbSendFileTransferMessage(cl, rfbEndOfFile, 0, 0, 0, NULL);
                close(cl->fileTransfer.fd);
                cl->fileTransfer.fd = -1;
                cl->fileTransfer.sending   = 0;
                cl->fileTransfer.receiving = 0;
                return retval;
            case -1:
                

	        errno=WSAGetLastError();

                rfbLog("rfbSendFileTransferChunk(): %s\n",strerror(errno));
                retval = rfbSendFileTransferMessage(cl, rfbAbortFileTransfer, 0, 0, 0, NULL);
                close(cl->fileTransfer.fd);
                cl->fileTransfer.fd = -1;
                cl->fileTransfer.sending   = 0;
                cl->fileTransfer.receiving = 0;
                return retval;
            default:
                
                if (!cl->fileTransfer.compressionEnabled)
                    return  rfbSendFileTransferMessage(cl, rfbFilePacket, 0, 0, bytesRead, readBuf);
                else {

                    nRetC = compress(compBuf, &nMaxCompSize, (unsigned char *)readBuf, bytesRead);
                    
                    
                    if ((nRetC==0) && (nMaxCompSize<bytesRead))
                        return  rfbSendFileTransferMessage(cl, rfbFilePacket, 0, 1, nMaxCompSize, (char *)compBuf);
                    else return  rfbSendFileTransferMessage(cl, rfbFilePacket, 0, 0, bytesRead, readBuf);

                    
                    return  rfbSendFileTransferMessage(cl, rfbFilePacket, 0, 0, bytesRead, readBuf);

                }
            }
        }
    }
    return TRUE;
}

rfbBool rfbProcessFileTransfer(rfbClientPtr cl, uint8_t contentType, uint8_t contentParam, uint32_t size, uint32_t length)
{
    char *buffer=NULL, *p=NULL;
    int retval=0;
    char filename1[MAX_PATH];
    char filename2[MAX_PATH];
    char szFileTime[MAX_PATH];
    struct stat statbuf;
    uint32_t sizeHtmp=0;
    int n=0;
    char timespec[64];

    unsigned char compBuff[sz_rfbBlockSize];
    unsigned long nRawBytes = sz_rfbBlockSize;
    int nRet = 0;


    FILEXFER_ALLOWED_OR_CLOSE_AND_RETURN("", cl, FALSE);
        
    

    switch (contentType) {
    case rfbDirContentRequest:
        switch (contentParam) {
        case rfbRDrivesList: 
            
            
            
            
            filename2[0]='C';
            filename2[1]=':';
            filename2[2]='l';
            filename2[3]=0;
            filename2[4]=0;
            retval = rfbSendFileTransferMessage(cl, rfbDirPacket, rfbADrivesList, 0, 5, filename2);
            if (buffer!=NULL) free(buffer);
            return retval;
            break;
        case rfbRDirContent: 
            
            if ((buffer = rfbProcessFileTransferReadBuffer(cl, length))==NULL) return FALSE;
            retval = rfbSendDirContent(cl, length, buffer);
            if (buffer!=NULL) free(buffer);
            return retval;
        }
        break;

    case rfbDirPacket:
        rfbLog("rfbProcessFileTransfer() rfbDirPacket\n");
        break;
    case rfbFileAcceptHeader:
        rfbLog("rfbProcessFileTransfer() rfbFileAcceptHeader\n");
        break;
    case rfbCommandReturn:
        rfbLog("rfbProcessFileTransfer() rfbCommandReturn\n");
        break;
    case rfbFileChecksums:
        
        rfbLog("rfbProcessFileTransfer() rfbFileChecksums\n");
        break;
    case rfbFileTransferAccess:
        rfbLog("rfbProcessFileTransfer() rfbFileTransferAccess\n");
        break;

    

    case rfbFileTransferRequest:
        
        
        if ((buffer = rfbProcessFileTransferReadBuffer(cl, length))==NULL) return FALSE;
        
        if (!rfbFilenameTranslate2UNIX(cl, buffer, filename1, sizeof(filename1)))
            goto fail;
        cl->fileTransfer.fd=open(filename1, O_RDONLY, 0744);

        
        if (DB) rfbLog("rfbProcessFileTransfer() rfbFileTransferRequest(\"%s\"->\"%s\") Open: %s fd=%d\n", buffer, filename1, (cl->fileTransfer.fd==-1?"Failed":"Success"), cl->fileTransfer.fd);
        
        if (cl->fileTransfer.fd!=-1) {
            if (fstat(cl->fileTransfer.fd, &statbuf)!=0) {
                close(cl->fileTransfer.fd);
                cl->fileTransfer.fd=-1;
            }
            else {
              
              strftime(timespec, sizeof(timespec), "%m/%d/%Y %H:%M",gmtime(&statbuf.st_ctime));
              buffer=realloc(buffer, length + strlen(timespec) + 2); 
              if (buffer==NULL) {
                  rfbLog("rfbProcessFileTransfer() rfbFileTransferRequest: Failed to malloc %d bytes\n", length + strlen(timespec) + 2);
                  return FALSE;
              }
              strcat(buffer,",");
              strcat(buffer, timespec);
              length = strlen(buffer);
              if (DB) rfbLog("rfbProcessFileTransfer() buffer is now: \"%s\"\n", buffer);
            }
        }

        
        cl->fileTransfer.compressionEnabled = (size==1);

        

        
        retval = rfbSendFileTransferMessage(cl, rfbFileHeader, 0, (cl->fileTransfer.fd==-1 ? -1 : statbuf.st_size), length, buffer);

        if (cl->fileTransfer.fd==-1)
        {
            if (buffer!=NULL) free(buffer);
            return retval;
        }
        
        cl->fileTransfer.fileSize = statbuf.st_size;
        cl->fileTransfer.numPackets = statbuf.st_size / sz_rfbBlockSize;
        cl->fileTransfer.receiving = 0;
        cl->fileTransfer.sending = 0; 

        
        sizeHtmp = 0;        
        LOCK(cl->sendMutex);
        if (rfbWriteExact(cl, (char *)&sizeHtmp, 4) < 0) {
          rfbLogPerror("rfbProcessFileTransfer: write");
          rfbCloseClient(cl);
          UNLOCK(cl->sendMutex);
          if (buffer!=NULL) free(buffer);
          return FALSE;
        }
        UNLOCK(cl->sendMutex);
        break;

    case rfbFileHeader:
        
        if (size==-1) {
            rfbLog("rfbProcessFileTransfer() rfbFileHeader (error, aborting)\n");
            close(cl->fileTransfer.fd);
            cl->fileTransfer.fd=-1;
            return TRUE;
        }

        

        
        cl->fileTransfer.sending=1;
        return rfbSendFileTransferChunk(cl);
        break;


    

    case rfbFileTransferOffer:
        
        
        
        
        if ((buffer = rfbProcessFileTransferReadBuffer(cl, length))==NULL) return FALSE;

        
        p = strrchr(buffer, ',');
        if (p!=NULL) {
            *p = '\0';
            strncpy(szFileTime, p+1, sizeof(szFileTime));
            szFileTime[sizeof(szFileTime)-1] = '\x00'; 
        } else szFileTime[0]=0;



        
        if ((n = rfbReadExact(cl, (char *)&sizeHtmp, 4)) <= 0) {
            if (n != 0)
                rfbLogPerror("rfbProcessFileTransfer: read sizeHtmp");
            rfbCloseClient(cl);
            
            if (buffer!=NULL) free(buffer);
            return FALSE;
        }
        sizeHtmp = Swap32IfLE(sizeHtmp);
        
        if (!rfbFilenameTranslate2UNIX(cl, buffer, filename1, sizeof(filename1)))
            goto fail;

        
        

        cl->fileTransfer.fd=open(filename1, O_CREAT|O_WRONLY|O_TRUNC, 0744);
        if (DB) rfbLog("rfbProcessFileTransfer() rfbFileTransferOffer(\"%s\"->\"%s\") %s %s fd=%d\n", buffer, filename1, (cl->fileTransfer.fd==-1?"Failed":"Success"), (cl->fileTransfer.fd==-1?strerror(errno):""), cl->fileTransfer.fd);
        
        
        
        retval = rfbSendFileTransferMessage(cl, rfbFileAcceptHeader, 0, (cl->fileTransfer.fd==-1 ? -1 : 0), length, buffer);
        if (cl->fileTransfer.fd==-1) {
            free(buffer);
            return retval;
        }
        
        
        cl->fileTransfer.fileSize = size;
        cl->fileTransfer.numPackets = size / sz_rfbBlockSize;
        cl->fileTransfer.receiving = 1;
        cl->fileTransfer.sending = 0;
        break;

    case rfbFilePacket:
        
        if ((buffer = rfbProcessFileTransferReadBuffer(cl, length))==NULL) return FALSE;
        if (cl->fileTransfer.fd!=-1) {
            
            if (size==0)
                retval=write(cl->fileTransfer.fd, buffer, length);
            else {

                
                nRet = uncompress(compBuff,&nRawBytes,(const unsigned char*)buffer, length);
		if(nRet == Z_OK)
		  retval=write(cl->fileTransfer.fd, (char*)compBuff, nRawBytes);
		else retval = -1;

                
                retval=write(cl->fileTransfer.fd, buffer, length);

            }
            if (retval==-1)
            {
                close(cl->fileTransfer.fd);
                cl->fileTransfer.fd=-1;
                cl->fileTransfer.sending   = 0;
                cl->fileTransfer.receiving = 0;
            }
        }
        break;

    case rfbEndOfFile:
        if (DB) rfbLog("rfbProcessFileTransfer() rfbEndOfFile\n");
        
        if (cl->fileTransfer.fd!=-1)
            close(cl->fileTransfer.fd);
        cl->fileTransfer.fd=-1;
        cl->fileTransfer.sending   = 0;
        cl->fileTransfer.receiving = 0;
        break;

    case rfbAbortFileTransfer:
        if (DB) rfbLog("rfbProcessFileTransfer() rfbAbortFileTransfer\n");
        
        if (cl->fileTransfer.fd!=-1)
        {
            close(cl->fileTransfer.fd);
            cl->fileTransfer.fd=-1;
            cl->fileTransfer.sending   = 0;
            cl->fileTransfer.receiving = 0;
        }
        else {
            
            if (contentParam == 0)
            {
                rfbLog("rfbProcessFileTransfer() File Transfer Permission DENIED! (Client Version <=RC18)\n");
                
                return rfbSendFileTransferMessage(cl, rfbAbortFileTransfer, 0, -1, 0, "");
            }
            
            if (cl->screen->getFileTransferPermission!=NULL)
            {
                if (cl->screen->getFileTransferPermission(cl)==TRUE)
                {
                    rfbLog("rfbProcessFileTransfer() File Transfer Permission Granted!\n");
                    return rfbSendFileTransferMessage(cl, rfbFileTransferAccess, 0, 1 , 0, ""); 
                }
                else {
                    rfbLog("rfbProcessFileTransfer() File Transfer Permission DENIED!\n");
                    return rfbSendFileTransferMessage(cl, rfbFileTransferAccess, 0, -1 , 0, ""); 
                }
            }
            else {
                if (cl->screen->permitFileTransfer)
                {
                    rfbLog("rfbProcessFileTransfer() File Transfer Permission Granted!\n");
                    return rfbSendFileTransferMessage(cl, rfbFileTransferAccess, 0, 1 , 0, ""); 
                }
                else {
                    rfbLog("rfbProcessFileTransfer() File Transfer Permission DENIED by default!\n");
                    return rfbSendFileTransferMessage(cl, rfbFileTransferAccess, 0, -1 , 0, ""); 
                }
                
            }
        }
        break;


    case rfbCommand:
        
        if ((buffer = rfbProcessFileTransferReadBuffer(cl, length))==NULL) return FALSE;
        switch (contentParam) {
        case rfbCDirCreate:  
            if (!rfbFilenameTranslate2UNIX(cl, buffer, filename1, sizeof(filename1)))
                goto fail;
            retval = mkdir(filename1, 0755);
            if (DB) rfbLog("rfbProcessFileTransfer() rfbCommand: rfbCDirCreate(\"%s\"->\"%s\") %s\n", buffer, filename1, (retval==-1?"Failed":"Success"));
            
            retval = rfbSendFileTransferMessage(cl, rfbCommandReturn, rfbADirCreate, retval, length, buffer);
            if (buffer!=NULL) free(buffer);
            return retval;
        case rfbCFileDelete: 
            if (!rfbFilenameTranslate2UNIX(cl, buffer, filename1, sizeof(filename1)))
                goto fail;
            if (stat(filename1,&statbuf)==0)
            {
                if (S_ISDIR(statbuf.st_mode))
                    retval = rmdir(filename1);
                else retval = unlink(filename1);
            }
            else retval=-1;
            retval = rfbSendFileTransferMessage(cl, rfbCommandReturn, rfbAFileDelete, retval, length, buffer);
            if (buffer!=NULL) free(buffer);
            return retval;
        case rfbCFileRename: 
            p = strrchr(buffer, '*');
            if (p != NULL)
            {
                
                *p = '\0';
                if (!rfbFilenameTranslate2UNIX(cl, buffer, filename1, sizeof(filename1)))
                    goto fail;
                if (!rfbFilenameTranslate2UNIX(cl, p+1,    filename2, sizeof(filename2)))
                    goto fail;
                retval = rename(filename1,filename2);
                if (DB) rfbLog("rfbProcessFileTransfer() rfbCommand: rfbCFileRename(\"%s\"->\"%s\" -->> \"%s\"->\"%s\") %s\n", buffer, filename1, p+1, filename2, (retval==-1?"Failed":"Success"));
                
                
                *p = '*';
                retval = rfbSendFileTransferMessage(cl, rfbCommandReturn, rfbAFileRename, retval, length, buffer);
                if (buffer!=NULL) free(buffer);
                return retval;
            }
            break;
        }
    
        break;
    }

    
    if (buffer!=NULL) free(buffer);
    return TRUE;

fail:
    if (buffer!=NULL) free(buffer);
    return FALSE;
}



static void rfbProcessClientNormalMessage(rfbClientPtr cl)
{
    int n=0;
    rfbClientToServerMsg msg;
    char *str;
    int i;
    uint32_t enc=0;
    uint32_t lastPreferredEncoding = -1;
    char encBuf[64];
    char encBuf2[64];
    rfbExtDesktopScreen *extDesktopScreens;
    rfbClientIteratorPtr iterator;
    rfbClientPtr clp;

    if ((n = rfbReadExact(cl, (char *)&msg, 1)) <= 0) {
        if (n != 0)
            rfbLogPerror("rfbProcessClientNormalMessage: read");
        rfbCloseClient(cl);
        return;
    }

    switch (msg.type) {

    case rfbSetPixelFormat:

        if ((n = rfbReadExact(cl, ((char *)&msg) + 1, sz_rfbSetPixelFormatMsg - 1)) <= 0) {
            if (n != 0)
                rfbLogPerror("rfbProcessClientNormalMessage: read");
            rfbCloseClient(cl);
            return;
        }

        cl->format.bitsPerPixel = msg.spf.format.bitsPerPixel;
        cl->format.depth = msg.spf.format.depth;
        cl->format.bigEndian = (msg.spf.format.bigEndian ? TRUE : FALSE);
        cl->format.trueColour = (msg.spf.format.trueColour ? TRUE : FALSE);
        cl->format.redMax = Swap16IfLE(msg.spf.format.redMax);
        cl->format.greenMax = Swap16IfLE(msg.spf.format.greenMax);
        cl->format.blueMax = Swap16IfLE(msg.spf.format.blueMax);
        cl->format.redShift = msg.spf.format.redShift;
        cl->format.greenShift = msg.spf.format.greenShift;
        cl->format.blueShift = msg.spf.format.blueShift;

	cl->readyForSetColourMapEntries = TRUE;
        cl->screen->setTranslateFunction(cl);

        rfbStatRecordMessageRcvd(cl, msg.type, sz_rfbSetPixelFormatMsg, sz_rfbSetPixelFormatMsg);

        return;


    case rfbFixColourMapEntries:
        if ((n = rfbReadExact(cl, ((char *)&msg) + 1, sz_rfbFixColourMapEntriesMsg - 1)) <= 0) {
            if (n != 0)
                rfbLogPerror("rfbProcessClientNormalMessage: read");
            rfbCloseClient(cl);
            return;
        }
        rfbStatRecordMessageRcvd(cl, msg.type, sz_rfbSetPixelFormatMsg, sz_rfbSetPixelFormatMsg);
        rfbLog("rfbProcessClientNormalMessage: %s", "FixColourMapEntries unsupported\n");
        rfbCloseClient(cl);
        return;


    
    case rfbSetEncodings:
    {

        if ((n = rfbReadExact(cl, ((char *)&msg) + 1, sz_rfbSetEncodingsMsg - 1)) <= 0) {
            if (n != 0)
                rfbLogPerror("rfbProcessClientNormalMessage: read");
            rfbCloseClient(cl);
            return;
        }

        msg.se.nEncodings = Swap16IfLE(msg.se.nEncodings);

        rfbStatRecordMessageRcvd(cl, msg.type, sz_rfbSetEncodingsMsg+(msg.se.nEncodings*4),sz_rfbSetEncodingsMsg+(msg.se.nEncodings*4));

        
        if (cl->preferredEncoding!=-1)
            lastPreferredEncoding = cl->preferredEncoding;

        
        cl->preferredEncoding=-1;
        cl->useCopyRect              = FALSE;
        cl->useNewFBSize             = FALSE;
        cl->useExtDesktopSize        = FALSE;
        cl->cursorWasChanged         = FALSE;
        cl->useRichCursorEncoding    = FALSE;
        cl->enableCursorPosUpdates   = FALSE;
        cl->enableCursorShapeUpdates = FALSE;
        cl->enableCursorShapeUpdates = FALSE;
        cl->enableLastRectEncoding   = FALSE;
        cl->enableKeyboardLedState   = FALSE;
        cl->enableSupportedMessages  = FALSE;
        cl->enableSupportedEncodings = FALSE;
        cl->enableServerIdentity     = FALSE;

        cl->tightQualityLevel        = -1;

        cl->tightCompressLevel       = TIGHT_DEFAULT_COMPRESSION;
        cl->turboSubsampLevel        = TURBO_DEFAULT_SUBSAMP;
        cl->turboQualityLevel        = -1;




        for (i = 0; i < msg.se.nEncodings; i++) {
            if ((n = rfbReadExact(cl, (char *)&enc, 4)) <= 0) {
                if (n != 0)
                    rfbLogPerror("rfbProcessClientNormalMessage: read");
                rfbCloseClient(cl);
                return;
            }
            enc = Swap32IfLE(enc);

            switch (enc) {

            case rfbEncodingCopyRect:
		cl->useCopyRect = TRUE;
                break;
            case rfbEncodingRaw:
            case rfbEncodingRRE:
            case rfbEncodingCoRRE:
            case rfbEncodingHextile:
            case rfbEncodingUltra:

	    case rfbEncodingZlib:
            case rfbEncodingZRLE:
            case rfbEncodingZYWRLE:

	    case rfbEncodingTight:



	    case rfbEncodingTightPng:

            
                if (cl->preferredEncoding == -1)
                    cl->preferredEncoding = enc;


                break;
	    case rfbEncodingXCursor:
		if(!cl->screen->dontConvertRichCursorToXCursor) {
		    rfbLog("Enabling X-style cursor updates for client %s\n", cl->host);
		    
		    if(!cl->enableCursorShapeUpdates)
		        rfbRedrawAfterHideCursor(cl,NULL);

		    cl->enableCursorShapeUpdates = TRUE;
		    cl->cursorWasChanged = TRUE;
		}
		break;
	    case rfbEncodingRichCursor:
	        rfbLog("Enabling full-color cursor updates for client %s\n", cl->host);
		
		if(!cl->enableCursorShapeUpdates)
		    rfbRedrawAfterHideCursor(cl,NULL);

	        cl->enableCursorShapeUpdates = TRUE;
	        cl->useRichCursorEncoding = TRUE;
	        cl->cursorWasChanged = TRUE;
	        break;
	    case rfbEncodingPointerPos:
		if (!cl->enableCursorPosUpdates) {
		    rfbLog("Enabling cursor position updates for client %s\n", cl->host);
		    cl->enableCursorPosUpdates = TRUE;
		    cl->cursorWasMoved = TRUE;
		}
	        break;
	    case rfbEncodingLastRect:
		if (!cl->enableLastRectEncoding) {
		    rfbLog("Enabling LastRect protocol extension for client " "%s\n", cl->host);
		    cl->enableLastRectEncoding = TRUE;
		}
		break;
	    case rfbEncodingNewFBSize:
		if (!cl->useNewFBSize) {
		    rfbLog("Enabling NewFBSize protocol extension for client " "%s\n", cl->host);
		    cl->useNewFBSize = TRUE;
		}
		break;
            case rfbEncodingExtDesktopSize:
                if (!cl->useExtDesktopSize) {
                    rfbLog("Enabling ExtDesktopSize protocol extension for client " "%s\n", cl->host);
                    cl->useExtDesktopSize = TRUE;
                    cl->useNewFBSize = TRUE;
                }
                break;
            case rfbEncodingKeyboardLedState:
                if (!cl->enableKeyboardLedState) {
                  rfbLog("Enabling KeyboardLedState protocol extension for client " "%s\n", cl->host);
                  cl->enableKeyboardLedState = TRUE;
                }
                break;           
            case rfbEncodingSupportedMessages:
                if (!cl->enableSupportedMessages) {
                  rfbLog("Enabling SupportedMessages protocol extension for client " "%s\n", cl->host);
                  cl->enableSupportedMessages = TRUE;
                }
                break;           
            case rfbEncodingSupportedEncodings:
                if (!cl->enableSupportedEncodings) {
                  rfbLog("Enabling SupportedEncodings protocol extension for client " "%s\n", cl->host);
                  cl->enableSupportedEncodings = TRUE;
                }
                break;           
            case rfbEncodingServerIdentity:
                if (!cl->enableServerIdentity) {
                  rfbLog("Enabling ServerIdentity protocol extension for client " "%s\n", cl->host);
                  cl->enableServerIdentity = TRUE;
                }
                break;
            case rfbEncodingXvp:
                if (cl->screen->xvpHook) {
                  rfbLog("Enabling Xvp protocol extension for client " "%s\n", cl->host);
                  if (!rfbSendXvp(cl, 1, rfbXvp_Init)) {
                    rfbCloseClient(cl);
                    return;
                  }
                }
                break;
            default:

		if ( enc >= (uint32_t)rfbEncodingCompressLevel0 && enc <= (uint32_t)rfbEncodingCompressLevel9 ) {
		    cl->zlibCompressLevel = enc & 0x0F;

		    cl->tightCompressLevel = enc & 0x0F;
		    rfbLog("Using compression level %d for client %s\n", cl->tightCompressLevel, cl->host);

		} else if ( enc >= (uint32_t)rfbEncodingQualityLevel0 && enc <= (uint32_t)rfbEncodingQualityLevel9 ) {
		    cl->tightQualityLevel = enc & 0x0F;
		    rfbLog("Using image quality level %d for client %s\n", cl->tightQualityLevel, cl->host);

		    cl->turboQualityLevel = tight2turbo_qual[enc & 0x0F];
		    cl->turboSubsampLevel = tight2turbo_subsamp[enc & 0x0F];
		    rfbLog("Using JPEG subsampling %d, Q%d for client %s\n", cl->turboSubsampLevel, cl->turboQualityLevel, cl->host);
		} else if ( enc >= (uint32_t)rfbEncodingFineQualityLevel0 + 1 && enc <= (uint32_t)rfbEncodingFineQualityLevel100 ) {
		    cl->turboQualityLevel = enc & 0xFF;
		    rfbLog("Using fine quality level %d for client %s\n", cl->turboQualityLevel, cl->host);
		} else if ( enc >= (uint32_t)rfbEncodingSubsamp1X && enc <= (uint32_t)rfbEncodingSubsampGray ) {
		    cl->turboSubsampLevel = enc & 0xFF;
		    rfbLog("Using subsampling level %d for client %s\n", cl->turboSubsampLevel, cl->host);

		} else  {

			rfbExtensionData* e;
			for(e = cl->extensions; e;) {
				rfbExtensionData* next = e->next;
				if(e->extension->enablePseudoEncoding && e->extension->enablePseudoEncoding(cl, &e->data, (int)enc))

					
					break;
				e = next;
			}
			if(e == NULL) {
				rfbBool handled = FALSE;
				
				rfbProtocolExtension* e;

				for(e = rfbGetExtensionIterator(); e;) {
					int* encs = e->pseudoEncodings;
					while(encs && *encs!=0) {
						if(*encs==(int)enc) {
							void* data = NULL;
							if(!e->enablePseudoEncoding(cl, &data, (int)enc)) {
								rfbLog("Installed extension pretends to handle pseudo encoding 0x%x, but does not!\n",(int)enc);
							} else {
								rfbEnableExtension(cl, e, data);
								handled = TRUE;
								e = NULL;
								break;
							}
						}
						encs++;
					}

					if(e)
						e = e->next;
				}
				rfbReleaseExtensionIterator();

				if(!handled)
					rfbLog("rfbProcessClientNormalMessage: " "ignoring unsupported encoding type %s\n", encodingName(enc,encBuf,sizeof(encBuf)));

			}
		}
            }
        }



        if (cl->preferredEncoding == -1) {
            if (lastPreferredEncoding==-1) {
                cl->preferredEncoding = rfbEncodingRaw;
                rfbLog("Defaulting to %s encoding for client %s\n", encodingName(cl->preferredEncoding,encBuf,sizeof(encBuf)),cl->host);
            }
            else {
                cl->preferredEncoding = lastPreferredEncoding;
                rfbLog("Sticking with %s encoding for client %s\n", encodingName(cl->preferredEncoding,encBuf,sizeof(encBuf)),cl->host);
            }
        }
        else {
          if (lastPreferredEncoding==-1) {
              rfbLog("Using %s encoding for client %s\n", encodingName(cl->preferredEncoding,encBuf,sizeof(encBuf)),cl->host);
          } else {
              rfbLog("Switching from %s to %s Encoding for client %s\n",  encodingName(lastPreferredEncoding,encBuf2,sizeof(encBuf2)), encodingName(cl->preferredEncoding,encBuf,sizeof(encBuf)), cl->host);

          }
        }
        
	if (cl->enableCursorPosUpdates && !cl->enableCursorShapeUpdates) {
	  rfbLog("Disabling cursor position updates for client %s\n", cl->host);
	  cl->enableCursorPosUpdates = FALSE;
	}

        return;
    }


    case rfbFramebufferUpdateRequest:
    {
        sraRegionPtr tmpRegion;

        if ((n = rfbReadExact(cl, ((char *)&msg) + 1, sz_rfbFramebufferUpdateRequestMsg-1)) <= 0) {
            if (n != 0)
                rfbLogPerror("rfbProcessClientNormalMessage: read");
            rfbCloseClient(cl);
            return;
        }

        rfbStatRecordMessageRcvd(cl, msg.type, sz_rfbFramebufferUpdateRequestMsg,sz_rfbFramebufferUpdateRequestMsg);

        
	if(!rectSwapIfLEAndClip(&msg.fur.x,&msg.fur.y,&msg.fur.w,&msg.fur.h,cl))
	{
	        rfbLog("Warning, ignoring rfbFramebufferUpdateRequest: %dXx%dY-%dWx%dH\n",msg.fur.x, msg.fur.y, msg.fur.w, msg.fur.h);
		return;
        }

        if (cl->clientFramebufferUpdateRequestHook)
            cl->clientFramebufferUpdateRequestHook(cl, &msg.fur);

	tmpRegion = sraRgnCreateRect(msg.fur.x, msg.fur.y, msg.fur.x+msg.fur.w, msg.fur.y+msg.fur.h);




        LOCK(cl->updateMutex);
	sraRgnOr(cl->requestedRegion,tmpRegion);

	if (!cl->readyForSetColourMapEntries) {
	    
	    cl->readyForSetColourMapEntries = TRUE;
	    if (!cl->format.trueColour) {
		if (!rfbSetClientColourMap(cl, 0, 0)) {
		    sraRgnDestroy(tmpRegion);
		    TSIGNAL(cl->updateCond);
		    UNLOCK(cl->updateMutex);
		    return;
		}
	    }
	}

       if (!msg.fur.incremental) {
	    sraRgnOr(cl->modifiedRegion,tmpRegion);
	    sraRgnSubtract(cl->copyRegion,tmpRegion);
            if (cl->useExtDesktopSize)
                cl->newFBSizePending = TRUE;
       }
       TSIGNAL(cl->updateCond);
       UNLOCK(cl->updateMutex);

       sraRgnDestroy(tmpRegion);

       return;
    }

    case rfbKeyEvent:

	if ((n = rfbReadExact(cl, ((char *)&msg) + 1, sz_rfbKeyEventMsg - 1)) <= 0) {
	    if (n != 0)
		rfbLogPerror("rfbProcessClientNormalMessage: read");
	    rfbCloseClient(cl);
	    return;
	}

	rfbStatRecordMessageRcvd(cl, msg.type, sz_rfbKeyEventMsg, sz_rfbKeyEventMsg);

	if(!cl->viewOnly) {
	    cl->screen->kbdAddEvent(msg.ke.down, (rfbKeySym)Swap32IfLE(msg.ke.key), cl);
	}

        return;


    case rfbPointerEvent:

	if ((n = rfbReadExact(cl, ((char *)&msg) + 1, sz_rfbPointerEventMsg - 1)) <= 0) {
	    if (n != 0)
		rfbLogPerror("rfbProcessClientNormalMessage: read");
	    rfbCloseClient(cl);
	    return;
	}

	rfbStatRecordMessageRcvd(cl, msg.type, sz_rfbPointerEventMsg, sz_rfbPointerEventMsg);
	
	if (cl->screen->pointerClient && cl->screen->pointerClient != cl)
	    return;

	if (msg.pe.buttonMask == 0)
	    cl->screen->pointerClient = NULL;
	else cl->screen->pointerClient = cl;

	if(!cl->viewOnly) {
	    if (msg.pe.buttonMask != cl->lastPtrButtons || cl->screen->deferPtrUpdateTime == 0) {
		cl->screen->ptrAddEvent(msg.pe.buttonMask, ScaleX(cl->scaledScreen, cl->screen, Swap16IfLE(msg.pe.x)), ScaleY(cl->scaledScreen, cl->screen, Swap16IfLE(msg.pe.y)), cl);


		cl->lastPtrButtons = msg.pe.buttonMask;
	    } else {
		cl->lastPtrX = ScaleX(cl->scaledScreen, cl->screen, Swap16IfLE(msg.pe.x));
		cl->lastPtrY = ScaleY(cl->scaledScreen, cl->screen, Swap16IfLE(msg.pe.y));
		cl->lastPtrButtons = msg.pe.buttonMask;
	    }
      }      
      return;


    case rfbFileTransfer:
        if ((n = rfbReadExact(cl, ((char *)&msg) + 1, sz_rfbFileTransferMsg - 1)) <= 0) {
            if (n != 0)
                rfbLogPerror("rfbProcessClientNormalMessage: read");
            rfbCloseClient(cl);
            return;
        }
        msg.ft.size         = Swap32IfLE(msg.ft.size);
        msg.ft.length       = Swap32IfLE(msg.ft.length);
        
        rfbProcessFileTransfer(cl, msg.ft.contentType, msg.ft.contentParam, msg.ft.size, msg.ft.length);
        return;

    case rfbSetSW:
        if ((n = rfbReadExact(cl, ((char *)&msg) + 1, sz_rfbSetSWMsg - 1)) <= 0) {
            if (n != 0)
                rfbLogPerror("rfbProcessClientNormalMessage: read");
            rfbCloseClient(cl);
            return;
        }
        msg.sw.x = Swap16IfLE(msg.sw.x);
        msg.sw.y = Swap16IfLE(msg.sw.y);
        rfbStatRecordMessageRcvd(cl, msg.type, sz_rfbSetSWMsg, sz_rfbSetSWMsg);
        

        rfbLog("Received a rfbSetSingleWindow(%d x, %d y)\n", msg.sw.x, msg.sw.y);
        if (cl->screen->setSingleWindow!=NULL)
            cl->screen->setSingleWindow(cl, msg.sw.x, msg.sw.y);
        return;

    case rfbSetServerInput:
        if ((n = rfbReadExact(cl, ((char *)&msg) + 1, sz_rfbSetServerInputMsg - 1)) <= 0) {
            if (n != 0)
                rfbLogPerror("rfbProcessClientNormalMessage: read");
            rfbCloseClient(cl);
            return;
        }
        rfbStatRecordMessageRcvd(cl, msg.type, sz_rfbSetServerInputMsg, sz_rfbSetServerInputMsg);

        
        

        rfbLog("Received a rfbSetServerInput(%d status)\n", msg.sim.status);
        if (cl->screen->setServerInput!=NULL)
            cl->screen->setServerInput(cl, msg.sim.status);
        return;
        
    case rfbTextChat:
        if ((n = rfbReadExact(cl, ((char *)&msg) + 1, sz_rfbTextChatMsg - 1)) <= 0) {
            if (n != 0)
                rfbLogPerror("rfbProcessClientNormalMessage: read");
            rfbCloseClient(cl);
            return;
        }
        
        msg.tc.pad2   = Swap16IfLE(msg.tc.pad2);
        msg.tc.length = Swap32IfLE(msg.tc.length);

        switch (msg.tc.length) {
        case rfbTextChatOpen:
        case rfbTextChatClose:
        case rfbTextChatFinished:
            
            
            str=NULL;
            rfbStatRecordMessageRcvd(cl, msg.type, sz_rfbTextChatMsg, sz_rfbTextChatMsg);
            break;
        default:
            if ((msg.tc.length>0) && (msg.tc.length<rfbTextMaxSize))
            {
                str = (char *)malloc(msg.tc.length);
                if (str==NULL)
                {
                    rfbLog("Unable to malloc %d bytes for a TextChat Message\n", msg.tc.length);
                    rfbCloseClient(cl);
                    return;
                }
                if ((n = rfbReadExact(cl, str, msg.tc.length)) <= 0) {
                    if (n != 0)
                        rfbLogPerror("rfbProcessClientNormalMessage: read");
                    free(str);
                    rfbCloseClient(cl);
                    return;
                }
                rfbStatRecordMessageRcvd(cl, msg.type, sz_rfbTextChatMsg+msg.tc.length, sz_rfbTextChatMsg+msg.tc.length);
            }
            else {
                
                rfbLog("client sent us a Text Message that is too big %d>%d\n", msg.tc.length, rfbTextMaxSize);
                rfbCloseClient(cl);
                return;
            }
        }

        
        if (cl->screen->setTextChat!=NULL)
            cl->screen->setTextChat(cl, msg.tc.length, str);

        free(str);
        return;


    case rfbClientCutText:

	if ((n = rfbReadExact(cl, ((char *)&msg) + 1, sz_rfbClientCutTextMsg - 1)) <= 0) {
	    if (n != 0)
		rfbLogPerror("rfbProcessClientNormalMessage: read");
	    rfbCloseClient(cl);
	    return;
	}

	msg.cct.length = Swap32IfLE(msg.cct.length);

	
	if (msg.cct.length > 1<<20) {
	    rfbLog("rfbClientCutText: too big cut text length requested: %u B > 1 MB\n", (unsigned int)msg.cct.length);
	    rfbCloseClient(cl);
	    return;
	}

	
	str = (char *)calloc(msg.cct.length ? msg.cct.length : 1, 1);
	if (str == NULL) {
		rfbLogPerror("rfbProcessClientNormalMessage: not enough memory");
		rfbCloseClient(cl);
		return;
	}

	if ((n = rfbReadExact(cl, str, msg.cct.length)) <= 0) {
	    if (n != 0)
	        rfbLogPerror("rfbProcessClientNormalMessage: read");
	    free(str);
	    rfbCloseClient(cl);
	    return;
	}
	rfbStatRecordMessageRcvd(cl, msg.type, sz_rfbClientCutTextMsg+msg.cct.length, sz_rfbClientCutTextMsg+msg.cct.length);
	if(!cl->viewOnly) {
	    cl->screen->setXCutText(str, msg.cct.length, cl);
	}
	free(str);

        return;

    case rfbPalmVNCSetScaleFactor:
      cl->PalmVNC = TRUE;
      if ((n = rfbReadExact(cl, ((char *)&msg) + 1, sz_rfbSetScaleMsg - 1)) <= 0) {
          if (n != 0)
            rfbLogPerror("rfbProcessClientNormalMessage: read");
          rfbCloseClient(cl);
          return;
      }

      if (msg.ssc.scale == 0) {
          rfbLogPerror("rfbProcessClientNormalMessage: will not accept a scale factor of zero");
          rfbCloseClient(cl);
          return;
      }

      rfbStatRecordMessageRcvd(cl, msg.type, sz_rfbSetScaleMsg, sz_rfbSetScaleMsg);
      rfbLog("rfbSetScale(%d)\n", msg.ssc.scale);
      rfbScalingSetup(cl,cl->screen->width/msg.ssc.scale, cl->screen->height/msg.ssc.scale);

      rfbSendNewScaleSize(cl);
      return;
      
    case rfbSetScale:

      if ((n = rfbReadExact(cl, ((char *)&msg) + 1, sz_rfbSetScaleMsg - 1)) <= 0) {
          if (n != 0)
            rfbLogPerror("rfbProcessClientNormalMessage: read");
          rfbCloseClient(cl);
          return;
      }

      if (msg.ssc.scale == 0) {
          rfbLogPerror("rfbProcessClientNormalMessage: will not accept a scale factor of zero");
          rfbCloseClient(cl);
          return;
      }

      rfbStatRecordMessageRcvd(cl, msg.type, sz_rfbSetScaleMsg, sz_rfbSetScaleMsg);
      rfbLog("rfbSetScale(%d)\n", msg.ssc.scale);
      rfbScalingSetup(cl,cl->screen->width/msg.ssc.scale, cl->screen->height/msg.ssc.scale);

      rfbSendNewScaleSize(cl);
      return;

    case rfbXvp:

      if ((n = rfbReadExact(cl, ((char *)&msg) + 1, sz_rfbXvpMsg - 1)) <= 0) {
          if (n != 0)
            rfbLogPerror("rfbProcessClientNormalMessage: read");
          rfbCloseClient(cl);
          return;
      }
      rfbStatRecordMessageRcvd(cl, msg.type, sz_rfbXvpMsg, sz_rfbXvpMsg);

      
      if(msg.xvp.version != 1) {
	rfbSendXvp(cl, msg.xvp.version, rfbXvp_Fail);
      }
      else {
	
	if(cl->screen->xvpHook && !cl->screen->xvpHook(cl, msg.xvp.version, msg.xvp.code))
	  rfbSendXvp(cl, 1, rfbXvp_Fail);
      }
      return;

    case rfbSetDesktopSize:

        if ((n = rfbReadExact(cl, ((char *)&msg) + 1, sz_rfbSetDesktopSizeMsg - 1)) <= 0) {
            if (n != 0)
              rfbLogPerror("rfbProcessClientNormalMessage: read");
            rfbCloseClient(cl);
            return;
        }

        if (msg.sdm.numberOfScreens == 0) {
            rfbLog("Ignoring setDesktopSize message from client that defines zero screens\n");
            return;
        }

        extDesktopScreens = (rfbExtDesktopScreen *) malloc(msg.sdm.numberOfScreens * sz_rfbExtDesktopScreen);
        if (extDesktopScreens == NULL) {
                rfbLogPerror("rfbProcessClientNormalMessage: not enough memory");
                rfbCloseClient(cl);
                return;
        }

        if ((n = rfbReadExact(cl, ((char *)extDesktopScreens), msg.sdm.numberOfScreens * sz_rfbExtDesktopScreen)) <= 0) {
            if (n != 0)
                rfbLogPerror("rfbProcessClientNormalMessage: read");
            free(extDesktopScreens);
            rfbCloseClient(cl);
            return;
        }
        rfbStatRecordMessageRcvd(cl, msg.type, sz_rfbSetDesktopSizeMsg + msg.sdm.numberOfScreens * sz_rfbExtDesktopScreen, sz_rfbSetDesktopSizeMsg + msg.sdm.numberOfScreens * sz_rfbExtDesktopScreen);

        for (i=0; i < msg.sdm.numberOfScreens; i++) {
            extDesktopScreens[i].id = Swap32IfLE(extDesktopScreens[i].id);
            extDesktopScreens[i].x = Swap16IfLE(extDesktopScreens[i].x);
            extDesktopScreens[i].y = Swap16IfLE(extDesktopScreens[i].y);
            extDesktopScreens[i].width = Swap16IfLE(extDesktopScreens[i].width);
            extDesktopScreens[i].height = Swap16IfLE(extDesktopScreens[i].height);
            extDesktopScreens[i].flags = Swap32IfLE(extDesktopScreens[i].flags);
        }
        msg.sdm.width = Swap16IfLE(msg.sdm.width);
        msg.sdm.height = Swap16IfLE(msg.sdm.height);

        rfbLog("Client requested resolution change to (%dx%d)\n", msg.sdm.width, msg.sdm.height);
        cl->requestedDesktopSizeChange = rfbExtDesktopSize_ClientRequestedChange;
        cl->lastDesktopSizeChangeError = cl->screen->setDesktopSizeHook(msg.sdm.width, msg.sdm.height, msg.sdm.numberOfScreens, extDesktopScreens, cl);

        if (cl->lastDesktopSizeChangeError == 0) {
            
            iterator = rfbGetClientIterator(cl->screen);
            while ((clp = rfbClientIteratorNext(iterator)) != NULL) {
                LOCK(clp->updateMutex);
                if (clp != cl)
                    clp->requestedDesktopSizeChange = rfbExtDesktopSize_OtherClientRequestedChange;
                UNLOCK(clp->updateMutex);
            }
        }
        else {
            
            cl->newFBSizePending = TRUE;
        }

        free(extDesktopScreens);
        return;

    default:
	{
	    rfbExtensionData *e,*next;

	    for(e=cl->extensions; e;) {
		next = e->next;
		if(e->extension->handleMessage && e->extension->handleMessage(cl, e->data, &msg))
                {
                    rfbStatRecordMessageRcvd(cl, msg.type, 0, 0); 
		    return;
                }
		e = next;
	    }

	    rfbLog("rfbProcessClientNormalMessage: unknown message type %d\n", msg.type);
	    rfbLog(" ... closing connection\n");
	    rfbCloseClient(cl);
	    return;
	}
    }
}





rfbBool rfbSendFramebufferUpdate(rfbClientPtr cl, sraRegionPtr givenUpdateRegion)

{
    sraRectangleIterator* i=NULL;
    sraRect rect;
    int nUpdateRegionRects;
    rfbFramebufferUpdateMsg *fu = (rfbFramebufferUpdateMsg *)cl->updateBuf;
    sraRegionPtr updateRegion,updateCopyRegion,tmpRegion;
    int dx, dy;
    rfbBool sendCursorShape = FALSE;
    rfbBool sendCursorPos = FALSE;
    rfbBool sendKeyboardLedState = FALSE;
    rfbBool sendSupportedMessages = FALSE;
    rfbBool sendSupportedEncodings = FALSE;
    rfbBool sendServerIdentity = FALSE;
    rfbBool result = TRUE;
    

    if(cl->screen->displayHook)
      cl->screen->displayHook(cl);

    

    if (cl->useNewFBSize && cl->newFBSizePending) {
      LOCK(cl->updateMutex);
      cl->newFBSizePending = FALSE;
      UNLOCK(cl->updateMutex);
      fu->type = rfbFramebufferUpdate;
      fu->nRects = Swap16IfLE(1);
      cl->ublen = sz_rfbFramebufferUpdateMsg;

      if (cl->useExtDesktopSize) {
        if (!rfbSendExtDesktopSize(cl, cl->scaledScreen->width, cl->scaledScreen->height)) {
          if(cl->screen->displayFinishedHook)
            cl->screen->displayFinishedHook(cl, FALSE);
          return FALSE;
        }
      }
      else if (!rfbSendNewFBSize(cl, cl->scaledScreen->width, cl->scaledScreen->height)) {
	if(cl->screen->displayFinishedHook)
	  cl->screen->displayFinishedHook(cl, FALSE);
        return FALSE;
      }
      result = rfbSendUpdateBuf(cl);
      if(cl->screen->displayFinishedHook)
	cl->screen->displayFinishedHook(cl, result);
      return result;
    }
    
    

    if (cl->enableCursorShapeUpdates) {
      if (cl->cursorWasChanged && cl->readyForSetColourMapEntries)
	  sendCursorShape = TRUE;
    }

    

    if (cl->enableCursorPosUpdates && cl->cursorWasMoved)
      sendCursorPos = TRUE;

    
    if ((cl->enableKeyboardLedState) && (cl->screen->getKeyboardLedStateHook!=NULL))
    {
        int x;
        x=cl->screen->getKeyboardLedStateHook(cl->screen);
        if (x!=cl->lastKeyboardLedState)
        {
            sendKeyboardLedState = TRUE;
            cl->lastKeyboardLedState=x;
        }
    }

    
    if (cl->enableSupportedMessages)
    {
        sendSupportedMessages = TRUE;
        
        cl->enableSupportedMessages = FALSE;
    }
    
    if (cl->enableSupportedEncodings)
    {
        sendSupportedEncodings = TRUE;
        
        cl->enableSupportedEncodings = FALSE;
    }
    
    if (cl->enableServerIdentity)
    {
        sendServerIdentity = TRUE;
        
        cl->enableServerIdentity = FALSE;
    }

    LOCK(cl->updateMutex);

    
    
    sraRgnSubtract(cl->copyRegion,cl->modifiedRegion);

    

    updateRegion = sraRgnCreateRgn(givenUpdateRegion);
    if(cl->screen->progressiveSliceHeight>0) {
	    int height=cl->screen->progressiveSliceHeight, y=cl->progressiveSliceY;
	    sraRegionPtr bbox=sraRgnBBox(updateRegion);
	    sraRect rect;
	    if(sraRgnPopRect(bbox,&rect,0)) {
		sraRegionPtr slice;
		if(y<rect.y1 || y>=rect.y2)
		    y=rect.y1;
	    	slice=sraRgnCreateRect(0,y,cl->screen->width,y+height);
		sraRgnAnd(updateRegion,slice);
		sraRgnDestroy(slice);
	    }
	    sraRgnDestroy(bbox);
	    y+=height;
	    if(y>=cl->screen->height)
		    y=0;
	    cl->progressiveSliceY=y;
    }

    sraRgnOr(updateRegion,cl->copyRegion);
    if(!sraRgnAnd(updateRegion,cl->requestedRegion) && sraRgnEmpty(updateRegion) && (cl->enableCursorShapeUpdates || (cl->cursorX == cl->screen->cursorX && cl->cursorY == cl->screen->cursorY)) && !sendCursorShape && !sendCursorPos && !sendKeyboardLedState && !sendSupportedMessages && !sendSupportedEncodings && !sendServerIdentity) {




      sraRgnDestroy(updateRegion);
      UNLOCK(cl->updateMutex);
      if(cl->screen->displayFinishedHook)
	cl->screen->displayFinishedHook(cl, TRUE);
      return TRUE;
    }

    

    updateCopyRegion = sraRgnCreateRgn(cl->copyRegion);
    sraRgnAnd(updateCopyRegion,cl->requestedRegion);
    tmpRegion = sraRgnCreateRgn(cl->requestedRegion);
    sraRgnOffset(tmpRegion,cl->copyDX,cl->copyDY);
    sraRgnAnd(updateCopyRegion,tmpRegion);
    sraRgnDestroy(tmpRegion);
    dx = cl->copyDX;
    dy = cl->copyDY;

    

    sraRgnSubtract(updateRegion,updateCopyRegion);

    

     sraRgnOr(cl->modifiedRegion,cl->copyRegion);
     sraRgnSubtract(cl->modifiedRegion,updateRegion);
     sraRgnSubtract(cl->modifiedRegion,updateCopyRegion);

     sraRgnMakeEmpty(cl->requestedRegion);
     sraRgnMakeEmpty(cl->copyRegion);
     cl->copyDX = 0;
     cl->copyDY = 0;
   
     UNLOCK(cl->updateMutex);
   
    if (!cl->enableCursorShapeUpdates) {
      if(cl->cursorX != cl->screen->cursorX || cl->cursorY != cl->screen->cursorY) {
	rfbRedrawAfterHideCursor(cl,updateRegion);
	LOCK(cl->screen->cursorMutex);
	cl->cursorX = cl->screen->cursorX;
	cl->cursorY = cl->screen->cursorY;
	UNLOCK(cl->screen->cursorMutex);
	rfbRedrawAfterHideCursor(cl,updateRegion);
      }
      rfbShowCursor(cl);
    }

    
    
    rfbStatRecordMessageSent(cl, rfbFramebufferUpdate, 0, 0);
    if (cl->preferredEncoding == rfbEncodingCoRRE) {
        nUpdateRegionRects = 0;

        for(i = sraRgnGetIterator(updateRegion); sraRgnIteratorNext(i,&rect);){
            int x = rect.x1;
            int y = rect.y1;
            int w = rect.x2 - x;
            int h = rect.y2 - y;
	    int rectsPerRow, rows;
            
            if (cl->screen!=cl->scaledScreen)
                rfbScaledCorrection(cl->screen, cl->scaledScreen, &x, &y, &w, &h, "rfbSendFramebufferUpdate");
	    rectsPerRow = (w-1)/cl->correMaxWidth+1;
	    rows = (h-1)/cl->correMaxHeight+1;
	    nUpdateRegionRects += rectsPerRow*rows;
        }
	sraRgnReleaseIterator(i); i=NULL;
    } else if (cl->preferredEncoding == rfbEncodingUltra) {
        nUpdateRegionRects = 0;
        
        for(i = sraRgnGetIterator(updateRegion); sraRgnIteratorNext(i,&rect);){
            int x = rect.x1;
            int y = rect.y1;
            int w = rect.x2 - x;
            int h = rect.y2 - y;
            
            if (cl->screen!=cl->scaledScreen)
                rfbScaledCorrection(cl->screen, cl->scaledScreen, &x, &y, &w, &h, "rfbSendFramebufferUpdate");
            nUpdateRegionRects += (((h-1) / (ULTRA_MAX_SIZE( w ) / w)) + 1);
          }
        sraRgnReleaseIterator(i); i=NULL;

    } else if (cl->preferredEncoding == rfbEncodingZlib) {
	nUpdateRegionRects = 0;

        for(i = sraRgnGetIterator(updateRegion); sraRgnIteratorNext(i,&rect);){
            int x = rect.x1;
            int y = rect.y1;
            int w = rect.x2 - x;
            int h = rect.y2 - y;
            
            if (cl->screen!=cl->scaledScreen)
                rfbScaledCorrection(cl->screen, cl->scaledScreen, &x, &y, &w, &h, "rfbSendFramebufferUpdate");
	    nUpdateRegionRects += (((h-1) / (ZLIB_MAX_SIZE( w ) / w)) + 1);
	}
	sraRgnReleaseIterator(i); i=NULL;

    } else if (cl->preferredEncoding == rfbEncodingTight) {
	nUpdateRegionRects = 0;

        for(i = sraRgnGetIterator(updateRegion); sraRgnIteratorNext(i,&rect);){
            int x = rect.x1;
            int y = rect.y1;
            int w = rect.x2 - x;
            int h = rect.y2 - y;
            int n;
            
            if (cl->screen!=cl->scaledScreen)
                rfbScaledCorrection(cl->screen, cl->scaledScreen, &x, &y, &w, &h, "rfbSendFramebufferUpdate");
	    n = rfbNumCodedRectsTight(cl, x, y, w, h);
	    if (n == 0) {
		nUpdateRegionRects = 0xFFFF;
		break;
	    }
	    nUpdateRegionRects += n;
	}
	sraRgnReleaseIterator(i); i=NULL;



    } else if (cl->preferredEncoding == rfbEncodingTightPng) {
	nUpdateRegionRects = 0;

        for(i = sraRgnGetIterator(updateRegion); sraRgnIteratorNext(i,&rect);){
            int x = rect.x1;
            int y = rect.y1;
            int w = rect.x2 - x;
            int h = rect.y2 - y;
            int n;
            
            if (cl->screen!=cl->scaledScreen)
                rfbScaledCorrection(cl->screen, cl->scaledScreen, &x, &y, &w, &h, "rfbSendFramebufferUpdate");
	    n = rfbNumCodedRectsTight(cl, x, y, w, h);
	    if (n == 0) {
		nUpdateRegionRects = 0xFFFF;
		break;
	    }
	    nUpdateRegionRects += n;
	}
	sraRgnReleaseIterator(i); i=NULL;

    } else {
        nUpdateRegionRects = sraRgnCountRects(updateRegion);
    }

    fu->type = rfbFramebufferUpdate;
    if (nUpdateRegionRects != 0xFFFF) {
	if(cl->screen->maxRectsPerUpdate>0  && cl->preferredEncoding != rfbEncodingCoRRE  && cl->preferredEncoding != rfbEncodingUltra   && cl->preferredEncoding != rfbEncodingZlib   && cl->preferredEncoding != rfbEncodingTight     && cl->preferredEncoding != rfbEncodingTightPng  && nUpdateRegionRects>cl->screen->maxRectsPerUpdate) {
















	    sraRegion* newUpdateRegion = sraRgnBBox(updateRegion);
	    sraRgnDestroy(updateRegion);
	    updateRegion = newUpdateRegion;
	    nUpdateRegionRects = sraRgnCountRects(updateRegion);
	}
	fu->nRects = Swap16IfLE((uint16_t)(sraRgnCountRects(updateCopyRegion) + nUpdateRegionRects + !!sendCursorShape + !!sendCursorPos + !!sendKeyboardLedState + !!sendSupportedMessages + !!sendSupportedEncodings + !!sendServerIdentity));


    } else {
	fu->nRects = 0xFFFF;
    }
    cl->ublen = sz_rfbFramebufferUpdateMsg;

   if (sendCursorShape) {
	cl->cursorWasChanged = FALSE;
	if (!rfbSendCursorShape(cl))
	    goto updateFailed;
    }
   
   if (sendCursorPos) {
	cl->cursorWasMoved = FALSE;
	if (!rfbSendCursorPos(cl))
	        goto updateFailed;
   }
   
   if (sendKeyboardLedState) {
       if (!rfbSendKeyboardLedState(cl))
           goto updateFailed;
   }

   if (sendSupportedMessages) {
       if (!rfbSendSupportedMessages(cl))
           goto updateFailed;
   }
   if (sendSupportedEncodings) {
       if (!rfbSendSupportedEncodings(cl))
           goto updateFailed;
   }
   if (sendServerIdentity) {
       if (!rfbSendServerIdentity(cl))
           goto updateFailed;
   }

    if (!sraRgnEmpty(updateCopyRegion)) {
	if (!rfbSendCopyRegion(cl,updateCopyRegion,dx,dy))
	        goto updateFailed;
    }

    for(i = sraRgnGetIterator(updateRegion); sraRgnIteratorNext(i,&rect);){
        int x = rect.x1;
        int y = rect.y1;
        int w = rect.x2 - x;
        int h = rect.y2 - y;

        
        if (cl->screen!=cl->scaledScreen)
            rfbScaledCorrection(cl->screen, cl->scaledScreen, &x, &y, &w, &h, "rfbSendFramebufferUpdate");

        switch (cl->preferredEncoding) {
	case -1:
        case rfbEncodingRaw:
            if (!rfbSendRectEncodingRaw(cl, x, y, w, h))
	        goto updateFailed;
            break;
        case rfbEncodingRRE:
            if (!rfbSendRectEncodingRRE(cl, x, y, w, h))
	        goto updateFailed;
            break;
        case rfbEncodingCoRRE:
            if (!rfbSendRectEncodingCoRRE(cl, x, y, w, h))
	        goto updateFailed;
	    break;
        case rfbEncodingHextile:
            if (!rfbSendRectEncodingHextile(cl, x, y, w, h))
	        goto updateFailed;
            break;
        case rfbEncodingUltra:
            if (!rfbSendRectEncodingUltra(cl, x, y, w, h))
                goto updateFailed;
            break;

	case rfbEncodingZlib:
	    if (!rfbSendRectEncodingZlib(cl, x, y, w, h))
	        goto updateFailed;
	    break;
       case rfbEncodingZRLE:
       case rfbEncodingZYWRLE:
           if (!rfbSendRectEncodingZRLE(cl, x, y, w, h))
	       goto updateFailed;
           break;


	case rfbEncodingTight:
	    if (!rfbSendRectEncodingTight(cl, x, y, w, h))
	        goto updateFailed;
	    break;

	case rfbEncodingTightPng:
	    if (!rfbSendRectEncodingTightPng(cl, x, y, w, h))
	        goto updateFailed;
	    break;


        }
    }
    if (i) {
        sraRgnReleaseIterator(i);
        i = NULL;
    }

    if ( nUpdateRegionRects == 0xFFFF && !rfbSendLastRectMarker(cl) )
	    goto updateFailed;

    if (!rfbSendUpdateBuf(cl)) {
updateFailed:
	result = FALSE;
    }

    if (!cl->enableCursorShapeUpdates) {
      rfbHideCursor(cl);
    }

    if(i)
        sraRgnReleaseIterator(i);
    sraRgnDestroy(updateRegion);
    sraRgnDestroy(updateCopyRegion);

    if(cl->screen->displayFinishedHook)
      cl->screen->displayFinishedHook(cl, result);
    return result;
}




rfbBool rfbSendCopyRegion(rfbClientPtr cl, sraRegionPtr reg, int dx, int dy)



{
    int x, y, w, h;
    rfbFramebufferUpdateRectHeader rect;
    rfbCopyRect cr;
    sraRectangleIterator* i;
    sraRect rect1;

    
    i = sraRgnGetReverseIterator(reg,dx>0,dy>0);

    
    dx = ScaleX(cl->screen, cl->scaledScreen, dx);
    dy = ScaleX(cl->screen, cl->scaledScreen, dy);

    while(sraRgnIteratorNext(i,&rect1)) {
      x = rect1.x1;
      y = rect1.y1;
      w = rect1.x2 - x;
      h = rect1.y2 - y;

      
      rfbScaledCorrection(cl->screen, cl->scaledScreen, &x, &y, &w, &h, "copyrect");

      rect.r.x = Swap16IfLE(x);
      rect.r.y = Swap16IfLE(y);
      rect.r.w = Swap16IfLE(w);
      rect.r.h = Swap16IfLE(h);
      rect.encoding = Swap32IfLE(rfbEncodingCopyRect);

      memcpy(&cl->updateBuf[cl->ublen], (char *)&rect, sz_rfbFramebufferUpdateRectHeader);
      cl->ublen += sz_rfbFramebufferUpdateRectHeader;

      cr.srcX = Swap16IfLE(x - dx);
      cr.srcY = Swap16IfLE(y - dy);

      memcpy(&cl->updateBuf[cl->ublen], (char *)&cr, sz_rfbCopyRect);
      cl->ublen += sz_rfbCopyRect;

      rfbStatRecordEncodingSent(cl, rfbEncodingCopyRect, sz_rfbFramebufferUpdateRectHeader + sz_rfbCopyRect, w * h  * (cl->scaledScreen->bitsPerPixel / 8));
    }
    sraRgnReleaseIterator(i);

    return TRUE;
}



rfbBool rfbSendRectEncodingRaw(rfbClientPtr cl, int x, int y, int w, int h)




{
    rfbFramebufferUpdateRectHeader rect;
    int nlines;
    int bytesPerLine = w * (cl->format.bitsPerPixel / 8);
    char *fbptr = (cl->scaledScreen->frameBuffer + (cl->scaledScreen->paddedWidthInBytes * y)
                   + (x * (cl->scaledScreen->bitsPerPixel / 8)));

    if(!h || !w)
	return TRUE; 

    
    if (cl->ublen > 0) {
        if (!rfbSendUpdateBuf(cl))
            return FALSE;
    }

    rect.r.x = Swap16IfLE(x);
    rect.r.y = Swap16IfLE(y);
    rect.r.w = Swap16IfLE(w);
    rect.r.h = Swap16IfLE(h);
    rect.encoding = Swap32IfLE(rfbEncodingRaw);

    memcpy(&cl->updateBuf[cl->ublen], (char *)&rect,sz_rfbFramebufferUpdateRectHeader);
    cl->ublen += sz_rfbFramebufferUpdateRectHeader;


    rfbStatRecordEncodingSent(cl, rfbEncodingRaw, sz_rfbFramebufferUpdateRectHeader + bytesPerLine * h, sz_rfbFramebufferUpdateRectHeader + bytesPerLine * h);

    nlines = (UPDATE_BUF_SIZE - cl->ublen) / bytesPerLine;

    while (TRUE) {
        if (nlines > h)
            nlines = h;

        (*cl->translateFn)(cl->translateLookupTable, &(cl->screen->serverFormat), &cl->format, fbptr, &cl->updateBuf[cl->ublen], cl->scaledScreen->paddedWidthInBytes, w, nlines);



        cl->ublen += nlines * bytesPerLine;
        h -= nlines;

        if (h == 0)     
            return TRUE;

        

        if (!rfbSendUpdateBuf(cl))
            return FALSE;

        fbptr += (cl->scaledScreen->paddedWidthInBytes * nlines);

        nlines = (UPDATE_BUF_SIZE - cl->ublen) / bytesPerLine;
        if (nlines == 0) {
            rfbErr("rfbSendRectEncodingRaw: send buffer too small for %d " "bytes per line\n", bytesPerLine);
            rfbCloseClient(cl);
            return FALSE;
        }
    }
}





rfbBool rfbSendLastRectMarker(rfbClientPtr cl)
{
    rfbFramebufferUpdateRectHeader rect;

    if (cl->ublen + sz_rfbFramebufferUpdateRectHeader > UPDATE_BUF_SIZE) {
	if (!rfbSendUpdateBuf(cl))
	    return FALSE;
    }

    rect.encoding = Swap32IfLE(rfbEncodingLastRect);
    rect.r.x = 0;
    rect.r.y = 0;
    rect.r.w = 0;
    rect.r.h = 0;

    memcpy(&cl->updateBuf[cl->ublen], (char *)&rect,sz_rfbFramebufferUpdateRectHeader);
    cl->ublen += sz_rfbFramebufferUpdateRectHeader;


    rfbStatRecordEncodingSent(cl, rfbEncodingLastRect, sz_rfbFramebufferUpdateRectHeader, sz_rfbFramebufferUpdateRectHeader);

    return TRUE;
}




rfbBool rfbSendNewFBSize(rfbClientPtr cl, int w, int h)


{
    rfbFramebufferUpdateRectHeader rect;

    if (cl->ublen + sz_rfbFramebufferUpdateRectHeader > UPDATE_BUF_SIZE) {
	if (!rfbSendUpdateBuf(cl))
	    return FALSE;
    }

    if (cl->PalmVNC==TRUE)
        rfbLog("Sending rfbEncodingNewFBSize in response to a PalmVNC style framebuffer resize (%dx%d)\n", w, h);
    else rfbLog("Sending rfbEncodingNewFBSize for resize to (%dx%d)\n", w, h);

    rect.encoding = Swap32IfLE(rfbEncodingNewFBSize);
    rect.r.x = 0;
    rect.r.y = 0;
    rect.r.w = Swap16IfLE(w);
    rect.r.h = Swap16IfLE(h);

    memcpy(&cl->updateBuf[cl->ublen], (char *)&rect, sz_rfbFramebufferUpdateRectHeader);
    cl->ublen += sz_rfbFramebufferUpdateRectHeader;

    rfbStatRecordEncodingSent(cl, rfbEncodingNewFBSize, sz_rfbFramebufferUpdateRectHeader, sz_rfbFramebufferUpdateRectHeader);

    return TRUE;
}



rfbBool rfbSendExtDesktopSize(rfbClientPtr cl, int w, int h)


{
    rfbFramebufferUpdateRectHeader rect;
    rfbExtDesktopSizeMsg edsHdr;
    rfbExtDesktopScreen eds;
    int i;
    char *logmsg;
    int numScreens = cl->screen->numberOfExtDesktopScreensHook(cl);

    if (cl->ublen + sz_rfbFramebufferUpdateRectHeader + sz_rfbExtDesktopSizeMsg + sz_rfbExtDesktopScreen * numScreens > UPDATE_BUF_SIZE) {

        if (!rfbSendUpdateBuf(cl))
            return FALSE;
    }

    rect.encoding = Swap32IfLE(rfbEncodingExtDesktopSize);
    rect.r.w = Swap16IfLE(w);
    rect.r.h = Swap16IfLE(h);
    rect.r.x = Swap16IfLE(cl->requestedDesktopSizeChange);
    rect.r.y = Swap16IfLE(cl->lastDesktopSizeChangeError);

    logmsg = "";

    if (cl->requestedDesktopSizeChange == rfbExtDesktopSize_ClientRequestedChange)
    {
        

        switch (cl->lastDesktopSizeChangeError)
        {
        case rfbExtDesktopSize_Success:
            logmsg = "resize successful";
            break;
        case rfbExtDesktopSize_ResizeProhibited:
            logmsg = "resize prohibited";
            break;
        case rfbExtDesktopSize_OutOfResources:
            logmsg = "resize failed: out of resources";
            break;
        case rfbExtDesktopSize_InvalidScreenLayout:
            logmsg = "resize failed: invalid screen layout";
            break;
        default:
            break;
        }
    }

    cl->requestedDesktopSizeChange = 0;
    cl->lastDesktopSizeChangeError = 0;

    rfbLog("Sending rfbEncodingExtDesktopSize for size (%dx%d) %s\n", w, h, logmsg);

    memcpy(&cl->updateBuf[cl->ublen], (char *)&rect, sz_rfbFramebufferUpdateRectHeader);
    cl->ublen += sz_rfbFramebufferUpdateRectHeader;

    edsHdr.numberOfScreens = numScreens;
    edsHdr.pad[0] = edsHdr.pad[1] = edsHdr.pad[2] = 0;
    memcpy(&cl->updateBuf[cl->ublen], (char *)&edsHdr, sz_rfbExtDesktopSizeMsg);
    cl->ublen += sz_rfbExtDesktopSizeMsg;

    for (i=0; i<numScreens; i++) {
        if (!cl->screen->getExtDesktopScreenHook(i, &eds, cl))
        {
            rfbErr("Error getting ExtendedDesktopSize information for screen #%d\n", i);
            return FALSE;
        }
        eds.id = Swap32IfLE(eds.id);
        eds.x = Swap16IfLE(eds.x);
        eds.y = Swap16IfLE(eds.y);
        eds.width = Swap16IfLE(eds.width);
        eds.height = Swap16IfLE(eds.height);
        eds.flags = Swap32IfLE(eds.flags);
        memcpy(&cl->updateBuf[cl->ublen], (char *)&eds, sz_rfbExtDesktopScreen);
        cl->ublen += sz_rfbExtDesktopScreen;
    }

    rfbStatRecordEncodingSent(cl, rfbEncodingExtDesktopSize, sz_rfbFramebufferUpdateRectHeader + sz_rfbExtDesktopSizeMsg + sz_rfbExtDesktopScreen * numScreens, sz_rfbFramebufferUpdateRectHeader + sz_rfbExtDesktopSizeMsg + sz_rfbExtDesktopScreen * numScreens);


    return TRUE;
}



rfbBool rfbSendUpdateBuf(rfbClientPtr cl)
{
    if(cl->sock<0)
      return FALSE;

    if (rfbWriteExact(cl, cl->updateBuf, cl->ublen) < 0) {
        rfbLogPerror("rfbSendUpdateBuf: write");
        rfbCloseClient(cl);
        return FALSE;
    }

    cl->ublen = 0;
    return TRUE;
}



rfbBool rfbSendSetColourMapEntries(rfbClientPtr cl, int firstColour, int nColours)


{
    char buf[sz_rfbSetColourMapEntriesMsg + 256 * 3 * 2];
    char *wbuf = buf;
    rfbSetColourMapEntriesMsg *scme;
    uint16_t *rgb;
    rfbColourMap* cm = &cl->screen->colourMap;
    int i, len;

    if (nColours > 256) {
	
    	wbuf = (char *) malloc(sz_rfbSetColourMapEntriesMsg + nColours * 3 * 2);
    }

    scme = (rfbSetColourMapEntriesMsg *)wbuf;
    rgb = (uint16_t *)(&wbuf[sz_rfbSetColourMapEntriesMsg]);

    scme->type = rfbSetColourMapEntries;

    scme->firstColour = Swap16IfLE(firstColour);
    scme->nColours = Swap16IfLE(nColours);

    len = sz_rfbSetColourMapEntriesMsg;

    for (i = 0; i < nColours; i++) {
      if(i<(int)cm->count) {
	if(cm->is16) {
	  rgb[i*3] = Swap16IfLE(cm->data.shorts[i*3]);
	  rgb[i*3+1] = Swap16IfLE(cm->data.shorts[i*3+1]);
	  rgb[i*3+2] = Swap16IfLE(cm->data.shorts[i*3+2]);
	} else {
	  rgb[i*3] = Swap16IfLE((unsigned short)cm->data.bytes[i*3]);
	  rgb[i*3+1] = Swap16IfLE((unsigned short)cm->data.bytes[i*3+1]);
	  rgb[i*3+2] = Swap16IfLE((unsigned short)cm->data.bytes[i*3+2]);
	}
      }
    }

    len += nColours * 3 * 2;

    LOCK(cl->sendMutex);
    if (rfbWriteExact(cl, wbuf, len) < 0) {
	rfbLogPerror("rfbSendSetColourMapEntries: write");
	rfbCloseClient(cl);
        if (wbuf != buf) free(wbuf);
        UNLOCK(cl->sendMutex);
	return FALSE;
    }
    UNLOCK(cl->sendMutex);

    rfbStatRecordMessageSent(cl, rfbSetColourMapEntries, len, len);
    if (wbuf != buf) free(wbuf);
    return TRUE;
}



void rfbSendBell(rfbScreenInfoPtr rfbScreen)
{
    rfbClientIteratorPtr i;
    rfbClientPtr cl;
    rfbBellMsg b;

    i = rfbGetClientIterator(rfbScreen);
    while((cl=rfbClientIteratorNext(i))) {
	b.type = rfbBell;
        LOCK(cl->sendMutex);
	if (rfbWriteExact(cl, (char *)&b, sz_rfbBellMsg) < 0) {
	    rfbLogPerror("rfbSendBell: write");
	    rfbCloseClient(cl);
	}
        UNLOCK(cl->sendMutex);
    }
    rfbStatRecordMessageSent(cl, rfbBell, sz_rfbBellMsg, sz_rfbBellMsg);
    rfbReleaseClientIterator(i);
}




void rfbSendServerCutText(rfbScreenInfoPtr rfbScreen,char *str, int len)
{
    rfbClientPtr cl;
    rfbServerCutTextMsg sct;
    rfbClientIteratorPtr iterator;

    memset((char *)&sct, 0, sizeof(sct));

    iterator = rfbGetClientIterator(rfbScreen);
    while ((cl = rfbClientIteratorNext(iterator)) != NULL) {
        sct.type = rfbServerCutText;
        sct.length = Swap32IfLE(len);
        LOCK(cl->sendMutex);
        if (rfbWriteExact(cl, (char *)&sct, sz_rfbServerCutTextMsg) < 0) {
            rfbLogPerror("rfbSendServerCutText: write");
            rfbCloseClient(cl);
            UNLOCK(cl->sendMutex);
            continue;
        }
        if (rfbWriteExact(cl, str, len) < 0) {
            rfbLogPerror("rfbSendServerCutText: write");
            rfbCloseClient(cl);
        }
        UNLOCK(cl->sendMutex);
        rfbStatRecordMessageSent(cl, rfbServerCutText, sz_rfbServerCutTextMsg+len, sz_rfbServerCutTextMsg+len);
    }
    rfbReleaseClientIterator(iterator);
}



static unsigned char ptrAcceleration = 50;

void rfbNewUDPConnection(rfbScreenInfoPtr rfbScreen, rfbSocket sock)

{
  if (write(sock, (char*) &ptrAcceleration, 1) < 0) {
	rfbLogPerror("rfbNewUDPConnection: write");
    }
}



void rfbProcessUDPInput(rfbScreenInfoPtr rfbScreen)
{
    int n;
    rfbClientPtr cl=rfbScreen->udpClient;
    rfbClientToServerMsg msg;

    if((!cl) || cl->onHold)
      return;

    if ((n = read(rfbScreen->udpSock, (char *)&msg, sizeof(msg))) <= 0) {
	if (n < 0) {
	    rfbLogPerror("rfbProcessUDPInput: read");
	}
	rfbDisconnectUDPSock(rfbScreen);
	return;
    }

    switch (msg.type) {

    case rfbKeyEvent:
	if (n != sz_rfbKeyEventMsg) {
	    rfbErr("rfbProcessUDPInput: key event incorrect length\n");
	    rfbDisconnectUDPSock(rfbScreen);
	    return;
	}
	cl->screen->kbdAddEvent(msg.ke.down, (rfbKeySym)Swap32IfLE(msg.ke.key), cl);
	break;

    case rfbPointerEvent:
	if (n != sz_rfbPointerEventMsg) {
	    rfbErr("rfbProcessUDPInput: ptr event incorrect length\n");
	    rfbDisconnectUDPSock(rfbScreen);
	    return;
	}
	cl->screen->ptrAddEvent(msg.pe.buttonMask, Swap16IfLE(msg.pe.x), Swap16IfLE(msg.pe.y), cl);
	break;

    default:
	rfbErr("rfbProcessUDPInput: unknown message type %d\n", msg.type);
	rfbDisconnectUDPSock(rfbScreen);
    }
}


