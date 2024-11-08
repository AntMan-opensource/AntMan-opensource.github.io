      #ifdef UNICODE





        #define _tcsnicmp(a,b,c) wcscasecmp(a,b)
    #else
        #define _tcsnicmp(a,b,c) strcasecmp(a,b)
    #endif




RGBQUAD	CxImage::GetTransColor()
{
	if (head.biBitCount<24 && info.nBkgndIndex>=0) return GetPaletteColor((uint8_t)info.nBkgndIndex);
	return info.nBkgndColor;
}


int32_t CxImage::GetTransIndex() const {
	return info.nBkgndIndex;
}


void CxImage::SetTransIndex(int32_t idx)
{
	if (idx<(int32_t)head.biClrUsed)
		info.nBkgndIndex = idx;
	else  info.nBkgndIndex = 0;
}


void CxImage::SetTransColor(RGBQUAD rgb)
{
	rgb.rgbReserved=0;
	info.nBkgndColor = rgb;
}

bool CxImage::IsTransparent() const {
	return info.nBkgndIndex>=0; 
}


bool CxImage::IsIndexed() const {
	return head.biClrUsed!=0;
}


uint8_t CxImage::GetColorType()
{
	uint8_t b = (uint8_t)((head.biBitCount>8) ? 2  : 1 );

	if (AlphaIsValid()) b = 4 ;

	return b;
}


int32_t CxImage::GetXDPI() const {
	return info.xDPI;
}


int32_t CxImage::GetYDPI() const {
	return info.yDPI;
}


void CxImage::SetXDPI(int32_t dpi)
{
	if (dpi<=0) dpi = CXIMAGE_DEFAULT_DPI;
	info.xDPI = dpi;
	head.biXPelsPerMeter = (int32_t) floor(dpi * 10000.0 / 254.0 + 0.5);
	if (pDib) ((BITMAPINFOHEADER*)pDib)->biXPelsPerMeter = head.biXPelsPerMeter;
}


void CxImage::SetYDPI(int32_t dpi)
{
	if (dpi<=0) dpi = CXIMAGE_DEFAULT_DPI;
	info.yDPI = dpi;
	head.biYPelsPerMeter = (int32_t) floor(dpi * 10000.0 / 254.0 + 0.5);
	if (pDib) ((BITMAPINFOHEADER*)pDib)->biYPelsPerMeter = head.biYPelsPerMeter;
}


uint32_t CxImage::GetFlags() const {
	return info.dwFlags;
}


void CxImage::SetFlags(uint32_t flags, bool bLockReservedFlags)
{
	if (bLockReservedFlags) info.dwFlags = flags & 0x0000ffff;
	else info.dwFlags = flags;
}


uint32_t CxImage::GetCodecOption(uint32_t imagetype)
{
	imagetype = GetTypeIndexFromId(imagetype);
	if (imagetype==0){
		imagetype = GetTypeIndexFromId(GetType());
	}
	return info.dwCodecOpt[imagetype];
}


bool CxImage::SetCodecOption(uint32_t opt, uint32_t imagetype)
{
	imagetype = GetTypeIndexFromId(imagetype);
	if (imagetype==0){
		imagetype = GetTypeIndexFromId(GetType());
	}
	info.dwCodecOpt[imagetype] = opt;
	return true;
}


void* CxImage::GetDIB() const {
	return pDib;
}

uint32_t CxImage::GetHeight() const {
	return head.biHeight;
}

uint32_t CxImage::GetWidth() const {
	return head.biWidth;
}


uint32_t CxImage::GetEffWidth() const {
	return info.dwEffWidth;
}


uint32_t CxImage::GetNumColors() const {
	return head.biClrUsed;
}


uint16_t CxImage::GetBpp() const {
	return head.biBitCount;
}


uint32_t CxImage::GetType() const {
	return info.dwType;
}


bool CxImage::SetType(uint32_t type)
{
	switch (type){

	case CXIMAGE_FORMAT_BMP:


	case CXIMAGE_FORMAT_GIF:


	case CXIMAGE_FORMAT_JPG:


	case CXIMAGE_FORMAT_PNG:


	case CXIMAGE_FORMAT_MNG:


	case CXIMAGE_FORMAT_ICO:


	case CXIMAGE_FORMAT_TIF:


	case CXIMAGE_FORMAT_TGA:


	case CXIMAGE_FORMAT_PCX:


	case CXIMAGE_FORMAT_WBMP:


	case CXIMAGE_FORMAT_WMF:


	case CXIMAGE_FORMAT_JBG:


	case CXIMAGE_FORMAT_JP2:


	case CXIMAGE_FORMAT_JPC:


	case CXIMAGE_FORMAT_PGX:


	case CXIMAGE_FORMAT_PNM:


	case CXIMAGE_FORMAT_RAS:


	case CXIMAGE_FORMAT_SKA:


	case CXIMAGE_FORMAT_RAW:


	case CXIMAGE_FORMAT_PSD:

		info.dwType = type;
		return true;
	case CXIMAGE_FORMAT_UNKNOWN:
	default:
		info.dwType = CXIMAGE_FORMAT_UNKNOWN;
	}
	return false;
}

uint32_t CxImage::GetNumTypes()
{
	return CMAX_IMAGE_FORMATS-1;
}

uint32_t CxImage::GetTypeIdFromName(const TCHAR* ext)
{

	if (_tcsnicmp(ext,_T("bmp"),3)==0 )		return CXIMAGE_FORMAT_BMP;


	if (_tcsnicmp(ext,_T("jpg"),3)==0 || _tcsnicmp(ext,_T("jpe"),3)==0 || _tcsnicmp(ext,_T("jfi"),3)==0 )		return CXIMAGE_FORMAT_JPG;



	if (_tcsnicmp(ext,_T("gif"),3)==0 )		return CXIMAGE_FORMAT_GIF;


	if (_tcsnicmp(ext,_T("png"),3)==0 )		return CXIMAGE_FORMAT_PNG;


	if (_tcsnicmp(ext,_T("ico"),3)==0 || _tcsnicmp(ext,_T("cur"),3)==0 )		return CXIMAGE_FORMAT_ICO;


	if (_tcsnicmp(ext,_T("tif"),3)==0 )		return CXIMAGE_FORMAT_TIF;


	if (_tcsnicmp(ext,_T("tga"),3)==0 )		return CXIMAGE_FORMAT_TGA;


	if (_tcsnicmp(ext,_T("pcx"),3)==0 )		return CXIMAGE_FORMAT_PCX;


	if (_tcsnicmp(ext,_T("wbm"),3)==0 )		return CXIMAGE_FORMAT_WBMP;


	if (_tcsnicmp(ext,_T("wmf"),3)==0 || _tcsnicmp(ext,_T("emf"),3)==0 )		return CXIMAGE_FORMAT_WMF;


	if (_tcsnicmp(ext,_T("jp2"),3)==0 || _tcsnicmp(ext,_T("j2k"),3)==0 )		return CXIMAGE_FORMAT_JP2;


	if (_tcsnicmp(ext,_T("jpc"),3)==0 || _tcsnicmp(ext,_T("j2c"),3)==0 )		return CXIMAGE_FORMAT_JPC;


	if (_tcsnicmp(ext,_T("pgx"),3)==0 )		return CXIMAGE_FORMAT_PGX;


	if (_tcsnicmp(ext,_T("ras"),3)==0 )		return CXIMAGE_FORMAT_RAS;


	if (_tcsnicmp(ext,_T("pnm"),3)==0 || _tcsnicmp(ext,_T("pgm"),3)==0 || _tcsnicmp(ext,_T("ppm"),3)==0 )		return CXIMAGE_FORMAT_PNM;



	if (_tcsnicmp(ext,_T("jbg"),3)==0 )		return CXIMAGE_FORMAT_JBG;


	if (_tcsnicmp(ext,_T("mng"),3)==0 || _tcsnicmp(ext,_T("jng"),3)==0 )		return CXIMAGE_FORMAT_MNG;


	if (_tcsnicmp(ext,_T("ska"),3)==0 )		return CXIMAGE_FORMAT_SKA;


	if (_tcsnicmp(ext,_T("psd"),3)==0 )		return CXIMAGE_FORMAT_PSD;


	if (_tcsnicmp(ext,_T("nef"),3)==0 || _tcsnicmp(ext,_T("crw"),3)==0 || _tcsnicmp(ext,_T("cr2"),3)==0 || _tcsnicmp(ext,_T("dng"),3)==0 || _tcsnicmp(ext,_T("arw"),3)==0 || _tcsnicmp(ext,_T("erf"),3)==0 || _tcsnicmp(ext,_T("3fr"),3)==0 || _tcsnicmp(ext,_T("dcr"),3)==0 || _tcsnicmp(ext,_T("raw"),3)==0 || _tcsnicmp(ext,_T("x3f"),3)==0 || _tcsnicmp(ext,_T("mef"),3)==0 || _tcsnicmp(ext,_T("raf"),3)==0 || _tcsnicmp(ext,_T("mrw"),3)==0 || _tcsnicmp(ext,_T("pef"),3)==0 || _tcsnicmp(ext,_T("sr2"),3)==0 || _tcsnicmp(ext,_T("orf"),3)==0 )		return CXIMAGE_FORMAT_RAW;
















	return CXIMAGE_FORMAT_UNKNOWN;
}

uint32_t CxImage::GetTypeIdFromIndex(const uint32_t index)
{
	uint32_t n;

	n=0; if (index == n) return CXIMAGE_FORMAT_UNKNOWN;

	n++; if (index == n) return CXIMAGE_FORMAT_BMP;


	n++; if (index == n) return CXIMAGE_FORMAT_GIF;


	n++; if (index == n) return CXIMAGE_FORMAT_JPG;


	n++; if (index == n) return CXIMAGE_FORMAT_PNG;


	n++; if (index == n) return CXIMAGE_FORMAT_ICO;


	n++; if (index == n) return CXIMAGE_FORMAT_TIF;


	n++; if (index == n) return CXIMAGE_FORMAT_TGA;


	n++; if (index == n) return CXIMAGE_FORMAT_PCX;


	n++; if (index == n) return CXIMAGE_FORMAT_WBMP;


	n++; if (index == n) return CXIMAGE_FORMAT_WMF;


	n++; if (index == n) return CXIMAGE_FORMAT_JP2;


	n++; if (index == n) return CXIMAGE_FORMAT_JPC;


	n++; if (index == n) return CXIMAGE_FORMAT_PGX;


	n++; if (index == n) return CXIMAGE_FORMAT_PNM;


	n++; if (index == n) return CXIMAGE_FORMAT_RAS;


	n++; if (index == n) return CXIMAGE_FORMAT_JBG;


	n++; if (index == n) return CXIMAGE_FORMAT_MNG;


	n++; if (index == n) return CXIMAGE_FORMAT_SKA;


	n++; if (index == n) return CXIMAGE_FORMAT_RAW;


	n++; if (index == n) return CXIMAGE_FORMAT_PSD;


	return CXIMAGE_FORMAT_UNKNOWN;
}

uint32_t CxImage::GetTypeIndexFromId(const uint32_t id)
{
	uint32_t n;

	n=0; if (id == CXIMAGE_FORMAT_UNKNOWN) return n;

	n++; if (id == CXIMAGE_FORMAT_BMP) return n;


	n++; if (id == CXIMAGE_FORMAT_GIF) return n;


	n++; if (id == CXIMAGE_FORMAT_JPG) return n;


	n++; if (id == CXIMAGE_FORMAT_PNG) return n;


	n++; if (id == CXIMAGE_FORMAT_ICO) return n;


	n++; if (id == CXIMAGE_FORMAT_TIF) return n;


	n++; if (id == CXIMAGE_FORMAT_TGA) return n;


	n++; if (id == CXIMAGE_FORMAT_PCX) return n;


	n++; if (id == CXIMAGE_FORMAT_WBMP) return n;


	n++; if (id == CXIMAGE_FORMAT_WMF) return n;


	n++; if (id == CXIMAGE_FORMAT_JP2) return n;


	n++; if (id == CXIMAGE_FORMAT_JPC) return n;


	n++; if (id == CXIMAGE_FORMAT_PGX) return n;


	n++; if (id == CXIMAGE_FORMAT_PNM) return n;


	n++; if (id == CXIMAGE_FORMAT_RAS) return n;


	n++; if (id == CXIMAGE_FORMAT_JBG) return n;


	n++; if (id == CXIMAGE_FORMAT_MNG) return n;


	n++; if (id == CXIMAGE_FORMAT_SKA) return n;


	n++; if (id == CXIMAGE_FORMAT_RAW) return n;


	n++; if (id == CXIMAGE_FORMAT_PSD) return n;


	return 0;
}


uint32_t CxImage::GetFrameDelay() const {
	return info.dwFrameDelay;
}


void CxImage::SetFrameDelay(uint32_t d)
{
	info.dwFrameDelay=d;
}

void CxImage::GetOffset(int32_t *x,int32_t *y)
{
	*x=info.xOffset;
	*y=info.yOffset;
}

void CxImage::SetOffset(int32_t x,int32_t y)
{
	info.xOffset=x;
	info.yOffset=y;
}


uint8_t CxImage::GetJpegQuality() const {
	return (uint8_t)(info.fQuality + 0.5f);
}


float CxImage::GetJpegQualityF() const {
	return info.fQuality;
}


void CxImage::SetJpegQuality(uint8_t q){
	info.fQuality = (float)q;
}


void CxImage::SetJpegQualityF(float q){
	if (q>0) info.fQuality = q;
	else  info.fQuality = 0.0f;
}


uint8_t CxImage::GetJpegScale() const {
	return info.nJpegScale;
}


void CxImage::SetJpegScale(uint8_t q){
	info.nJpegScale = q;
}


int32_t CxImage::GetProgress() const {
	return info.nProgress;
}


int32_t CxImage::GetEscape() const {
	return info.nEscape;
}


void CxImage::SetProgress(int32_t p)
{
	info.nProgress = p;
}


void CxImage::SetEscape(int32_t i)
{
	info.nEscape = i;
}


bool CxImage::IsValid() const {
	return pDib!=0;
}


bool CxImage::IsEnabled() const {
	return info.bEnabled;
}


void CxImage::Enable(bool enable)
{
	info.bEnabled=enable;
}


int32_t CxImage::GetNumFrames() const {
	return info.nNumFrames;
}


int32_t CxImage::GetFrame() const {
	return info.nFrame;
}


void CxImage::SetFrame(int32_t nFrame){
	info.nFrame=nFrame;
}


void CxImage::SetDisposalMethod(uint8_t dm)
{	info.dispmeth=dm; }


uint8_t CxImage::GetDisposalMethod() const {	return info.dispmeth; }

bool CxImage::GetRetreiveAllFrames() const {	return info.bGetAllFrames; }

void CxImage::SetRetreiveAllFrames(bool flag)
{	info.bGetAllFrames = flag; }

CxImage * CxImage::GetFrame(int32_t nFrame) const {
	if ( ppFrames == NULL) return NULL;
	if ( info.nNumFrames == 0) return NULL;
	if ( nFrame >= info.nNumFrames ) return NULL;
	if ( nFrame < 0) nFrame = info.nNumFrames - 1;
	return ppFrames[nFrame];
}

int16_t CxImage::m_ntohs(const int16_t word)
{
	if (info.bLittleEndianHost) return word;
	return ( (word & 0xff) << 8 ) | ( (word >> 8) & 0xff );
}

int32_t CxImage::m_ntohl(const int32_t dword)
{
	if (info.bLittleEndianHost) return dword;
	return  ((dword & 0xff) << 24 ) | ((dword & 0xff00) << 8 ) | ((dword >> 8) & 0xff00) | ((dword >> 24) & 0xff);
}

void CxImage::bihtoh(BITMAPINFOHEADER* bih)
{
	bih->biSize = m_ntohl(bih->biSize);
	bih->biWidth = m_ntohl(bih->biWidth);
	bih->biHeight = m_ntohl(bih->biHeight);
	bih->biPlanes = m_ntohs(bih->biPlanes);
	bih->biBitCount = m_ntohs(bih->biBitCount);
	bih->biCompression = m_ntohl(bih->biCompression);
	bih->biSizeImage = m_ntohl(bih->biSizeImage);
	bih->biXPelsPerMeter = m_ntohl(bih->biXPelsPerMeter);
	bih->biYPelsPerMeter = m_ntohl(bih->biYPelsPerMeter);
	bih->biClrUsed = m_ntohl(bih->biClrUsed);
	bih->biClrImportant = m_ntohl(bih->biClrImportant);
}


const char* CxImage::GetLastError()
{
	return info.szLastError;
}

uint32_t CxImage::DumpSize()
{
	uint32_t n;
	n = sizeof(BITMAPINFOHEADER) + sizeof(CXIMAGEINFO) + GetSize();


	if (pAlpha){
		n += 1 + head.biWidth * head.biHeight;
	} else n++;



	if (pSelection){
		n += 1 + head.biWidth * head.biHeight;
	} else n++;



	if (ppLayers){
		for (int32_t m=0; m<GetNumLayers(); m++){
			if (GetLayer(m)){
				n += 1 + GetLayer(m)->DumpSize();
			}
		}
	} else n++;


	if (ppFrames){
		for (int32_t m=0; m<GetNumFrames(); m++){
			if (GetFrame(m)){
				n += 1 + GetFrame(m)->DumpSize();
			}
		}
	} else n++;

	return n;
}

uint32_t CxImage::Dump(uint8_t * dst)
{
	if (!dst) return 0;

	memcpy(dst,&head,sizeof(BITMAPINFOHEADER));
	dst += sizeof(BITMAPINFOHEADER);

	memcpy(dst,&info,sizeof(CXIMAGEINFO));
	dst += sizeof(CXIMAGEINFO);

	memcpy(dst,pDib,GetSize());
	dst += GetSize();


	if (pAlpha){
		memset(dst++, 1, 1);
		memcpy(dst,pAlpha,head.biWidth * head.biHeight);
		dst += head.biWidth * head.biHeight;
	} else {
		memset(dst++, 0, 1);
	}



	if (pSelection){
		memset(dst++, 1, 1);
		memcpy(dst,pSelection,head.biWidth * head.biHeight);
		dst += head.biWidth * head.biHeight;
	} else {
		memset(dst++, 0, 1);
	}



	if (ppLayers){
		memset(dst++, 1, 1);
		for (int32_t m=0; m<GetNumLayers(); m++){
			if (GetLayer(m)){
				dst += GetLayer(m)->Dump(dst);
			}
		}
	} else {
		memset(dst++, 0, 1);
	}


	if (ppFrames){
		memset(dst++, 1, 1);
		for (int32_t m=0; m<GetNumFrames(); m++){
			if (GetFrame(m)){
				dst += GetFrame(m)->Dump(dst);
			}
		}
	} else {
		memset(dst++, 0, 1);
	}

	return DumpSize();
}

uint32_t CxImage::UnDump(const uint8_t * src)
{
	if (!src)
		return 0;
	if (!Destroy())
		return 0;
	if (!DestroyFrames())
		return 0;

	uint32_t n = 0;

	memcpy(&head,src,sizeof(BITMAPINFOHEADER));
	n += sizeof(BITMAPINFOHEADER);

	memcpy(&info,&src[n],sizeof(CXIMAGEINFO));
	n += sizeof(CXIMAGEINFO);

	if (!Create(head.biWidth, head.biHeight, head.biBitCount, info.dwType))
		return 0;

	memcpy(pDib,&src[n],GetSize());
	n += GetSize();


	if (src[n++]){
		if (AlphaCreate()){
			memcpy(pAlpha, &src[n], head.biWidth * head.biHeight);
		}
		n += head.biWidth * head.biHeight;
	}



	if (src[n++]){
		RECT box = info.rSelectionBox;
		if (SelectionCreate()){
			info.rSelectionBox = box;
			memcpy(pSelection, &src[n], head.biWidth * head.biHeight);
		}
		n += head.biWidth * head.biHeight;
	}



	if (src[n++]){
		ppLayers = new CxImage*[info.nNumLayers];
		for (int32_t m=0; m<GetNumLayers(); m++){
			ppLayers[m] = new CxImage();
			n += ppLayers[m]->UnDump(&src[n]);
		}
	}


	if (src[n++]){
		ppFrames = new CxImage*[info.nNumFrames];
		for (int32_t m=0; m<GetNumFrames(); m++){
			ppFrames[m] = new CxImage();
			n += ppFrames[m]->UnDump(&src[n]);
		}
	}

	return n;
}


const float CxImage::GetVersionNumber()
{
	return 7.000020000f;
}

const TCHAR* CxImage::GetVersion()
{
	static const TCHAR CxImageVersion[] = _T("CxImage 7.0.2");
	return (CxImageVersion);
}

