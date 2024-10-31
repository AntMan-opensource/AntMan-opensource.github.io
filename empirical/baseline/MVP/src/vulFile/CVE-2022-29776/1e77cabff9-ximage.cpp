                void CxImage::Startup(uint32_t imagetype)















{
	
	pDib = pSelection = pAlpha = NULL;
	ppLayers = ppFrames = NULL;
	
	memset(&head,0,sizeof(BITMAPINFOHEADER));
	memset(&info,0,sizeof(CXIMAGEINFO));
	
    info.dwType = imagetype;
	info.fQuality = 90.0f;
	info.nAlphaMax = 255;
	info.nBkgndIndex = -1;
	info.bEnabled = true;
	info.nJpegScale = 1;
	SetXDPI(CXIMAGE_DEFAULT_DPI);
	SetYDPI(CXIMAGE_DEFAULT_DPI);

	int16_t test = 1;
	info.bLittleEndianHost = (*((char *) &test) == 1);
}


CxImage::CxImage(uint32_t imagetype)
{
	Startup(imagetype);
}


bool CxImage::Destroy()
{
	
	if (info.pGhost==NULL){
		if (ppLayers) { 
			for(int32_t n=0; n<info.nNumLayers;n++){ delete ppLayers[n]; }
			delete [] ppLayers; ppLayers=0; info.nNumLayers = 0;
		}
		if (pSelection) {free(pSelection); pSelection=0;}
		if (pAlpha) {free(pAlpha); pAlpha=0;}
		if (pDib) {free(pDib); pDib=0;}
		return true;
	}
	return false;
}

bool CxImage::DestroyFrames()
{
	if (info.pGhost==NULL) {
		if (ppFrames) {
			for (int32_t n=0; n<info.nNumFrames; n++) { delete ppFrames[n]; }
			delete [] ppFrames; ppFrames = NULL; info.nNumFrames = 0;
		}
		return true;
	}
	return false;
}


CxImage::CxImage(uint32_t dwWidth, uint32_t dwHeight, uint32_t wBpp, uint32_t imagetype)
{
	Startup(imagetype);
	Create(dwWidth,dwHeight,wBpp,imagetype);
}


CxImage::CxImage(const CxImage &src, bool copypixels, bool copyselection, bool copyalpha)
{
	Startup(src.GetType());
	Copy(src,copypixels,copyselection,copyalpha);
}


void CxImage::Copy(const CxImage &src, bool copypixels, bool copyselection, bool copyalpha)
{
	
	if (src.info.pGhost){
		Ghost(&src);
		return;
	}
	
	memcpy(&info,&src.info,sizeof(CXIMAGEINFO));
	memcpy(&head,&src.head,sizeof(BITMAPINFOHEADER)); 
	
	Create(src.GetWidth(),src.GetHeight(),src.GetBpp(),src.GetType());
	
	if (copypixels && pDib && src.pDib) memcpy(pDib,src.pDib,GetSize());
	else SetPalette(src.GetPalette());
	int32_t nSize = head.biWidth * head.biHeight;
	
	if (copyselection && src.pSelection){
		if (pSelection) free(pSelection);
		pSelection = (uint8_t*)malloc(nSize);
		memcpy(pSelection,src.pSelection,nSize);
	}
	
	if (copyalpha && src.pAlpha){
		if (pAlpha) free(pAlpha);
		pAlpha = (uint8_t*)malloc(nSize);
		memcpy(pAlpha,src.pAlpha,nSize);
	}
}


void CxImage::CopyInfo(const CxImage &src)
{
	if (pDib==NULL) memcpy(&info,&src.info,sizeof(CXIMAGEINFO));
}


CxImage& CxImage::operator = (const CxImage& isrc)
{
	if (this != &isrc) Copy(isrc);
	return *this;
}


void* CxImage::Create(uint32_t dwWidth, uint32_t dwHeight, uint32_t wBpp, uint32_t imagetype)
{
	
	if (!Destroy())
		return NULL;

	
	if ((dwWidth == 0) || (dwHeight == 0)){
		strcpy(info.szLastError,"CxImage::Create : width and height must be greater than zero");
		return NULL;
	}

    
    if		(wBpp <= 1)	wBpp = 1;
    else if (wBpp <= 4)	wBpp = 4;
    else if (wBpp <= 8)	wBpp = 8;
    else				wBpp = 24;

	
	if ((((float)dwWidth*(float)dwHeight*(float)wBpp)/8.0f) > (float)CXIMAGE_MAX_MEMORY)
	{
		strcpy(info.szLastError,"CXIMAGE_MAX_MEMORY exceeded");
		return NULL;
	}

	
    switch (wBpp){
        case 1:
            head.biClrUsed = 2;	break;
        case 4:
            head.biClrUsed = 16; break;
        case 8:
            head.biClrUsed = 256; break;
        default:
            head.biClrUsed = 0;
    }

	
    info.dwEffWidth = ((((wBpp * dwWidth) + 31) / 32) * 4);
    info.dwType = imagetype;

    
	head.biSize = sizeof(BITMAPINFOHEADER); 
    head.biWidth = dwWidth;		
    head.biHeight = dwHeight;	
    head.biPlanes = 1;			
    head.biBitCount = (uint16_t)wBpp;		
    head.biCompression = BI_RGB;    
    head.biSizeImage = info.dwEffWidth * dwHeight;




	pDib = malloc(GetSize()); 
    if (!pDib){
		strcpy(info.szLastError,"CxImage::Create can't allocate memory");
		return NULL;
	}

	
	RGBQUAD* pal=GetPalette();
	if (pal) memset(pal,0,GetPaletteSize());
	

	if (pSelection) SelectionDelete();

	

	if (pAlpha) AlphaDelete();


    
    
    BITMAPINFOHEADER*  lpbi;
	lpbi = (BITMAPINFOHEADER*)(pDib);
    *lpbi = head;

	info.pImage=GetBits();

    return pDib; 
}


uint8_t* CxImage::GetBits(uint32_t row)
{ 
	if (pDib){
		if (row) {
			if (row<(uint32_t)head.biHeight){
				return ((uint8_t*)pDib + *(uint32_t*)pDib + GetPaletteSize() + (info.dwEffWidth * row));
			} else {
				return NULL;
			}
		} else {
			return ((uint8_t*)pDib + *(uint32_t*)pDib + GetPaletteSize());
		}
	}
	return NULL;
}


int32_t CxImage::GetSize()
{
	return head.biSize + head.biSizeImage + GetPaletteSize();
}


bool CxImage::IsInside(int32_t x, int32_t y)
{
  return (0<=y && y<head.biHeight && 0<=x && x<head.biWidth);
}


void CxImage::Clear(uint8_t bval)
{
	if (pDib == 0) return;

	if (GetBpp() == 1){
		if (bval > 0) bval = 255;
	}
	if (GetBpp() == 4){
		bval = (uint8_t)(17*(0x0F & bval));
	}

	memset(info.pImage,bval,head.biSizeImage);
}


bool CxImage::Transfer(CxImage &from, bool bTransferFrames )
{
	if (!Destroy())
		return false;

	memcpy(&head,&from.head,sizeof(BITMAPINFOHEADER));
	memcpy(&info,&from.info,sizeof(CXIMAGEINFO));

	pDib = from.pDib;
	pSelection = from.pSelection;
	pAlpha = from.pAlpha;
	ppLayers = from.ppLayers;

	memset(&from.head,0,sizeof(BITMAPINFOHEADER));
	memset(&from.info,0,sizeof(CXIMAGEINFO));
	from.pDib = from.pSelection = from.pAlpha = NULL;
	from.ppLayers = NULL;

	if (bTransferFrames){
		DestroyFrames();
		ppFrames = from.ppFrames;
		from.ppFrames = NULL;
	}

	return true;
}


void CxImage::Ghost(const CxImage *from)
{
	if (from){
		memcpy(&head,&from->head,sizeof(BITMAPINFOHEADER));
		memcpy(&info,&from->info,sizeof(CXIMAGEINFO));
		pDib = from->pDib;
		pSelection = from->pSelection;
		pAlpha = from->pAlpha;
		ppLayers = from->ppLayers;
		ppFrames = from->ppFrames;
		info.pGhost=(CxImage *)from;
	}
}


void CxImage::Bitfield2RGB(uint8_t *src, uint32_t redmask, uint32_t greenmask, uint32_t bluemask, uint8_t bpp)
{
	switch (bpp){
	case 16:
	{
		uint32_t ns[3]={0,0,0};
		
		for (int32_t i=0;i<16;i++){
			if ((redmask>>i)&0x01) ns[0]++;
			if ((greenmask>>i)&0x01) ns[1]++;
			if ((bluemask>>i)&0x01) ns[2]++;
		}
		ns[1]+=ns[0]; ns[2]+=ns[1];	ns[0]=8-ns[0]; ns[1]-=8; ns[2]-=8;
		
		int32_t effwidth2=(((head.biWidth + 1) / 2) * 4);
		uint16_t w;
		int32_t y2,y3,x2,x3;
		uint8_t *p=info.pImage;
		
		for (int32_t y=head.biHeight-1; y>=0; y--){
			y2=effwidth2*y;
			y3=info.dwEffWidth*y;
			for (int32_t x=head.biWidth-1; x>=0; x--){
				x2 = 2*x+y2;
				x3 = 3*x+y3;
				w = (uint16_t)(src[x2]+256*src[1+x2]);
				p[  x3]=(uint8_t)((w & bluemask)<<ns[0]);
				p[1+x3]=(uint8_t)((w & greenmask)>>ns[1]);
				p[2+x3]=(uint8_t)((w & redmask)>>ns[2]);
			}
		}
		break;
	}
	case 32:
	{
		uint32_t ns[3]={0,0,0};
		
		for (int32_t i=8;i<32;i+=8){
			if (redmask>>i) ns[0]++;
			if (greenmask>>i) ns[1]++;
			if (bluemask>>i) ns[2]++;
		}
		
		int32_t effwidth4 = head.biWidth * 4;
		int32_t y4,y3,x4,x3;
		uint8_t *p=info.pImage;
		
		for (int32_t y=head.biHeight-1; y>=0; y--){
			y4=effwidth4*y;
			y3=info.dwEffWidth*y;
			for (int32_t x=head.biWidth-1; x>=0; x--){
				x4 = 4*x+y4;
				x3 = 3*x+y3;
				p[  x3]=src[ns[2]+x4];
				p[1+x3]=src[ns[1]+x4];
				p[2+x3]=src[ns[0]+x4];
			}
		}
	}

	}
	return;
}


bool CxImage::CreateFromArray(uint8_t* pArray,uint32_t dwWidth,uint32_t dwHeight,uint32_t dwBitsperpixel, uint32_t dwBytesperline, bool bFlipImage)
{
	if (pArray==NULL) return false;
	if (!((dwBitsperpixel==1)||(dwBitsperpixel==4)||(dwBitsperpixel==8)|| (dwBitsperpixel==24)||(dwBitsperpixel==32))) return false;

	if (!Create(dwWidth,dwHeight,dwBitsperpixel)) return false;

	if (dwBitsperpixel<24) SetGrayPalette();


	if (dwBitsperpixel==32) AlphaCreate();


	uint8_t *dst,*src;

	for (uint32_t y = 0; y<dwHeight; y++) {
		dst = info.pImage + (bFlipImage?(dwHeight-1-y):y) * info.dwEffWidth;
		src = pArray + y * dwBytesperline;
		if (dwBitsperpixel==32){
			for(uint32_t x=0;x<dwWidth;x++){
				*dst++=src[0];
				*dst++=src[1];
				*dst++=src[2];

				AlphaSet(x,(bFlipImage?(dwHeight-1-y):y),src[3]);

				src+=4;
			}
		} else {
			memcpy(dst,src,min(info.dwEffWidth,dwBytesperline));
		}
	}
	return true;
}


bool CxImage::CreateFromMatrix(uint8_t** ppMatrix,uint32_t dwWidth,uint32_t dwHeight,uint32_t dwBitsperpixel, uint32_t dwBytesperline, bool bFlipImage)
{
	if (ppMatrix==NULL) return false;
	if (!((dwBitsperpixel==1)||(dwBitsperpixel==4)||(dwBitsperpixel==8)|| (dwBitsperpixel==24)||(dwBitsperpixel==32))) return false;

	if (!Create(dwWidth,dwHeight,dwBitsperpixel)) return false;

	if (dwBitsperpixel<24) SetGrayPalette();


	if (dwBitsperpixel==32) AlphaCreate();


	uint8_t *dst,*src;

	for (uint32_t y = 0; y<dwHeight; y++) {
		dst = info.pImage + (bFlipImage?(dwHeight-1-y):y) * info.dwEffWidth;
		src = ppMatrix[y];
		if (src){
			if (dwBitsperpixel==32){
				for(uint32_t x=0;x<dwWidth;x++){
					*dst++=src[0];
					*dst++=src[1];
					*dst++=src[2];

					AlphaSet(x,(bFlipImage?(dwHeight-1-y):y),src[3]);

					src+=4;
				}
			} else {
				memcpy(dst,src,min(info.dwEffWidth,dwBytesperline));
			}
		}
	}
	return true;
}


int32_t CxImage::CompareColors(const void *elem1, const void *elem2)
{
	RGBQUAD* c1 = (RGBQUAD*)elem1;
	RGBQUAD* c2 = (RGBQUAD*)elem2;

	int32_t g1 = (int32_t)RGB2GRAY(c1->rgbRed,c1->rgbGreen,c1->rgbBlue);
	int32_t g2 = (int32_t)RGB2GRAY(c2->rgbRed,c2->rgbGreen,c2->rgbBlue);
	
	return (g1-g2);
}


void CxImage::FreeMemory(void* memblock)
{
	if (memblock)
		free(memblock);
}


