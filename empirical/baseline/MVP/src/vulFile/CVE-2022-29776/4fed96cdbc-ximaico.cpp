         bool CxImageICO::Decode(CxFile *hFile)








{
	if (hFile==NULL) return false;

	uint32_t off = hFile->Tell(); 
	int32_t	page=info.nFrame;	

	
	ICONHEADER icon_header;
	hFile->Read(&icon_header,sizeof(ICONHEADER),1);

	icon_header.idType = m_ntohs(icon_header.idType);
	icon_header.idCount = m_ntohs(icon_header.idCount);

	
	if ((icon_header.idReserved == 0) && ((icon_header.idType == 1)||(icon_header.idType == 2))) {

		info.nNumFrames = icon_header.idCount;

		
		ICONDIRENTRY *icon_list = (ICONDIRENTRY *)malloc(icon_header.idCount * sizeof(ICONDIRENTRY));
		int32_t c;
		for (c = 0; c < icon_header.idCount; c++) {
			hFile->Read(icon_list + c, sizeof(ICONDIRENTRY), 1);

			icon_list[c].wPlanes = m_ntohs(icon_list[c].wPlanes);
			icon_list[c].wBitCount = m_ntohs(icon_list[c].wBitCount);
			icon_list[c].dwBytesInRes = m_ntohl(icon_list[c].dwBytesInRes);
			icon_list[c].dwImageOffset = m_ntohl(icon_list[c].dwImageOffset);
		}

		if ((page>=0)&&(page<icon_header.idCount)){

			if (info.nEscape == -1) {
				
				head.biWidth = icon_list[page].bWidth;
				head.biHeight = icon_list[page].bHeight;

				if (head.biWidth==0 && head.biHeight==0)
				{	
					hFile->Seek(off + icon_list[page].dwImageOffset, SEEK_SET);
					CxImage png;
					png.SetEscape(-1);
					if (png.Decode(hFile,CXIMAGE_FORMAT_PNG)){
						Transfer(png);
						info.nNumFrames = icon_header.idCount;
					}
				}

				free(icon_list);
				info.dwType = CXIMAGE_FORMAT_ICO;
				return true;
			}

			
			BITMAPINFOHEADER bih;
			hFile->Seek(off + icon_list[page].dwImageOffset, SEEK_SET);

			if (icon_list[page].bWidth==0 && icon_list[page].bHeight==0)
			{	

				CxImage png;
				if (png.Decode(hFile,CXIMAGE_FORMAT_PNG)){
					Transfer(png);
					info.nNumFrames = icon_header.idCount;
				}
				SetType(CXIMAGE_FORMAT_ICO);

			}
			else {
				hFile->Read(&bih,sizeof(BITMAPINFOHEADER),1);

				bihtoh(&bih);

				c = bih.biBitCount;

				
				Create(icon_list[page].bWidth,icon_list[page].bHeight, c, CXIMAGE_FORMAT_ICO);	

				
				RGBQUAD pal[256];
				if (bih.biClrUsed)
					hFile->Read(pal,bih.biClrUsed*sizeof(RGBQUAD), 1);
				else hFile->Read(pal,head.biClrUsed*sizeof(RGBQUAD), 1);

				SetPalette(pal,head.biClrUsed);	

				
				if (c<=24){
					hFile->Read(info.pImage, head.biSizeImage, 1);
				} else { 
					uint8_t* buf=(uint8_t*)malloc(4*head.biHeight*head.biWidth);
					uint8_t* src = buf;
					hFile->Read(buf, 4*head.biHeight*head.biWidth, 1);

					if (!AlphaIsValid()) AlphaCreate();

					for (int32_t y = 0; y < head.biHeight; y++) {
						uint8_t* dst = GetBits(y);
						for(int32_t x=0;x<head.biWidth;x++){
							*dst++=src[0];
							*dst++=src[1];
							*dst++=src[2];

							AlphaSet(x,y,src[3]);

							src+=4;
						}
					}
					free(buf);
				}
				
				int32_t maskwdt = ((head.biWidth+31) / 32) * 4;	
				int32_t masksize = head.biHeight * maskwdt;				
				uint8_t *mask = (uint8_t *)malloc(masksize);
				if (hFile->Read(mask, masksize, 1)){

					bool bGoodMask=false;
					for (int32_t im=0;im<masksize;im++){
						if (mask[im]!=255){
							bGoodMask=true;
							break;
						}
					}

					if (bGoodMask){
						int32_t x,y;

						bool bNeedAlpha = false;
						if (!AlphaIsValid()){
							AlphaCreate();
						} else { 
							bNeedAlpha=true; 
						}
						for (y = 0; y < head.biHeight; y++) {
							for (x = 0; x < head.biWidth; x++) {
								if (((mask[y*maskwdt+(x>>3)]>>(7-x%8))&0x01)){
									AlphaSet(x,y,0);
									bNeedAlpha=true;
								}
							}
						}
						if (!bNeedAlpha) AlphaDelete();


						
						RGBQUAD cc,ct;
						int32_t nTransColors=0;
						int32_t nTransIndex=0;
						for (y = 0; y < head.biHeight; y++){
							for (x = 0; x < head.biWidth; x++){
								if (((mask[y*maskwdt+(x>>3)] >> (7-x%8)) & 0x01)){
									cc = GetPixelColor(x,y,false);
									if (nTransColors==0){
										nTransIndex = GetPixelIndex(x,y);
										nTransColors++;
										ct = cc;
									} else {
										if (memcmp(&cc, &ct, sizeof(RGBQUAD)) != 0){
											nTransColors++;
										}
									}
								}
							}
						}
						if (nTransColors==1 && c<=8){
							SetTransColor(ct);
							SetTransIndex(nTransIndex);

							AlphaDelete(); 

						}

						
						if (c <= 8){ 
							  
							
							

							uint8_t colorsUsed[256];
							memset(colorsUsed, 0, sizeof(colorsUsed));

							for (y = 0; y < head.biHeight; y++){
								for (x = 0; x < head.biWidth; x++){
									colorsUsed[BlindGetPixelIndex(x,y)] = 1;
								}
							}

							int32_t iTransIdx = -1;
							for (x = (int32_t)(head.biClrUsed-1); x>=0 ; x--){
								if (colorsUsed[x] == 0){
									iTransIdx = x; 
									break;
								}
							}

							
							if (iTransIdx >= 0){
								bool bNeedTrans = false;
								for (y = 0; y < head.biHeight; y++){
									for (x = 0; x < head.biWidth; x++){
										
										if (((mask[y*maskwdt+(x>>3)] >> (7-x%8)) & 0x01)){
											
											SetPixelIndex(x, y, (uint8_t)iTransIdx);
											bNeedTrans = true;
										}
									}
								}
								
								if (bNeedTrans)	SetTransIndex(iTransIdx);

								AlphaDelete(); 

							}
						}
					} else {
						SetTransIndex(0); 
						Negative();
					}
				} 
				free(mask);
			}
			free(icon_list);
			
			return true;
		}
		free(icon_list);
	}
	return false;
}






bool CxImageICO::Encode(CxFile * hFile, CxImage ** pImages, int32_t nPageCount)
{
  cx_try {
	if (hFile==NULL) cx_throw("invalid file pointer");
	if (pImages==NULL || nPageCount<=0) cx_throw("multipage ICO, no images!");

	int32_t i;
	for (i=0; i<nPageCount; i++){
		if (pImages[i]==NULL)
			cx_throw("Bad image pointer");
		if (!(pImages[i]->IsValid()))
			cx_throw("Empty image");
	}

	CxImageICO ghost;
	for (i=0; i<nPageCount; i++){	
		ghost.Ghost(pImages[i]);
		ghost.info.nNumFrames = nPageCount;
		if (i==0) {
			if (!ghost.Encode(hFile,false,nPageCount))
				cx_throw("Error writing ICO file header");
		}
		if (!ghost.Encode(hFile,true,nPageCount)) 
			cx_throw("Error saving ICO image header");
	}
	for (i=0; i<nPageCount; i++){	
		ghost.Ghost(pImages[i]);
		ghost.info.nNumFrames = nPageCount;
		if (!ghost.Encode(hFile,true,i)) 
			cx_throw("Error saving ICO body");
	}

  } cx_catch {
	  if (strcmp(message,"")) strncpy(info.szLastError,message,255);
	  return false;
  }
	return true;
}

bool CxImageICO::Encode(CxFile * hFile, bool bAppend, int32_t nPageCount)
{
	if (EncodeSafeCheck(hFile)) return false;


	
	if ((head.biWidth>255)||(head.biHeight>255)){
		strcpy(info.szLastError,"Can't save this image as icon");
		return false;
	}


	
	RGBQUAD* pal=GetPalette();
	if (head.biBitCount<=8 && pal==NULL) return false;

	int32_t maskwdt=((head.biWidth+31)/32)*4; 
	int32_t masksize=head.biHeight * maskwdt; 
	int32_t bitcount=head.biBitCount;
	int32_t imagesize=head.biSizeImage;

	if (AlphaIsValid() && head.biClrUsed==0){
		bitcount=32;
		imagesize=4*head.biHeight*head.biWidth;
	}


	
	int32_t nPages = nPageCount;
	if (nPages<1) nPages = 1;

	ICONHEADER icon_header={0,1,(uint16_t)nPages};

	if (!bAppend)
		m_dwImageOffset = sizeof(ICONHEADER) + nPages * sizeof(ICONDIRENTRY);

	uint32_t dwBytesInRes = sizeof(BITMAPINFOHEADER)+head.biClrUsed*sizeof(RGBQUAD)+imagesize+masksize;

	ICONDIRENTRY icon_list={
		(uint8_t)head.biWidth, (uint8_t)head.biHeight, (uint8_t)head.biClrUsed, 0, 0, (uint16_t)bitcount, dwBytesInRes, m_dwImageOffset };







	BITMAPINFOHEADER bi={
		sizeof(BITMAPINFOHEADER), head.biWidth, 2*head.biHeight, 1, (uint16_t)bitcount, 0, (uint32_t)imagesize, 0, 0, 0, 0 };








	CxImage png(*this);
	CxMemFile memfile;
	if (head.biWidth>255 || head.biHeight>255){
		icon_list.bWidth = icon_list.bHeight = 0;
		memfile.Open();
		png.Encode(&memfile,CXIMAGE_FORMAT_PNG);
		icon_list.dwBytesInRes = dwBytesInRes = memfile.Size();
	}


	if (!bAppend){
		icon_header.idType = m_ntohs(icon_header.idType);
		icon_header.idCount = m_ntohs(icon_header.idCount);
		hFile->Write(&icon_header,sizeof(ICONHEADER),1);	
		icon_header.idType = m_ntohs(icon_header.idType);
		icon_header.idCount = m_ntohs(icon_header.idCount);
	}


	if ((bAppend && nPageCount==info.nNumFrames) || (!bAppend && nPageCount==0)){
		icon_list.wPlanes = m_ntohs(icon_list.wPlanes);
		icon_list.wBitCount = m_ntohs(icon_list.wBitCount);
		icon_list.dwBytesInRes = m_ntohl(icon_list.dwBytesInRes);
		icon_list.dwImageOffset = m_ntohl(icon_list.dwImageOffset);
		hFile->Write(&icon_list,sizeof(ICONDIRENTRY),1);	
		icon_list.wPlanes = m_ntohs(icon_list.wPlanes);
		icon_list.wBitCount = m_ntohs(icon_list.wBitCount);
		icon_list.dwBytesInRes = m_ntohl(icon_list.dwBytesInRes);
		icon_list.dwImageOffset = m_ntohl(icon_list.dwImageOffset);

		m_dwImageOffset += dwBytesInRes;			
	}

	if ((bAppend && nPageCount<info.nNumFrames) || (!bAppend && nPageCount==0))
	{

		if (icon_list.bWidth==0 && icon_list.bHeight==0) {	
			hFile->Write(memfile.GetBuffer(false),dwBytesInRes,1);
		} else  {

			bihtoh(&bi);
			hFile->Write(&bi,sizeof(BITMAPINFOHEADER),1);			
			bihtoh(&bi);

			bool bTransparent = info.nBkgndIndex >= 0;
			RGBQUAD ct = GetTransColor();
			if (pal){
				if (bTransparent) SetPaletteColor((uint8_t)info.nBkgndIndex,0,0,0,0);
			 	hFile->Write(pal,head.biClrUsed*sizeof(RGBQUAD),1); 
				if (bTransparent) SetPaletteColor((uint8_t)info.nBkgndIndex,ct);
			}


			if (AlphaIsValid() && head.biClrUsed==0){
				uint8_t* buf=(uint8_t*)malloc(imagesize);
				uint8_t* dst = buf;
				for (int32_t y = 0; y < head.biHeight; y++) {
					uint8_t* src = GetBits(y);
					for(int32_t x=0;x<head.biWidth;x++){
						*dst++=*src++;
						*dst++=*src++;
						*dst++=*src++;
						*dst++=AlphaGet(x,y);
					}
				}
				hFile->Write(buf,imagesize, 1);
				free(buf);
			} else {
				hFile->Write(info.pImage,imagesize,1);	
			}

			hFile->Write(info.pImage,imagesize,1);	


			
			uint8_t* mask=(uint8_t*)calloc(masksize,1);	
			if (!mask) return false;

			
			uint8_t* iDst;
			int32_t pos,i;
			RGBQUAD c={0,0,0,0};
			int32_t* pc = (int32_t*)&c;
			int32_t* pct= (int32_t*)&ct;

			bool bAlphaPaletteIsValid = AlphaPaletteIsValid();
			bool bAlphaIsValid = AlphaIsValid();

			
			for (int32_t y = 0; y < head.biHeight; y++) {
				for (int32_t x = 0; x < head.biWidth; x++) {
					i=0;

					if (bAlphaIsValid && AlphaGet(x,y)==0) i=1;
					if (bAlphaPaletteIsValid && BlindGetPixelColor(x,y).rgbReserved==0) i=1;

					c=GetPixelColor(x,y,false);
					if (bTransparent && *pc==*pct) i=1;
					iDst = mask + y*maskwdt + (x>>3);
					pos = 7-x%8;
					*iDst &= ~(0x01<<pos);
					*iDst |= ((i & 0x01)<<pos);
				}
			}
			
			hFile->Write(mask,masksize,1);
			free(mask);
		}
	}

	return true;
}





