












extern	void TIFFCvtIEEEFloatToNative(TIFF*, uint32, float*);
extern	void TIFFCvtIEEEDoubleToNative(TIFF*, uint32, double*);


static  TIFFDirEntry* TIFFReadDirectoryFind(TIFFDirEntry* dir, uint16 dircount, uint16 tagid);
static	int EstimateStripByteCounts(TIFF*, TIFFDirEntry*, uint16);
static	void MissingRequired(TIFF*, const char*);
static	int TIFFCheckDirOffset(TIFF*, toff_t);
static	int CheckDirCount(TIFF*, TIFFDirEntry*, uint32);
static	uint16 TIFFFetchDirectory(TIFF*, toff_t, TIFFDirEntry**, toff_t *);
static	tsize_t TIFFFetchData(TIFF*, TIFFDirEntry*, char*);
static	tsize_t TIFFFetchString(TIFF*, TIFFDirEntry*, char*);
static	float TIFFFetchRational(TIFF*, TIFFDirEntry*);
static	int TIFFFetchNormalTag(TIFF*, TIFFDirEntry*);
static	int TIFFFetchPerSampleShorts(TIFF*, TIFFDirEntry*, uint16*);
static	int TIFFFetchPerSampleLongs(TIFF*, TIFFDirEntry*, uint32*);
static	int TIFFFetchPerSampleAnys(TIFF*, TIFFDirEntry*, double*);
static	int TIFFFetchShortArray(TIFF*, TIFFDirEntry*, uint16*);
static	int TIFFFetchStripThing(TIFF*, TIFFDirEntry*, long, uint32**);
static	int TIFFFetchRefBlackWhite(TIFF*, TIFFDirEntry*);
static	int TIFFFetchSubjectDistance(TIFF*, TIFFDirEntry*);
static	float TIFFFetchFloat(TIFF*, TIFFDirEntry*);
static	int TIFFFetchFloatArray(TIFF*, TIFFDirEntry*, float*);
static	int TIFFFetchDoubleArray(TIFF*, TIFFDirEntry*, double*);
static	int TIFFFetchAnyArray(TIFF*, TIFFDirEntry*, double*);
static	int TIFFFetchShortPair(TIFF*, TIFFDirEntry*);
static	void ChopUpSingleUncompressedStrip(TIFF*);


int TIFFReadDirectory(TIFF* tif)
{
	static const char module[] = "TIFFReadDirectory";

	int n;
	TIFFDirectory* td;
	TIFFDirEntry *dp, *dir = NULL;
	uint16 iv;
	uint32 v;
	const TIFFFieldInfo* fip;
	size_t fix;
	uint16 dircount;
	int diroutoforderwarning = 0, compressionknown = 0;
	int haveunknowntags = 0;

	tif->tif_diroff = tif->tif_nextdiroff;
	
	if (!TIFFCheckDirOffset(tif, tif->tif_nextdiroff))
		return 0;
	
	(*tif->tif_cleanup)(tif);
	tif->tif_curdir++;
	dircount = TIFFFetchDirectory(tif, tif->tif_nextdiroff, &dir, &tif->tif_nextdiroff);
	if (!dircount) {
		TIFFErrorExt(tif->tif_clientdata, module, "%s: Failed to read directory at offset %u", tif->tif_name, tif->tif_nextdiroff);

		return 0;
	}

	tif->tif_flags &= ~TIFF_BEENWRITING;	
	
	td = &tif->tif_dir;
	
	TIFFFreeDirectory(tif);
	TIFFDefaultDirectory(tif);
	
	TIFFSetField(tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);

	
	for (dp = dir, n = dircount; n > 0; n--, dp++) {
		if (tif->tif_flags & TIFF_SWAB) {
			TIFFSwabArrayOfShort(&dp->tdir_tag, 2);
			TIFFSwabArrayOfLong(&dp->tdir_count, 2);
		}
		if (dp->tdir_tag == TIFFTAG_SAMPLESPERPIXEL) {
			if (!TIFFFetchNormalTag(tif, dp))
				goto bad;
			dp->tdir_tag = IGNORE;
		}
	}
	
	fix = 0;
	for (dp = dir, n = dircount; n > 0; n--, dp++) {

		if (dp->tdir_tag == IGNORE)
			continue;
		if (fix >= tif->tif_nfields)
			fix = 0;

		
		if (dp->tdir_tag < tif->tif_fieldinfo[fix]->field_tag) {
			if (!diroutoforderwarning) {
				TIFFWarningExt(tif->tif_clientdata, module, "%s: invalid TIFF directory; tags are not sorted in ascending order", tif->tif_name);

				diroutoforderwarning = 1;
			}
			fix = 0;			
		}
		while (fix < tif->tif_nfields && tif->tif_fieldinfo[fix]->field_tag < dp->tdir_tag)
			fix++;
		if (fix >= tif->tif_nfields || tif->tif_fieldinfo[fix]->field_tag != dp->tdir_tag) {
			
			haveunknowntags = 1;
			continue;
		}
		
		if (tif->tif_fieldinfo[fix]->field_bit == FIELD_IGNORE) {
	ignore:
			dp->tdir_tag = IGNORE;
			continue;
		}
		
		fip = tif->tif_fieldinfo[fix];
		while (dp->tdir_type != (unsigned short) fip->field_type && fix < tif->tif_nfields) {
			if (fip->field_type == TIFF_ANY)	
				break;
			fip = tif->tif_fieldinfo[++fix];
			if (fix >= tif->tif_nfields || fip->field_tag != dp->tdir_tag) {
				TIFFWarningExt(tif->tif_clientdata, module, "%s: wrong data type %d for \"%s\"; tag ignored", tif->tif_name, dp->tdir_type, tif->tif_fieldinfo[fix-1]->field_name);


				goto ignore;
			}
		}
		
		if (fip->field_readcount != TIFF_VARIABLE && fip->field_readcount != TIFF_VARIABLE2) {
			uint32 expected = (fip->field_readcount == TIFF_SPP) ? (uint32) td->td_samplesperpixel :
			    (uint32) fip->field_readcount;
			if (!CheckDirCount(tif, dp, expected))
				goto ignore;
		}

		switch (dp->tdir_tag) {
		case TIFFTAG_COMPRESSION:
			
			if (dp->tdir_count == 1) {
				v = TIFFExtractData(tif, dp->tdir_type, dp->tdir_offset);
				if (!TIFFSetField(tif, dp->tdir_tag, (uint16)v))
					goto bad;
				else compressionknown = 1;
				break;
			
			} else if (dp->tdir_type == TIFF_LONG) {
				if (!TIFFFetchPerSampleLongs(tif, dp, &v) || !TIFFSetField(tif, dp->tdir_tag, (uint16)v))
					goto bad;
			} else {
				if (!TIFFFetchPerSampleShorts(tif, dp, &iv)
				    || !TIFFSetField(tif, dp->tdir_tag, iv))
					goto bad;
			}
			dp->tdir_tag = IGNORE;
			break;
		case TIFFTAG_STRIPOFFSETS:
		case TIFFTAG_STRIPBYTECOUNTS:
		case TIFFTAG_TILEOFFSETS:
		case TIFFTAG_TILEBYTECOUNTS:
			TIFFSetFieldBit(tif, fip->field_bit);
			break;
		case TIFFTAG_IMAGEWIDTH:
		case TIFFTAG_IMAGELENGTH:
		case TIFFTAG_IMAGEDEPTH:
		case TIFFTAG_TILELENGTH:
		case TIFFTAG_TILEWIDTH:
		case TIFFTAG_TILEDEPTH:
		case TIFFTAG_PLANARCONFIG:
		case TIFFTAG_ROWSPERSTRIP:
		case TIFFTAG_EXTRASAMPLES:
			if (!TIFFFetchNormalTag(tif, dp))
				goto bad;
			dp->tdir_tag = IGNORE;
			break;
		}
	}

	
	if (haveunknowntags) {
	    fix = 0;
	    for (dp = dir, n = dircount; n > 0; n--, dp++) {
		if (dp->tdir_tag == IGNORE)
			continue;
		if (fix >= tif->tif_nfields || dp->tdir_tag < tif->tif_fieldinfo[fix]->field_tag)
			fix = 0;			
		while (fix < tif->tif_nfields && tif->tif_fieldinfo[fix]->field_tag < dp->tdir_tag)
			fix++;
		if (fix >= tif->tif_nfields || tif->tif_fieldinfo[fix]->field_tag != dp->tdir_tag) {

					TIFFWarningExt(tif->tif_clientdata, module, "%s: unknown field with tag %d (0x%x) encountered", tif->tif_name, dp->tdir_tag, dp->tdir_tag);





					if (!_TIFFMergeFieldInfo(tif, _TIFFCreateAnonFieldInfo(tif, dp->tdir_tag, (TIFFDataType) dp->tdir_type), 1))



					{
					TIFFWarningExt(tif->tif_clientdata, module, "Registering anonymous field with tag %d (0x%x) failed", dp->tdir_tag, dp->tdir_tag);



					dp->tdir_tag = IGNORE;
					continue;
					}
			fix = 0;
			while (fix < tif->tif_nfields && tif->tif_fieldinfo[fix]->field_tag < dp->tdir_tag)
				fix++;
		}
		
		fip = tif->tif_fieldinfo[fix];
		while (dp->tdir_type != (unsigned short) fip->field_type && fix < tif->tif_nfields) {
			if (fip->field_type == TIFF_ANY)	
				break;
			fip = tif->tif_fieldinfo[++fix];
			if (fix >= tif->tif_nfields || fip->field_tag != dp->tdir_tag) {
				TIFFWarningExt(tif->tif_clientdata, module, "%s: wrong data type %d for \"%s\"; tag ignored", tif->tif_name, dp->tdir_type, tif->tif_fieldinfo[fix-1]->field_name);


				dp->tdir_tag = IGNORE;
				break;
			}
		}
	    }
	}

	
	if ((td->td_compression==COMPRESSION_OJPEG) && (td->td_planarconfig==PLANARCONFIG_SEPARATE)) {
		dp = TIFFReadDirectoryFind(dir,dircount,TIFFTAG_STRIPOFFSETS);
		if ((dp!=0) && (dp->tdir_count==1)) {
			dp = TIFFReadDirectoryFind(dir, dircount, TIFFTAG_STRIPBYTECOUNTS);
			if ((dp!=0) && (dp->tdir_count==1)) {
				td->td_planarconfig=PLANARCONFIG_CONTIG;
				TIFFWarningExt(tif->tif_clientdata, "TIFFReadDirectory", "Planarconfig tag value assumed incorrect, " "assuming data is contig instead of chunky");


			}
		}
	}

	
	if (!TIFFFieldSet(tif, FIELD_IMAGEDIMENSIONS)) {
		MissingRequired(tif, "ImageLength");
		goto bad;
	}
	
	if (!TIFFFieldSet(tif, FIELD_TILEDIMENSIONS)) {
		td->td_nstrips = TIFFNumberOfStrips(tif);
		td->td_tilewidth = td->td_imagewidth;
		td->td_tilelength = td->td_rowsperstrip;
		td->td_tiledepth = td->td_imagedepth;
		tif->tif_flags &= ~TIFF_ISTILED;
	} else {
		td->td_nstrips = TIFFNumberOfTiles(tif);
		tif->tif_flags |= TIFF_ISTILED;
	}
	if (!td->td_nstrips) {
		TIFFErrorExt(tif->tif_clientdata, module, "%s: cannot handle zero number of %s", tif->tif_name, isTiled(tif) ? "tiles" : "strips");

		goto bad;
	}
	td->td_stripsperimage = td->td_nstrips;
	if (td->td_planarconfig == PLANARCONFIG_SEPARATE)
		td->td_stripsperimage /= td->td_samplesperpixel;
	if (!TIFFFieldSet(tif, FIELD_STRIPOFFSETS)) {
		if ((td->td_compression==COMPRESSION_OJPEG) && (isTiled(tif)==0) && (td->td_nstrips==1)) {

			
			TIFFSetFieldBit(tif, FIELD_STRIPOFFSETS);
		} else {
			MissingRequired(tif, isTiled(tif) ? "TileOffsets" : "StripOffsets");
			goto bad;
		}
	}

	
	for (dp = dir, n = dircount; n > 0; n--, dp++) {
		if (dp->tdir_tag == IGNORE)
			continue;
		switch (dp->tdir_tag) {
		case TIFFTAG_MINSAMPLEVALUE:
		case TIFFTAG_MAXSAMPLEVALUE:
		case TIFFTAG_BITSPERSAMPLE:
		case TIFFTAG_DATATYPE:
		case TIFFTAG_SAMPLEFORMAT:
			
			if (dp->tdir_count == 1) {
				v = TIFFExtractData(tif, dp->tdir_type, dp->tdir_offset);
				if (!TIFFSetField(tif, dp->tdir_tag, (uint16)v))
					goto bad;
			
			} else if (dp->tdir_tag == TIFFTAG_BITSPERSAMPLE && dp->tdir_type == TIFF_LONG) {
				if (!TIFFFetchPerSampleLongs(tif, dp, &v) || !TIFFSetField(tif, dp->tdir_tag, (uint16)v))
					goto bad;
			} else {
				if (!TIFFFetchPerSampleShorts(tif, dp, &iv) || !TIFFSetField(tif, dp->tdir_tag, iv))
					goto bad;
			}
			break;
		case TIFFTAG_SMINSAMPLEVALUE:
		case TIFFTAG_SMAXSAMPLEVALUE:
			{
				double dv = 0.0;
				if (!TIFFFetchPerSampleAnys(tif, dp, &dv) || !TIFFSetField(tif, dp->tdir_tag, dv))
					goto bad;
			}
			break;
		case TIFFTAG_STRIPOFFSETS:
		case TIFFTAG_TILEOFFSETS:
			if (!TIFFFetchStripThing(tif, dp, td->td_nstrips, &td->td_stripoffset))
				goto bad;
			break;
		case TIFFTAG_STRIPBYTECOUNTS:
		case TIFFTAG_TILEBYTECOUNTS:
			if (!TIFFFetchStripThing(tif, dp, td->td_nstrips, &td->td_stripbytecount))
				goto bad;
			break;
		case TIFFTAG_COLORMAP:
		case TIFFTAG_TRANSFERFUNCTION:
			{
				char* cp;
				
				v = 1L<<td->td_bitspersample;
				if (dp->tdir_tag == TIFFTAG_COLORMAP || dp->tdir_count != v) {
					if (!CheckDirCount(tif, dp, 3 * v))
						break;
				}
				v *= sizeof(uint16);
				cp = (char *)_TIFFCheckMalloc(tif, dp->tdir_count, sizeof (uint16), "to read \"TransferFunction\" tag");


				if (cp != NULL) {
					if (TIFFFetchData(tif, dp, cp)) {
						
						uint32 c = 1L << td->td_bitspersample;
						if (dp->tdir_count == c)
							v = 0L;
						TIFFSetField(tif, dp->tdir_tag, cp, cp+v, cp+2*v);
					}
					_TIFFfree(cp);
				}
				break;
			}
		case TIFFTAG_PAGENUMBER:
		case TIFFTAG_HALFTONEHINTS:
		case TIFFTAG_YCBCRSUBSAMPLING:
		case TIFFTAG_DOTRANGE:
			(void) TIFFFetchShortPair(tif, dp);
			break;
		case TIFFTAG_REFERENCEBLACKWHITE:
			(void) TIFFFetchRefBlackWhite(tif, dp);
			break;

		case TIFFTAG_OSUBFILETYPE:
			v = 0L;
			switch (TIFFExtractData(tif, dp->tdir_type, dp->tdir_offset)) {
			case OFILETYPE_REDUCEDIMAGE:
				v = FILETYPE_REDUCEDIMAGE;
				break;
			case OFILETYPE_PAGE:
				v = FILETYPE_PAGE;
				break;
			}
			if (v)
				TIFFSetField(tif, TIFFTAG_SUBFILETYPE, v);
			break;

		default:
			(void) TIFFFetchNormalTag(tif, dp);
			break;
		}
	}
	
	if (td->td_compression==COMPRESSION_OJPEG)
	{
		if (!TIFFFieldSet(tif,FIELD_PHOTOMETRIC))
		{
			TIFFWarningExt(tif->tif_clientdata, "TIFFReadDirectory", "Photometric tag is missing, assuming data is YCbCr");
			if (!TIFFSetField(tif,TIFFTAG_PHOTOMETRIC,PHOTOMETRIC_YCBCR))
				goto bad;
		}
		else if (td->td_photometric==PHOTOMETRIC_RGB)
		{
			td->td_photometric=PHOTOMETRIC_YCBCR;
			TIFFWarningExt(tif->tif_clientdata, "TIFFReadDirectory", "Photometric tag value assumed incorrect, " "assuming data is YCbCr instead of RGB");

		}
		if (!TIFFFieldSet(tif,FIELD_BITSPERSAMPLE))
		{
			TIFFWarningExt(tif->tif_clientdata,"TIFFReadDirectory", "BitsPerSample tag is missing, assuming 8 bits per sample");
			if (!TIFFSetField(tif,TIFFTAG_BITSPERSAMPLE,8))
				goto bad;
		}
		if (!TIFFFieldSet(tif,FIELD_SAMPLESPERPIXEL))
		{
			if ((td->td_photometric==PHOTOMETRIC_RGB)
			    || (td->td_photometric==PHOTOMETRIC_YCBCR))
			{
				TIFFWarningExt(tif->tif_clientdata, "TIFFReadDirectory", "SamplesPerPixel tag is missing, " "assuming correct SamplesPerPixel value is 3");


				if (!TIFFSetField(tif,TIFFTAG_SAMPLESPERPIXEL,3))
					goto bad;
			}
			else if ((td->td_photometric==PHOTOMETRIC_MINISWHITE)
				 || (td->td_photometric==PHOTOMETRIC_MINISBLACK))
			{
				TIFFWarningExt(tif->tif_clientdata, "TIFFReadDirectory", "SamplesPerPixel tag is missing, " "assuming correct SamplesPerPixel value is 1");


				if (!TIFFSetField(tif,TIFFTAG_SAMPLESPERPIXEL,1))
					goto bad;
			}
		}
	}
	
	if (td->td_photometric == PHOTOMETRIC_PALETTE && !TIFFFieldSet(tif, FIELD_COLORMAP)) {
		MissingRequired(tif, "Colormap");
		goto bad;
	}
	
	if (td->td_compression!=COMPRESSION_OJPEG)
	{
		
		if (!TIFFFieldSet(tif, FIELD_STRIPBYTECOUNTS)) {
			
			if ((td->td_planarconfig == PLANARCONFIG_CONTIG && td->td_nstrips > 1) || (td->td_planarconfig == PLANARCONFIG_SEPARATE && td->td_nstrips != td->td_samplesperpixel)) {


			    MissingRequired(tif, "StripByteCounts");
			    goto bad;
			}
			TIFFWarningExt(tif->tif_clientdata, module, "%s: TIFF directory is missing required " "\"%s\" field, calculating from imagelength", tif->tif_name, _TIFFFieldWithTag(tif,TIFFTAG_STRIPBYTECOUNTS)->field_name);



			if (EstimateStripByteCounts(tif, dir, dircount) < 0)
			    goto bad;
		
		#define	BYTECOUNTLOOKSBAD  ( (td->td_stripbytecount[0] == 0 && td->td_stripoffset[0] != 0) || (td->td_compression == COMPRESSION_NONE && td->td_stripbytecount[0] > TIFFGetFileSize(tif) - td->td_stripoffset[0]) || (tif->tif_mode == O_RDONLY && td->td_compression == COMPRESSION_NONE && td->td_stripbytecount[0] < TIFFScanlineSize(tif) * td->td_imagelength)






		} else if (td->td_nstrips == 1 && td->td_stripoffset[0] != 0 && BYTECOUNTLOOKSBAD) {

			
			TIFFWarningExt(tif->tif_clientdata, module, "%s: Bogus \"%s\" field, ignoring and calculating from imagelength", tif->tif_name, _TIFFFieldWithTag(tif,TIFFTAG_STRIPBYTECOUNTS)->field_name);


			if(EstimateStripByteCounts(tif, dir, dircount) < 0)
			    goto bad;
		} else if (td->td_planarconfig == PLANARCONFIG_CONTIG && td->td_nstrips > 2 && td->td_compression == COMPRESSION_NONE && td->td_stripbytecount[0] != td->td_stripbytecount[1] && td->td_stripbytecount[0] != 0 && td->td_stripbytecount[1] != 0 ) {




			
			TIFFWarningExt(tif->tif_clientdata, module, "%s: Wrong \"%s\" field, ignoring and calculating from imagelength", tif->tif_name, _TIFFFieldWithTag(tif,TIFFTAG_STRIPBYTECOUNTS)->field_name);


			if (EstimateStripByteCounts(tif, dir, dircount) < 0)
			    goto bad;
		}
	}
	if (dir) {
		_TIFFfree((char *)dir);
		dir = NULL;
	}
	if (!TIFFFieldSet(tif, FIELD_MAXSAMPLEVALUE))
		td->td_maxsamplevalue = (uint16)((1L<<td->td_bitspersample)-1);
	

	
	if (td->td_nstrips > 1) {
		tstrip_t strip;

		td->td_stripbytecountsorted = 1;
		for (strip = 1; strip < td->td_nstrips; strip++) {
			if (td->td_stripoffset[strip - 1] > td->td_stripoffset[strip]) {
				td->td_stripbytecountsorted = 0;
				break;
			}
		}
	}

	if (!TIFFFieldSet(tif, FIELD_COMPRESSION))
		TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_NONE);
	
	if (td->td_nstrips == 1 && td->td_compression == COMPRESSION_NONE && (tif->tif_flags & (TIFF_STRIPCHOP|TIFF_ISTILED)) == TIFF_STRIPCHOP)
		ChopUpSingleUncompressedStrip(tif);

	
	tif->tif_row = (uint32) -1;
	tif->tif_curstrip = (tstrip_t) -1;
	tif->tif_col = (uint32) -1;
	tif->tif_curtile = (ttile_t) -1;
	tif->tif_tilesize = (tsize_t) -1;

	tif->tif_scanlinesize = TIFFScanlineSize(tif);
	if (!tif->tif_scanlinesize) {
		TIFFErrorExt(tif->tif_clientdata, module, "%s: cannot handle zero scanline size", tif->tif_name);

		return (0);
	}

	if (isTiled(tif)) {
		tif->tif_tilesize = TIFFTileSize(tif);
		if (!tif->tif_tilesize) {
			TIFFErrorExt(tif->tif_clientdata, module, "%s: cannot handle zero tile size", tif->tif_name);

			return (0);
		}
	} else {
		if (!TIFFStripSize(tif)) {
			TIFFErrorExt(tif->tif_clientdata, module, "%s: cannot handle zero strip size", tif->tif_name);

			return (0);
		}
	}
	return (1);
bad:
	if (dir)
		_TIFFfree(dir);
	return (0);
}

static TIFFDirEntry* TIFFReadDirectoryFind(TIFFDirEntry* dir, uint16 dircount, uint16 tagid)
{
	TIFFDirEntry* m;
	uint16 n;
	for (m=dir, n=0; n<dircount; m++, n++)
	{
		if (m->tdir_tag==tagid)
			return(m);
	}
	return(0);
}


int TIFFReadCustomDirectory(TIFF* tif, toff_t diroff, const TIFFFieldInfo info[], size_t n)

{
	static const char module[] = "TIFFReadCustomDirectory";

	TIFFDirectory* td = &tif->tif_dir;
	TIFFDirEntry *dp, *dir = NULL;
	const TIFFFieldInfo* fip;
	size_t fix;
	uint16 i, dircount;

	_TIFFSetupFieldInfo(tif, info, n);

	dircount = TIFFFetchDirectory(tif, diroff, &dir, NULL);
	if (!dircount) {
		TIFFErrorExt(tif->tif_clientdata, module, "%s: Failed to read custom directory at offset %u", tif->tif_name, diroff);

		return 0;
	}

	TIFFFreeDirectory(tif);
        _TIFFmemset(&tif->tif_dir, 0, sizeof(TIFFDirectory));

	fix = 0;
	for (dp = dir, i = dircount; i > 0; i--, dp++) {
		if (tif->tif_flags & TIFF_SWAB) {
			TIFFSwabArrayOfShort(&dp->tdir_tag, 2);
			TIFFSwabArrayOfLong(&dp->tdir_count, 2);
		}

		if (fix >= tif->tif_nfields || dp->tdir_tag == IGNORE)
			continue;

		while (fix < tif->tif_nfields && tif->tif_fieldinfo[fix]->field_tag < dp->tdir_tag)
			fix++;

		if (fix >= tif->tif_nfields || tif->tif_fieldinfo[fix]->field_tag != dp->tdir_tag) {

			TIFFWarningExt(tif->tif_clientdata, module, "%s: unknown field with tag %d (0x%x) encountered", tif->tif_name, dp->tdir_tag, dp->tdir_tag);

			if (!_TIFFMergeFieldInfo(tif, _TIFFCreateAnonFieldInfo(tif, dp->tdir_tag, (TIFFDataType) dp->tdir_type), 1))



			{
				TIFFWarningExt(tif->tif_clientdata, module, "Registering anonymous field with tag %d (0x%x) failed", dp->tdir_tag, dp->tdir_tag);

				goto ignore;
			}

			fix = 0;
			while (fix < tif->tif_nfields && tif->tif_fieldinfo[fix]->field_tag < dp->tdir_tag)
				fix++;
		}
		
		if (tif->tif_fieldinfo[fix]->field_bit == FIELD_IGNORE) {
	ignore:
			dp->tdir_tag = IGNORE;
			continue;
		}
		
		fip = tif->tif_fieldinfo[fix];
		while (dp->tdir_type != (unsigned short) fip->field_type && fix < tif->tif_nfields) {
			if (fip->field_type == TIFF_ANY)	
				break;
                        fip = tif->tif_fieldinfo[++fix];
			if (fix >= tif->tif_nfields || fip->field_tag != dp->tdir_tag) {
				TIFFWarningExt(tif->tif_clientdata, module, "%s: wrong data type %d for \"%s\"; tag ignored", tif->tif_name, dp->tdir_type, tif->tif_fieldinfo[fix-1]->field_name);


				goto ignore;
			}
		}
		
		if (fip->field_readcount != TIFF_VARIABLE && fip->field_readcount != TIFF_VARIABLE2) {
			uint32 expected = (fip->field_readcount == TIFF_SPP) ? (uint32) td->td_samplesperpixel :
			    (uint32) fip->field_readcount;
			if (!CheckDirCount(tif, dp, expected))
				goto ignore;
		}

		
		switch (dp->tdir_tag) {
			case EXIFTAG_SUBJECTDISTANCE:
				(void) TIFFFetchSubjectDistance(tif, dp);
				break;
			default:
				(void) TIFFFetchNormalTag(tif, dp);
				break;
		}
	}
	
	if (dir)
		_TIFFfree(dir);
	return 1;
}


int TIFFReadEXIFDirectory(TIFF* tif, toff_t diroff)
{
	size_t exifFieldInfoCount;
	const TIFFFieldInfo *exifFieldInfo = _TIFFGetExifFieldInfo(&exifFieldInfoCount);
	return TIFFReadCustomDirectory(tif, diroff, exifFieldInfo, exifFieldInfoCount);
}

static int EstimateStripByteCounts(TIFF* tif, TIFFDirEntry* dir, uint16 dircount)
{
	static const char module[] = "EstimateStripByteCounts";

	TIFFDirEntry *dp;
	TIFFDirectory *td = &tif->tif_dir;
	uint32 strip;

	if (td->td_stripbytecount)
		_TIFFfree(td->td_stripbytecount);
	td->td_stripbytecount = (uint32*)
	    _TIFFCheckMalloc(tif, td->td_nstrips, sizeof (uint32), "for \"StripByteCounts\" array");
        if( td->td_stripbytecount == NULL )
            return -1;

	if (td->td_compression != COMPRESSION_NONE) {
		uint32 space = (uint32)(sizeof (TIFFHeader)
		    + sizeof (uint16)
		    + (dircount * sizeof (TIFFDirEntry))
		    + sizeof (uint32));
		toff_t filesize = TIFFGetFileSize(tif);
		uint16 n;

		
		for (dp = dir, n = dircount; n > 0; n--, dp++)
		{
			uint32 cc = TIFFDataWidth((TIFFDataType) dp->tdir_type);
			if (cc == 0) {
				TIFFErrorExt(tif->tif_clientdata, module, "%s: Cannot determine size of unknown tag type %d", tif->tif_name, dp->tdir_type);

				return -1;
			}
			cc = cc * dp->tdir_count;
			if (cc > sizeof (uint32))
				space += cc;
		}
		space = filesize - space;
		if (td->td_planarconfig == PLANARCONFIG_SEPARATE)
			space /= td->td_samplesperpixel;
		for (strip = 0; strip < td->td_nstrips; strip++)
			td->td_stripbytecount[strip] = space;
		 
		strip--;
		if (((toff_t)(td->td_stripoffset[strip]+ td->td_stripbytecount[strip])) > filesize)
			td->td_stripbytecount[strip] = filesize - td->td_stripoffset[strip];
	} else if (isTiled(tif)) {
		uint32 bytespertile = TIFFTileSize(tif);

		for (strip = 0; strip < td->td_nstrips; strip++)
                    td->td_stripbytecount[strip] = bytespertile;
	} else {
		uint32 rowbytes = TIFFScanlineSize(tif);
		uint32 rowsperstrip = td->td_imagelength/td->td_stripsperimage;
		for (strip = 0; strip < td->td_nstrips; strip++)
			td->td_stripbytecount[strip] = rowbytes * rowsperstrip;
	}
	TIFFSetFieldBit(tif, FIELD_STRIPBYTECOUNTS);
	if (!TIFFFieldSet(tif, FIELD_ROWSPERSTRIP))
		td->td_rowsperstrip = td->td_imagelength;
	return 1;
}

static void MissingRequired(TIFF* tif, const char* tagname)
{
	static const char module[] = "MissingRequired";

	TIFFErrorExt(tif->tif_clientdata, module, "%s: TIFF directory is missing required \"%s\" field", tif->tif_name, tagname);

}


static int TIFFCheckDirOffset(TIFF* tif, toff_t diroff)
{
	uint16 n;

	if (diroff == 0)			
		return 0;

	for (n = 0; n < tif->tif_dirnumber && tif->tif_dirlist; n++) {
		if (tif->tif_dirlist[n] == diroff)
			return 0;
	}

	tif->tif_dirnumber++;

	if (tif->tif_dirnumber > tif->tif_dirlistsize) {
		toff_t* new_dirlist;

		
		new_dirlist = (toff_t *)_TIFFCheckRealloc(tif, tif->tif_dirlist, tif->tif_dirnumber, 2 * sizeof(toff_t), "for IFD list");



		if (!new_dirlist)
			return 0;
		tif->tif_dirlistsize = 2 * tif->tif_dirnumber;
		tif->tif_dirlist = new_dirlist;
	}

	tif->tif_dirlist[tif->tif_dirnumber - 1] = diroff;

	return 1;
}


static int CheckDirCount(TIFF* tif, TIFFDirEntry* dir, uint32 count)
{
	if (count > dir->tdir_count) {
		TIFFWarningExt(tif->tif_clientdata, tif->tif_name, "incorrect count for field \"%s\" (%u, expecting %u); tag ignored", _TIFFFieldWithTag(tif, dir->tdir_tag)->field_name, dir->tdir_count, count);


		return (0);
	} else if (count < dir->tdir_count) {
		TIFFWarningExt(tif->tif_clientdata, tif->tif_name, "incorrect count for field \"%s\" (%u, expecting %u); tag trimmed", _TIFFFieldWithTag(tif, dir->tdir_tag)->field_name, dir->tdir_count, count);


		return (1);
	}
	return (1);
}


static uint16 TIFFFetchDirectory(TIFF* tif, toff_t diroff, TIFFDirEntry **pdir, toff_t *nextdiroff)

{
	static const char module[] = "TIFFFetchDirectory";

	TIFFDirEntry *dir;
	uint16 dircount;

	assert(pdir);

	tif->tif_diroff = diroff;
	if (nextdiroff)
		*nextdiroff = 0;
	if (!isMapped(tif)) {
		if (!SeekOK(tif, tif->tif_diroff)) {
			TIFFErrorExt(tif->tif_clientdata, module, "%s: Seek error accessing TIFF directory", tif->tif_name);

			return 0;
		}
		if (!ReadOK(tif, &dircount, sizeof (uint16))) {
			TIFFErrorExt(tif->tif_clientdata, module, "%s: Can not read TIFF directory count", tif->tif_name);

			return 0;
		}
		if (tif->tif_flags & TIFF_SWAB)
			TIFFSwabShort(&dircount);
		dir = (TIFFDirEntry *)_TIFFCheckMalloc(tif, dircount, sizeof (TIFFDirEntry), "to read TIFF directory");

		if (dir == NULL)
			return 0;
		if (!ReadOK(tif, dir, dircount*sizeof (TIFFDirEntry))) {
			TIFFErrorExt(tif->tif_clientdata, module, "%.100s: Can not read TIFF directory", tif->tif_name);

			_TIFFfree(dir);
			return 0;
		}
		
		if (nextdiroff)
			(void) ReadOK(tif, nextdiroff, sizeof(uint32));
	} else {
		toff_t off = tif->tif_diroff;

		
		if (tif->tif_size < sizeof (uint16) || off > tif->tif_size - sizeof(uint16)) {
			TIFFErrorExt(tif->tif_clientdata, module, "%s: Can not read TIFF directory count", tif->tif_name);

			return 0;
		} else {
			_TIFFmemcpy(&dircount, tif->tif_base + off, sizeof(uint16));
		}
		off += sizeof (uint16);
		if (tif->tif_flags & TIFF_SWAB)
			TIFFSwabShort(&dircount);
		dir = (TIFFDirEntry *)_TIFFCheckMalloc(tif, dircount, sizeof(TIFFDirEntry), "to read TIFF directory");

		if (dir == NULL)
			return 0;
		if (off + dircount * sizeof (TIFFDirEntry) > tif->tif_size) {
			TIFFErrorExt(tif->tif_clientdata, module, "%s: Can not read TIFF directory", tif->tif_name);

			_TIFFfree(dir);
			return 0;
		} else {
			_TIFFmemcpy(dir, tif->tif_base + off, dircount * sizeof(TIFFDirEntry));
		}
		if (nextdiroff) {
			off += dircount * sizeof (TIFFDirEntry);
			if (off + sizeof (uint32) <= tif->tif_size) {
				_TIFFmemcpy(nextdiroff, tif->tif_base + off, sizeof (uint32));
			}
		}
	}
	if (nextdiroff && tif->tif_flags & TIFF_SWAB)
		TIFFSwabLong(nextdiroff);
	*pdir = dir;
	return dircount;
}


static tsize_t TIFFFetchData(TIFF* tif, TIFFDirEntry* dir, char* cp)
{
	uint32 w = TIFFDataWidth((TIFFDataType) dir->tdir_type);
	
	uint32 cc = dir->tdir_count * w;

	
	if (!dir->tdir_count || !w || cc / w != dir->tdir_count)
		goto bad;

	if (!isMapped(tif)) {
		if (!SeekOK(tif, dir->tdir_offset))
			goto bad;
		if (!ReadOK(tif, cp, cc))
			goto bad;
	} else {
		
		if (dir->tdir_offset + cc < dir->tdir_offset || dir->tdir_offset + cc < cc || dir->tdir_offset + cc > tif->tif_size)

			goto bad;
		_TIFFmemcpy(cp, tif->tif_base + dir->tdir_offset, cc);
	}
	if (tif->tif_flags & TIFF_SWAB) {
		switch (dir->tdir_type) {
		case TIFF_SHORT:
		case TIFF_SSHORT:
			TIFFSwabArrayOfShort((uint16*) cp, dir->tdir_count);
			break;
		case TIFF_LONG:
		case TIFF_SLONG:
		case TIFF_FLOAT:
			TIFFSwabArrayOfLong((uint32*) cp, dir->tdir_count);
			break;
		case TIFF_RATIONAL:
		case TIFF_SRATIONAL:
			TIFFSwabArrayOfLong((uint32*) cp, 2*dir->tdir_count);
			break;
		case TIFF_DOUBLE:
			TIFFSwabArrayOfDouble((double*) cp, dir->tdir_count);
			break;
		}
	}
	return (cc);
bad:
	TIFFErrorExt(tif->tif_clientdata, tif->tif_name, "Error fetching data for field \"%s\"", _TIFFFieldWithTag(tif, dir->tdir_tag)->field_name);

	return (tsize_t) 0;
}


static tsize_t TIFFFetchString(TIFF* tif, TIFFDirEntry* dir, char* cp)
{
	if (dir->tdir_count <= 4) {
		uint32 l = dir->tdir_offset;
		if (tif->tif_flags & TIFF_SWAB)
			TIFFSwabLong(&l);
		_TIFFmemcpy(cp, &l, dir->tdir_count);
		return (1);
	}
	return (TIFFFetchData(tif, dir, cp));
}


static int cvtRational(TIFF* tif, TIFFDirEntry* dir, uint32 num, uint32 denom, float* rv)
{
	if (denom == 0) {
		TIFFErrorExt(tif->tif_clientdata, tif->tif_name, "%s: Rational with zero denominator (num = %u)", _TIFFFieldWithTag(tif, dir->tdir_tag)->field_name, num);

		return (0);
	} else {
		if (dir->tdir_type == TIFF_RATIONAL)
			*rv = ((float)num / (float)denom);
		else *rv = ((float)(int32)num / (float)(int32)denom);
		return (1);
	}
}


static float TIFFFetchRational(TIFF* tif, TIFFDirEntry* dir)
{
	uint32 l[2];
	float v;

	return (!TIFFFetchData(tif, dir, (char *)l) || !cvtRational(tif, dir, l[0], l[1], &v) ? 1.0f : v);
}


static float TIFFFetchFloat(TIFF* tif, TIFFDirEntry* dir)
{
	float v;
	int32 l = TIFFExtractData(tif, dir->tdir_type, dir->tdir_offset);
        _TIFFmemcpy(&v, &l, sizeof(float));
	TIFFCvtIEEEFloatToNative(tif, 1, &v);
	return (v);
}


static int TIFFFetchByteArray(TIFF* tif, TIFFDirEntry* dir, uint8* v)
{
    if (dir->tdir_count <= 4) {
        
        if (tif->tif_header.tiff_magic == TIFF_BIGENDIAN) {
	    if (dir->tdir_type == TIFF_SBYTE)
                switch (dir->tdir_count) {
                    case 4: v[3] = dir->tdir_offset & 0xff;
                    case 3: v[2] = (dir->tdir_offset >> 8) & 0xff;
                    case 2: v[1] = (dir->tdir_offset >> 16) & 0xff;
		    case 1: v[0] = dir->tdir_offset >> 24;
                }
	    else switch (dir->tdir_count) {
                    case 4: v[3] = dir->tdir_offset & 0xff;
                    case 3: v[2] = (dir->tdir_offset >> 8) & 0xff;
                    case 2: v[1] = (dir->tdir_offset >> 16) & 0xff;
		    case 1: v[0] = dir->tdir_offset >> 24;
                }
	} else {
	    if (dir->tdir_type == TIFF_SBYTE)
                switch (dir->tdir_count) {
                    case 4: v[3] = dir->tdir_offset >> 24;
                    case 3: v[2] = (dir->tdir_offset >> 16) & 0xff;
                    case 2: v[1] = (dir->tdir_offset >> 8) & 0xff;
                    case 1: v[0] = dir->tdir_offset & 0xff;
		}
	    else switch (dir->tdir_count) {
                    case 4: v[3] = dir->tdir_offset >> 24;
                    case 3: v[2] = (dir->tdir_offset >> 16) & 0xff;
                    case 2: v[1] = (dir->tdir_offset >> 8) & 0xff;
                    case 1: v[0] = dir->tdir_offset & 0xff;
		}
	}
        return (1);
    } else return (TIFFFetchData(tif, dir, (char*) v) != 0);
}


static int TIFFFetchShortArray(TIFF* tif, TIFFDirEntry* dir, uint16* v)
{
	if (dir->tdir_count <= 2) {
		if (tif->tif_header.tiff_magic == TIFF_BIGENDIAN) {
			switch (dir->tdir_count) {
			case 2: v[1] = (uint16) (dir->tdir_offset & 0xffff);
			case 1: v[0] = (uint16) (dir->tdir_offset >> 16);
			}
		} else {
			switch (dir->tdir_count) {
			case 2: v[1] = (uint16) (dir->tdir_offset >> 16);
			case 1: v[0] = (uint16) (dir->tdir_offset & 0xffff);
			}
		}
		return (1);
	} else return (TIFFFetchData(tif, dir, (char *)v) != 0);
}


static int TIFFFetchShortPair(TIFF* tif, TIFFDirEntry* dir)
{
	
	if (dir->tdir_count > 2) {
		TIFFWarningExt(tif->tif_clientdata, tif->tif_name, "unexpected count for field \"%s\", %u, expected 2; ignored", _TIFFFieldWithTag(tif, dir->tdir_tag)->field_name, dir->tdir_count);


		return 0;
	}

	switch (dir->tdir_type) {
		case TIFF_BYTE:
		case TIFF_SBYTE:
			{
			uint8 v[4];
			return TIFFFetchByteArray(tif, dir, v)
				&& TIFFSetField(tif, dir->tdir_tag, v[0], v[1]);
			}
		case TIFF_SHORT:
		case TIFF_SSHORT:
			{
			uint16 v[2];
			return TIFFFetchShortArray(tif, dir, v)
				&& TIFFSetField(tif, dir->tdir_tag, v[0], v[1]);
			}
		default:
			return 0;
	}
}


static int TIFFFetchLongArray(TIFF* tif, TIFFDirEntry* dir, uint32* v)
{
	if (dir->tdir_count == 1) {
		v[0] = dir->tdir_offset;
		return (1);
	} else return (TIFFFetchData(tif, dir, (char*) v) != 0);
}


static int TIFFFetchRationalArray(TIFF* tif, TIFFDirEntry* dir, float* v)
{
	int ok = 0;
	uint32* l;

	l = (uint32*)_TIFFCheckMalloc(tif, dir->tdir_count, TIFFDataWidth((TIFFDataType) dir->tdir_type), "to fetch array of rationals");

	if (l) {
		if (TIFFFetchData(tif, dir, (char *)l)) {
			uint32 i;
			for (i = 0; i < dir->tdir_count; i++) {
				ok = cvtRational(tif, dir, l[2*i+0], l[2*i+1], &v[i]);
				if (!ok)
					break;
			}
		}
		_TIFFfree((char *)l);
	}
	return (ok);
}


static int TIFFFetchFloatArray(TIFF* tif, TIFFDirEntry* dir, float* v)
{

	if (dir->tdir_count == 1) {
	        union {
		  float  f;
		  uint32 i;
		} float_union;

		float_union.i=dir->tdir_offset;
		v[0]=float_union.f;
		TIFFCvtIEEEFloatToNative(tif, dir->tdir_count, v);
		return (1);
	} else	if (TIFFFetchData(tif, dir, (char*) v)) {
		TIFFCvtIEEEFloatToNative(tif, dir->tdir_count, v);
		return (1);
	} else return (0);
}


static int TIFFFetchDoubleArray(TIFF* tif, TIFFDirEntry* dir, double* v)
{
	if (TIFFFetchData(tif, dir, (char*) v)) {
		TIFFCvtIEEEDoubleToNative(tif, dir->tdir_count, v);
		return (1);
	} else return (0);
}


static int TIFFFetchAnyArray(TIFF* tif, TIFFDirEntry* dir, double* v)
{
	int i;

	switch (dir->tdir_type) {
	case TIFF_BYTE:
	case TIFF_SBYTE:
		if (!TIFFFetchByteArray(tif, dir, (uint8*) v))
			return (0);
		if (dir->tdir_type == TIFF_BYTE) {
			uint8* vp = (uint8*) v;
			for (i = dir->tdir_count-1; i >= 0; i--)
				v[i] = vp[i];
		} else {
			int8* vp = (int8*) v;
			for (i = dir->tdir_count-1; i >= 0; i--)
				v[i] = vp[i];
		}
		break;
	case TIFF_SHORT:
	case TIFF_SSHORT:
		if (!TIFFFetchShortArray(tif, dir, (uint16*) v))
			return (0);
		if (dir->tdir_type == TIFF_SHORT) {
			uint16* vp = (uint16*) v;
			for (i = dir->tdir_count-1; i >= 0; i--)
				v[i] = vp[i];
		} else {
			int16* vp = (int16*) v;
			for (i = dir->tdir_count-1; i >= 0; i--)
				v[i] = vp[i];
		}
		break;
	case TIFF_LONG:
	case TIFF_SLONG:
		if (!TIFFFetchLongArray(tif, dir, (uint32*) v))
			return (0);
		if (dir->tdir_type == TIFF_LONG) {
			uint32* vp = (uint32*) v;
			for (i = dir->tdir_count-1; i >= 0; i--)
				v[i] = vp[i];
		} else {
			int32* vp = (int32*) v;
			for (i = dir->tdir_count-1; i >= 0; i--)
				v[i] = vp[i];
		}
		break;
	case TIFF_RATIONAL:
	case TIFF_SRATIONAL:
		if (!TIFFFetchRationalArray(tif, dir, (float*) v))
			return (0);
		{ float* vp = (float*) v;
		  for (i = dir->tdir_count-1; i >= 0; i--)
			v[i] = vp[i];
		}
		break;
	case TIFF_FLOAT:
		if (!TIFFFetchFloatArray(tif, dir, (float*) v))
			return (0);
		{ float* vp = (float*) v;
		  for (i = dir->tdir_count-1; i >= 0; i--)
			v[i] = vp[i];
		}
		break;
	case TIFF_DOUBLE:
		return (TIFFFetchDoubleArray(tif, dir, (double*) v));
	default:
		
		
		
		TIFFErrorExt(tif->tif_clientdata, tif->tif_name, "cannot read TIFF_ANY type %d for field \"%s\"", dir->tdir_type, _TIFFFieldWithTag(tif, dir->tdir_tag)->field_name);


		return (0);
	}
	return (1);
}


static int TIFFFetchNormalTag(TIFF* tif, TIFFDirEntry* dp)
{
	static const char mesg[] = "to fetch tag value";
	int ok = 0;
	const TIFFFieldInfo* fip = _TIFFFieldWithTag(tif, dp->tdir_tag);

	if (dp->tdir_count > 1) {		
		char* cp = NULL;

		switch (dp->tdir_type) {
		case TIFF_BYTE:
		case TIFF_SBYTE:
			cp = (char *)_TIFFCheckMalloc(tif, dp->tdir_count, sizeof (uint8), mesg);
			ok = cp && TIFFFetchByteArray(tif, dp, (uint8*) cp);
			break;
		case TIFF_SHORT:
		case TIFF_SSHORT:
			cp = (char *)_TIFFCheckMalloc(tif, dp->tdir_count, sizeof (uint16), mesg);
			ok = cp && TIFFFetchShortArray(tif, dp, (uint16*) cp);
			break;
		case TIFF_LONG:
		case TIFF_SLONG:
			cp = (char *)_TIFFCheckMalloc(tif, dp->tdir_count, sizeof (uint32), mesg);
			ok = cp && TIFFFetchLongArray(tif, dp, (uint32*) cp);
			break;
		case TIFF_RATIONAL:
		case TIFF_SRATIONAL:
			cp = (char *)_TIFFCheckMalloc(tif, dp->tdir_count, sizeof (float), mesg);
			ok = cp && TIFFFetchRationalArray(tif, dp, (float*) cp);
			break;
		case TIFF_FLOAT:
			cp = (char *)_TIFFCheckMalloc(tif, dp->tdir_count, sizeof (float), mesg);
			ok = cp && TIFFFetchFloatArray(tif, dp, (float*) cp);
			break;
		case TIFF_DOUBLE:
			cp = (char *)_TIFFCheckMalloc(tif, dp->tdir_count, sizeof (double), mesg);
			ok = cp && TIFFFetchDoubleArray(tif, dp, (double*) cp);
			break;
		case TIFF_ASCII:
		case TIFF_UNDEFINED:		
			
			cp = (char *)_TIFFCheckMalloc(tif, dp->tdir_count + 1, 1, mesg);
			if( (ok = (cp && TIFFFetchString(tif, dp, cp))) != 0 )
				cp[dp->tdir_count] = '\0';	
			break;
		}
		if (ok) {
			ok = (fip->field_passcount ? TIFFSetField(tif, dp->tdir_tag, dp->tdir_count, cp)
			  : TIFFSetField(tif, dp->tdir_tag, cp));
		}
		if (cp != NULL)
			_TIFFfree(cp);
	} else if (CheckDirCount(tif, dp, 1)) {	
		switch (dp->tdir_type) {
		case TIFF_BYTE:
		case TIFF_SBYTE:
		case TIFF_SHORT:
		case TIFF_SSHORT:
			
			{ TIFFDataType type = fip->field_type;
			  if (type != TIFF_LONG && type != TIFF_SLONG) {
				uint16 v = (uint16)
			   TIFFExtractData(tif, dp->tdir_type, dp->tdir_offset);
				ok = (fip->field_passcount ? TIFFSetField(tif, dp->tdir_tag, 1, &v)
				  : TIFFSetField(tif, dp->tdir_tag, v));
				break;
			  }
			}
			
		case TIFF_LONG:
		case TIFF_SLONG:
			{ uint32 v32 = TIFFExtractData(tif, dp->tdir_type, dp->tdir_offset);
			  ok = (fip->field_passcount ?  TIFFSetField(tif, dp->tdir_tag, 1, &v32)
			    : TIFFSetField(tif, dp->tdir_tag, v32));
			}
			break;
		case TIFF_RATIONAL:
		case TIFF_SRATIONAL:
		case TIFF_FLOAT:
			{ float v = (dp->tdir_type == TIFF_FLOAT ?  TIFFFetchFloat(tif, dp)
			    : TIFFFetchRational(tif, dp));
			  ok = (fip->field_passcount ? TIFFSetField(tif, dp->tdir_tag, 1, &v)
			    : TIFFSetField(tif, dp->tdir_tag, v));
			}
			break;
		case TIFF_DOUBLE:
			{ double v;
			  ok = (TIFFFetchDoubleArray(tif, dp, &v) && (fip->field_passcount ? TIFFSetField(tif, dp->tdir_tag, 1, &v)

			    : TIFFSetField(tif, dp->tdir_tag, v))
			  );
			}
			break;
		case TIFF_ASCII:
		case TIFF_UNDEFINED:		
			{ char c[2];
			  if( (ok = (TIFFFetchString(tif, dp, c) != 0)) != 0 ) {
				c[1] = '\0';		
				ok = (fip->field_passcount ? TIFFSetField(tif, dp->tdir_tag, 1, c)
				      : TIFFSetField(tif, dp->tdir_tag, c));
			  }
			}
			break;
		}
	}
	return (ok);
}



static int TIFFFetchPerSampleShorts(TIFF* tif, TIFFDirEntry* dir, uint16* pl)
{
    uint16 samples = tif->tif_dir.td_samplesperpixel;
    int status = 0;

    if (CheckDirCount(tif, dir, (uint32) samples)) {
        uint16 buf[10];
        uint16* v = buf;

        if (dir->tdir_count > NITEMS(buf))
            v = (uint16*) _TIFFCheckMalloc(tif, dir->tdir_count, sizeof(uint16), "to fetch per-sample values");
        if (v && TIFFFetchShortArray(tif, dir, v)) {
            uint16 i;
            int check_count = dir->tdir_count;
            if( samples < check_count )
                check_count = samples;

            for (i = 1; i < check_count; i++)
                if (v[i] != v[0]) {
			TIFFErrorExt(tif->tif_clientdata, tif->tif_name, "Cannot handle different per-sample values for field \"%s\"", _TIFFFieldWithTag(tif, dir->tdir_tag)->field_name);

			goto bad;
                }
            *pl = v[0];
            status = 1;
        }
      bad:
        if (v && v != buf)
            _TIFFfree(v);
    }
    return (status);
}


static int TIFFFetchPerSampleLongs(TIFF* tif, TIFFDirEntry* dir, uint32* pl)
{
    uint16 samples = tif->tif_dir.td_samplesperpixel;
    int status = 0;

    if (CheckDirCount(tif, dir, (uint32) samples)) {
        uint32 buf[10];
        uint32* v = buf;

        if (dir->tdir_count > NITEMS(buf))
            v = (uint32*) _TIFFCheckMalloc(tif, dir->tdir_count, sizeof(uint32), "to fetch per-sample values");
        if (v && TIFFFetchLongArray(tif, dir, v)) {
            uint16 i;
            int check_count = dir->tdir_count;

            if( samples < check_count )
                check_count = samples;
            for (i = 1; i < check_count; i++)
                if (v[i] != v[0]) {
			TIFFErrorExt(tif->tif_clientdata, tif->tif_name, "Cannot handle different per-sample values for field \"%s\"", _TIFFFieldWithTag(tif, dir->tdir_tag)->field_name);

			goto bad;
                }
            *pl = v[0];
            status = 1;
        }
      bad:
        if (v && v != buf)
            _TIFFfree(v);
    }
    return (status);
}


static int TIFFFetchPerSampleAnys(TIFF* tif, TIFFDirEntry* dir, double* pl)
{
    uint16 samples = tif->tif_dir.td_samplesperpixel;
    int status = 0;

    if (CheckDirCount(tif, dir, (uint32) samples)) {
        double buf[10];
        double* v = buf;

        if (dir->tdir_count > NITEMS(buf))
            v = (double*) _TIFFCheckMalloc(tif, dir->tdir_count, sizeof (double), "to fetch per-sample values");
        if (v && TIFFFetchAnyArray(tif, dir, v)) {
            uint16 i;
            int check_count = dir->tdir_count;
            if( samples < check_count )
                check_count = samples;

            for (i = 1; i < check_count; i++)
                if (v[i] != v[0]) {
			TIFFErrorExt(tif->tif_clientdata, tif->tif_name, "Cannot handle different per-sample values for field \"%s\"", _TIFFFieldWithTag(tif, dir->tdir_tag)->field_name);

			goto bad;
                }
            *pl = v[0];
            status = 1;
        }
      bad:
        if (v && v != buf)
            _TIFFfree(v);
    }
    return (status);
}



static int TIFFFetchStripThing(TIFF* tif, TIFFDirEntry* dir, long nstrips, uint32** lpp)
{
	register uint32* lp;
	int status;

        CheckDirCount(tif, dir, (uint32) nstrips);

	
	if (*lpp == NULL && (*lpp = (uint32 *)_TIFFCheckMalloc(tif, nstrips, sizeof (uint32), "for strip array")) == NULL)

		return (0);
	lp = *lpp;
        _TIFFmemset( lp, 0, sizeof(uint32) * nstrips );

	if (dir->tdir_type == (int)TIFF_SHORT) {
		
		uint16* dp = (uint16*) _TIFFCheckMalloc(tif, dir->tdir_count, sizeof (uint16), "to fetch strip tag");
		if (dp == NULL)
			return (0);
		if( (status = TIFFFetchShortArray(tif, dir, dp)) != 0 ) {
                    int i;
                    
                    for( i = 0; i < nstrips && i < (int) dir->tdir_count; i++ )
                    {
                        lp[i] = dp[i];
                    }
		}
		_TIFFfree((char*) dp);

        } else if( nstrips != (int) dir->tdir_count ) {
            

            uint32* dp = (uint32*) _TIFFCheckMalloc(tif, dir->tdir_count, sizeof (uint32), "to fetch strip tag");
            if (dp == NULL)
                return (0);

            status = TIFFFetchLongArray(tif, dir, dp);
            if( status != 0 ) {
                int i;

                for( i = 0; i < nstrips && i < (int) dir->tdir_count; i++ )
                {
                    lp[i] = dp[i];
                }
            }

            _TIFFfree( (char *) dp );
	} else status = TIFFFetchLongArray(tif, dir, lp);
        
	return (status);
}


static int TIFFFetchRefBlackWhite(TIFF* tif, TIFFDirEntry* dir)
{
	static const char mesg[] = "for \"ReferenceBlackWhite\" array";
	char* cp;
	int ok;

	if (dir->tdir_type == TIFF_RATIONAL)
		return (TIFFFetchNormalTag(tif, dir));
	
	cp = (char *)_TIFFCheckMalloc(tif, dir->tdir_count, sizeof (uint32), mesg);
	if( (ok = (cp && TIFFFetchLongArray(tif, dir, (uint32*) cp))) != 0) {
		float* fp = (float*)
		    _TIFFCheckMalloc(tif, dir->tdir_count, sizeof (float), mesg);
		if( (ok = (fp != NULL)) != 0 ) {
			uint32 i;
			for (i = 0; i < dir->tdir_count; i++)
				fp[i] = (float)((uint32*) cp)[i];
			ok = TIFFSetField(tif, dir->tdir_tag, fp);
			_TIFFfree((char*) fp);
		}
	}
	if (cp)
		_TIFFfree(cp);
	return (ok);
}


static int TIFFFetchSubjectDistance(TIFF* tif, TIFFDirEntry* dir)
{
	uint32 l[2];
	float v;
	int ok = 0;

    if( dir->tdir_count != 1 || dir->tdir_type != TIFF_RATIONAL )
    {
		TIFFWarningExt(tif->tif_clientdata, tif->tif_name, "incorrect count or type for SubjectDistance, tag ignored" );
		return (0);
    }

	if (TIFFFetchData(tif, dir, (char *)l)
	    && cvtRational(tif, dir, l[0], l[1], &v)) {
		
		ok = TIFFSetField(tif, dir->tdir_tag, (l[0] != 0xFFFFFFFF) ? v : -v);
	}

	return ok;
}


static void ChopUpSingleUncompressedStrip(TIFF* tif)
{
	register TIFFDirectory *td = &tif->tif_dir;
	uint32 bytecount = td->td_stripbytecount[0];
	uint32 offset = td->td_stripoffset[0];
	tsize_t rowbytes = TIFFVTileSize(tif, 1), stripbytes;
	tstrip_t strip, nstrips, rowsperstrip;
	uint32* newcounts;
	uint32* newoffsets;

	
	if (rowbytes > STRIP_SIZE_DEFAULT) {
		stripbytes = rowbytes;
		rowsperstrip = 1;
	} else if (rowbytes > 0 ) {
		rowsperstrip = STRIP_SIZE_DEFAULT / rowbytes;
		stripbytes = rowbytes * rowsperstrip;
	}
        else return;

	
	if (rowsperstrip >= td->td_rowsperstrip)
		return;
	nstrips = (tstrip_t) TIFFhowmany(bytecount, stripbytes);
        if( nstrips == 0 ) 
            return;

	newcounts = (uint32*) _TIFFCheckMalloc(tif, nstrips, sizeof (uint32), "for chopped \"StripByteCounts\" array");
	newoffsets = (uint32*) _TIFFCheckMalloc(tif, nstrips, sizeof (uint32), "for chopped \"StripOffsets\" array");
	if (newcounts == NULL || newoffsets == NULL) {
	        
		if (newcounts != NULL)
			_TIFFfree(newcounts);
		if (newoffsets != NULL)
			_TIFFfree(newoffsets);
		return;
	}
	
	for (strip = 0; strip < nstrips; strip++) {
		if ((uint32)stripbytes > bytecount)
			stripbytes = bytecount;
		newcounts[strip] = stripbytes;
		newoffsets[strip] = offset;
		offset += stripbytes;
		bytecount -= stripbytes;
	}
	
	td->td_stripsperimage = td->td_nstrips = nstrips;
	TIFFSetField(tif, TIFFTAG_ROWSPERSTRIP, rowsperstrip);

	_TIFFfree(td->td_stripbytecount);
	_TIFFfree(td->td_stripoffset);
	td->td_stripbytecount = newcounts;
	td->td_stripoffset = newoffsets;
	td->td_stripbytecountsorted = 1;
}



