







GF_Err Media_GetSampleDesc(GF_MediaBox *mdia, u32 SampleDescIndex, GF_SampleEntryBox **out_entry, u32 *dataRefIndex)
{
	GF_SampleDescriptionBox *stsd;
	GF_SampleEntryBox *entry = NULL;

	if (!mdia) return GF_ISOM_INVALID_FILE;

	stsd = mdia->information->sampleTable->SampleDescription;
	if (!stsd) return GF_ISOM_INVALID_FILE;
	if (!SampleDescIndex || (SampleDescIndex > gf_list_count(stsd->child_boxes)) ) return GF_BAD_PARAM;

	entry = (GF_SampleEntryBox*)gf_list_get(stsd->child_boxes, SampleDescIndex - 1);
	if (!entry) return GF_ISOM_INVALID_FILE;

	if (out_entry) *out_entry = entry;
	if (dataRefIndex) *dataRefIndex = entry->dataReferenceIndex;
	return GF_OK;
}

GF_Err Media_GetSampleDescIndex(GF_MediaBox *mdia, u64 DTS, u32 *sampleDescIndex)
{
	GF_Err e;
	u32 sampleNumber, prevSampleNumber, num;
	u64 offset;
	if (sampleDescIndex == NULL) return GF_BAD_PARAM;

	
	e = stbl_findEntryForTime(mdia->information->sampleTable, (u32) DTS, 0, &sampleNumber, &prevSampleNumber);
	if (e) return e;

	if (!sampleNumber && !prevSampleNumber) {
		
		if (gf_list_count(mdia->information->sampleTable->SampleDescription->child_boxes)) {
			(*sampleDescIndex) = 1;
			return GF_OK;
		}
		return GF_BAD_PARAM;
	}
	return stbl_GetSampleInfos(mdia->information->sampleTable, ( sampleNumber ? sampleNumber : prevSampleNumber), &offset, &num, sampleDescIndex, NULL);
}

static GF_Err gf_isom_get_3gpp_audio_esd(GF_SampleTableBox *stbl, u32 type, GF_GenericAudioSampleEntryBox *entry, GF_ESD **out_esd)
{
	(*out_esd) = gf_odf_desc_esd_new(2);
	(*out_esd)->decoderConfig->streamType = GF_STREAM_AUDIO;
	
	switch (type) {
	case GF_ISOM_SUBTYPE_3GP_EVRC:
		(*out_esd)->decoderConfig->objectTypeIndication = GF_CODECID_EVRC;
		return GF_OK;
	case GF_ISOM_SUBTYPE_3GP_QCELP:
	{
		u32 block_size, sample_rate, sample_size, i;
		GF_SttsEntry *ent;
		GF_BitStream *bs;
		char szName[80];
		
		sample_size = stbl->SampleSize->sampleSize;
		(*out_esd)->decoderConfig->objectTypeIndication = GF_CODECID_QCELP;
		bs = gf_bs_new(NULL, 0, GF_BITSTREAM_WRITE);
		gf_bs_write_data(bs, "QLCMfmt ", 8);
		gf_bs_write_u32_le(bs, 150);
		gf_bs_write_u8(bs, 1);
		gf_bs_write_u8(bs, 0);
		
		gf_bs_write_data(bs, "\x41\x6D\x7F\x5E\x15\xB1\xD0\x11\xBA\x91\x00\x80\x5F\xB4\xB9\x7E", 16);
		gf_bs_write_u16_le(bs, 1);
		memset(szName, 0, 80);
		strcpy(szName, "QCELP-13K(GPAC-emulated)");
		gf_bs_write_data(bs, szName, 80);
		ent = &stbl->TimeToSample->entries[0];
		sample_rate = entry->samplerate_hi;
		block_size = ent ? ent->sampleDelta : 160;
		gf_bs_write_u16_le(bs, 8*sample_size*sample_rate/block_size);
		gf_bs_write_u16_le(bs, sample_size);
		gf_bs_write_u16_le(bs, block_size);
		gf_bs_write_u16_le(bs, sample_rate);
		gf_bs_write_u16_le(bs, entry->bitspersample);
		gf_bs_write_u32_le(bs, sample_size ? 0 : 7);
		
		for (i=0; i<7; i++) {
			static const u32 qcelp_r2s [] = {0, 1, 1, 4, 2, 8, 3, 17, 4, 35, 5, 8, 14, 1};
			if (sample_size) {
				gf_bs_write_u16(bs, 0);
			} else {
				gf_bs_write_u8(bs, qcelp_r2s[2*i+1]);
				gf_bs_write_u8(bs, qcelp_r2s[2*i]);
			}
		}
		gf_bs_write_u16(bs, 0);
		memset(szName, 0, 80);
		gf_bs_write_data(bs, szName, 20);
		gf_bs_get_content(bs, & (*out_esd)->decoderConfig->decoderSpecificInfo->data, & (*out_esd)->decoderConfig->decoderSpecificInfo->dataLength);
		gf_bs_del(bs);
	}
	return GF_OK;
	case GF_ISOM_SUBTYPE_3GP_SMV:
		(*out_esd)->decoderConfig->objectTypeIndication = GF_CODECID_SMV;
		return GF_OK;
	case GF_ISOM_SUBTYPE_3GP_AMR:
		(*out_esd)->decoderConfig->objectTypeIndication = GF_CODECID_AMR;
		return GF_OK;
	case GF_ISOM_SUBTYPE_3GP_AMR_WB:
		(*out_esd)->decoderConfig->objectTypeIndication = GF_CODECID_AMR_WB;
		return GF_OK;
	default:
		GF_LOG(GF_LOG_WARNING, GF_LOG_CONTAINER, ("[iso file] unsupported sample description type %s\n", gf_4cc_to_str(entry->type)));
		break;
	}
	return GF_OK;
}

GF_Err Media_GetESD(GF_MediaBox *mdia, u32 sampleDescIndex, GF_ESD **out_esd, Bool true_desc_only)
{
	u32 type;
	GF_ESD *esd;
	GF_MPEGSampleEntryBox *entry = NULL;
	GF_ESDBox *ESDa;
	GF_ProtectionSchemeInfoBox *sinf;
	GF_SampleDescriptionBox *stsd = mdia->information->sampleTable->SampleDescription;

	*out_esd = NULL;
	if (!stsd || !stsd->child_boxes || !sampleDescIndex || (sampleDescIndex > gf_list_count(stsd->child_boxes)) )
		return GF_BAD_PARAM;

	esd = NULL;
	entry = (GF_MPEGSampleEntryBox*)gf_list_get(stsd->child_boxes, sampleDescIndex - 1);
	if (! entry) return GF_ISOM_INVALID_MEDIA;

	*out_esd = NULL;
	ESDa = NULL;
	type = entry->type;
	switch (type) {
	case GF_ISOM_BOX_TYPE_ENCV:
	case GF_ISOM_BOX_TYPE_ENCA:
	case GF_ISOM_BOX_TYPE_ENCS:
	case GF_ISOM_BOX_TYPE_ENCF:
	case GF_ISOM_BOX_TYPE_ENCM:
	case GF_ISOM_BOX_TYPE_ENCT:
		sinf = (GF_ProtectionSchemeInfoBox *) gf_isom_box_find_child(entry->child_boxes, GF_ISOM_BOX_TYPE_SINF);
		if (sinf && sinf->original_format) {
			type = sinf->original_format->data_format;
		}
		break;
	case GF_ISOM_BOX_TYPE_RESV:
		sinf = (GF_ProtectionSchemeInfoBox *) gf_isom_box_find_child(entry->child_boxes, GF_ISOM_BOX_TYPE_RINF);
		if (sinf && sinf->original_format) {
			type = sinf->original_format->data_format;
		}
		break;
	}

	switch (type) {
	case GF_ISOM_BOX_TYPE_MP4V:
		ESDa = ((GF_MPEGVisualSampleEntryBox*)entry)->esd;
		if (ESDa) esd = (GF_ESD *) ESDa->desc;
		
		else esd = ((GF_MPEGVisualSampleEntryBox*) entry)->emul_esd;
		break;
	case GF_ISOM_BOX_TYPE_AVC1:
	case GF_ISOM_BOX_TYPE_AVC2:
	case GF_ISOM_BOX_TYPE_AVC3:
	case GF_ISOM_BOX_TYPE_AVC4:
	case GF_ISOM_BOX_TYPE_HVC1:
	case GF_ISOM_BOX_TYPE_HEV1:
	case GF_ISOM_BOX_TYPE_HVC2:
	case GF_ISOM_BOX_TYPE_HEV2:
	case GF_ISOM_BOX_TYPE_HVT1:
	case GF_ISOM_BOX_TYPE_264B:
	case GF_ISOM_BOX_TYPE_265B:
	case GF_ISOM_BOX_TYPE_DVHE:
	case GF_ISOM_BOX_TYPE_VVC1:
	case GF_ISOM_BOX_TYPE_VVI1:
		esd = ((GF_MPEGVisualSampleEntryBox*) entry)->emul_esd;
		break;
	case GF_ISOM_BOX_TYPE_SVC1:
	case GF_ISOM_BOX_TYPE_MVC1:
		if ((mdia->mediaTrack->extractor_mode & 0x0000FFFF) != GF_ISOM_NALU_EXTRACT_INSPECT)
			AVC_RewriteESDescriptorEx((GF_MPEGVisualSampleEntryBox*) entry, mdia);
		else AVC_RewriteESDescriptorEx((GF_MPEGVisualSampleEntryBox*) entry, NULL);
		esd = ((GF_MPEGVisualSampleEntryBox*) entry)->emul_esd;
		break;
	case GF_ISOM_BOX_TYPE_LHE1:
	case GF_ISOM_BOX_TYPE_LHV1:
		if ((mdia->mediaTrack->extractor_mode & 0x0000FFFF) != GF_ISOM_NALU_EXTRACT_INSPECT)
			HEVC_RewriteESDescriptorEx((GF_MPEGVisualSampleEntryBox*) entry, mdia);
		else HEVC_RewriteESDescriptorEx((GF_MPEGVisualSampleEntryBox*) entry, NULL);
		esd = ((GF_MPEGVisualSampleEntryBox*) entry)->emul_esd;
		break;
	case GF_ISOM_BOX_TYPE_AV01:
		AV1_RewriteESDescriptorEx((GF_MPEGVisualSampleEntryBox*)entry, mdia);
		esd = ((GF_MPEGVisualSampleEntryBox*)entry)->emul_esd;
		break;
	case GF_ISOM_BOX_TYPE_VP08:
	case GF_ISOM_BOX_TYPE_VP09:
		VP9_RewriteESDescriptorEx((GF_MPEGVisualSampleEntryBox*)entry, mdia);
		esd = ((GF_MPEGVisualSampleEntryBox*)entry)->emul_esd;
		break;
	case GF_ISOM_BOX_TYPE_MP4A:
        {
            GF_MPEGAudioSampleEntryBox *ase = (GF_MPEGAudioSampleEntryBox*)entry;
            ESDa = ase->esd;
            if (ESDa) {
				esd = (GF_ESD *) ESDa->desc;
            } else if (!true_desc_only) {
				Bool make_mp4a = GF_FALSE;
				sinf = (GF_ProtectionSchemeInfoBox *) gf_isom_box_find_child(entry->child_boxes, GF_ISOM_BOX_TYPE_SINF);

				if (sinf && sinf->original_format) {
					if (sinf->original_format->data_format==GF_ISOM_BOX_TYPE_MP4A) {
						make_mp4a = GF_TRUE;
					}
				} else {
					
					make_mp4a = GF_TRUE;
				}
				if (make_mp4a) {
					GF_M4ADecSpecInfo aacinfo;
					memset(&aacinfo, 0, sizeof(GF_M4ADecSpecInfo));
					aacinfo.nb_chan = ase->channel_count;
					aacinfo.base_object_type = GF_M4A_AAC_LC;
					aacinfo.base_sr = ase->samplerate_hi;
					*out_esd = gf_odf_desc_esd_new(0);
					(*out_esd)->decoderConfig->streamType = GF_STREAM_AUDIO;
					(*out_esd)->decoderConfig->objectTypeIndication = GF_CODECID_AAC_MPEG4;
					gf_m4a_write_config(&aacinfo, &(*out_esd)->decoderConfig->decoderSpecificInfo->data, &(*out_esd)->decoderConfig->decoderSpecificInfo->dataLength);
				}
            }
        }
		break;
	case GF_ISOM_BOX_TYPE_MP4S:
		if (entry->internal_type==GF_ISOM_SAMPLE_ENTRY_MP4S) {
			ESDa = entry->esd;
			if (ESDa) esd = (GF_ESD *) ESDa->desc;
		}
		break;

	case GF_ISOM_BOX_TYPE_TX3G:
	case GF_ISOM_BOX_TYPE_TEXT:
		if (!true_desc_only && mdia->mediaTrack->moov->mov->convert_streaming_text) {
			GF_Err e = gf_isom_get_ttxt_esd(mdia, out_esd);
			if (e) return e;
			break;
		}
		else return GF_ISOM_INVALID_MEDIA;


	case GF_ISOM_BOX_TYPE_WVTT:
	{
		GF_WebVTTSampleEntryBox*vtte = (GF_WebVTTSampleEntryBox*)entry;
		esd =  gf_odf_desc_esd_new(2);
		*out_esd = esd;
		esd->decoderConfig->streamType = GF_STREAM_TEXT;
		esd->decoderConfig->objectTypeIndication = GF_CODECID_WEBVTT;
		if (vtte->config) {
			esd->decoderConfig->decoderSpecificInfo->dataLength = (u32) strlen(vtte->config->string);
			esd->decoderConfig->decoderSpecificInfo->data = gf_malloc(sizeof(char)*esd->decoderConfig->decoderSpecificInfo->dataLength);
			memcpy(esd->decoderConfig->decoderSpecificInfo->data, vtte->config->string, esd->decoderConfig->decoderSpecificInfo->dataLength);
		}
	}
		break;
	case GF_ISOM_BOX_TYPE_STPP:
	case GF_ISOM_BOX_TYPE_SBTT:
	case GF_ISOM_BOX_TYPE_STXT:
		break;


	case GF_ISOM_SUBTYPE_3GP_AMR:
	case GF_ISOM_SUBTYPE_3GP_AMR_WB:
	case GF_ISOM_SUBTYPE_3GP_EVRC:
	case GF_ISOM_SUBTYPE_3GP_QCELP:
	case GF_ISOM_SUBTYPE_3GP_SMV:
		if (!true_desc_only) {
			GF_Err e = gf_isom_get_3gpp_audio_esd(mdia->information->sampleTable, type, (GF_GenericAudioSampleEntryBox*)entry, out_esd);
			if (e) return e;
			break;
		} else return GF_ISOM_INVALID_MEDIA;

	case GF_ISOM_SUBTYPE_OPUS: {
		GF_OpusSpecificBox *e = ((GF_MPEGAudioSampleEntryBox*)entry)->cfg_opus;
		GF_BitStream *bs_out;
		if (!e) {
			GF_LOG(GF_LOG_WARNING, GF_LOG_CONTAINER, ("ESD not found for Opus\n)"));
			break;
		}

		*out_esd = gf_odf_desc_esd_new(2);
		(*out_esd)->decoderConfig->streamType = GF_STREAM_AUDIO;
		(*out_esd)->decoderConfig->objectTypeIndication = GF_CODECID_OPUS;

		
		bs_out = gf_bs_new(NULL, 0, GF_BITSTREAM_WRITE);
		gf_isom_box_size((GF_Box *) e);
		gf_isom_box_write((GF_Box *) e, bs_out);
		gf_bs_get_content(bs_out, & (*out_esd)->decoderConfig->decoderSpecificInfo->data, & (*out_esd)->decoderConfig->decoderSpecificInfo->dataLength);
		gf_bs_del(bs_out);
		break;
	}
	case GF_ISOM_SUBTYPE_3GP_H263:
		if (true_desc_only) {
			return GF_ISOM_INVALID_MEDIA;
		} else {
			esd =  gf_odf_desc_esd_new(2);
			*out_esd = esd;
			esd->decoderConfig->streamType = GF_STREAM_VISUAL;
			esd->decoderConfig->objectTypeIndication = GF_CODECID_H263;
			break;
		}

	case GF_ISOM_SUBTYPE_MP3:
		if (true_desc_only) {
			return GF_ISOM_INVALID_MEDIA;
		} else {
			esd =  gf_odf_desc_esd_new(2);
			*out_esd = esd;
			esd->decoderConfig->streamType = GF_STREAM_AUDIO;
			esd->decoderConfig->objectTypeIndication = GF_CODECID_MPEG_AUDIO;
			break;
		}

	case GF_ISOM_SUBTYPE_LSR1:
		if (true_desc_only) {
			return GF_ISOM_INVALID_MEDIA;
		} else {
			GF_LASeRSampleEntryBox*ptr = (GF_LASeRSampleEntryBox*)entry;
			esd =  gf_odf_desc_esd_new(2);
			*out_esd = esd;
			esd->decoderConfig->streamType = GF_STREAM_SCENE;
			esd->decoderConfig->objectTypeIndication = GF_CODECID_LASER;
			esd->decoderConfig->decoderSpecificInfo->dataLength = ptr->lsr_config->hdr_size;
			esd->decoderConfig->decoderSpecificInfo->data = gf_malloc(sizeof(char)*ptr->lsr_config->hdr_size);
			if (!esd->decoderConfig->decoderSpecificInfo->data) return GF_OUT_OF_MEM;
			memcpy(esd->decoderConfig->decoderSpecificInfo->data, ptr->lsr_config->hdr, sizeof(char)*ptr->lsr_config->hdr_size);
			break;
		}
	case GF_ISOM_SUBTYPE_MH3D_MHA1:
	case GF_ISOM_SUBTYPE_MH3D_MHA2:
	case GF_ISOM_SUBTYPE_MH3D_MHM1:
	case GF_ISOM_SUBTYPE_MH3D_MHM2:
		if (true_desc_only) {
			return GF_ISOM_INVALID_MEDIA;
		} else {
			GF_MPEGAudioSampleEntryBox*ptr = (GF_MPEGAudioSampleEntryBox*)entry;
			esd = gf_odf_desc_esd_new(2);
			*out_esd = esd;
			esd->decoderConfig->streamType = GF_STREAM_AUDIO;
			if ((type==GF_ISOM_SUBTYPE_MH3D_MHA1) || (type==GF_ISOM_SUBTYPE_MH3D_MHA2))
				esd->decoderConfig->objectTypeIndication = GF_CODECID_MPHA;
			else esd->decoderConfig->objectTypeIndication = GF_CODECID_MHAS;
			if (ptr->cfg_mha) {
				GF_BitStream *bs = gf_bs_new(NULL, 0, GF_BITSTREAM_WRITE);

				gf_bs_write_u8(bs, ptr->cfg_mha->configuration_version);
				gf_bs_write_u8(bs, ptr->cfg_mha->mha_pl_indication);
				gf_bs_write_u8(bs, ptr->cfg_mha->reference_channel_layout);
				gf_bs_write_u16(bs, ptr->cfg_mha->mha_config ? ptr->cfg_mha->mha_config_size : 0);
				if (ptr->cfg_mha->mha_config && ptr->cfg_mha->mha_config_size)
					gf_bs_write_data(bs, ptr->cfg_mha->mha_config, ptr->cfg_mha->mha_config_size);

				gf_bs_get_content(bs, &esd->decoderConfig->decoderSpecificInfo->data, &esd->decoderConfig->decoderSpecificInfo->dataLength);
				gf_bs_del(bs);
			}
		}
		break;

	default:
		return GF_ISOM_INVALID_MEDIA;
	}

	if (true_desc_only) {
		if (!esd) return GF_ISOM_INVALID_MEDIA;
		*out_esd = esd;
		return GF_OK;
	} else {
		if (!esd && !*out_esd) return GF_ISOM_INVALID_MEDIA;
		if (*out_esd == NULL) return gf_odf_desc_copy((GF_Descriptor *)esd, (GF_Descriptor **)out_esd);
	}
	return GF_OK;
}

Bool Media_IsSampleSyncShadow(GF_ShadowSyncBox *stsh, u32 sampleNumber)
{
	u32 i;
	GF_StshEntry *ent;
	if (!stsh) return 0;
	i=0;
	while ((ent = (GF_StshEntry*)gf_list_enum(stsh->entries, &i))) {
		if ((u32) ent->syncSampleNumber == sampleNumber) return 1;
		else if ((u32) ent->syncSampleNumber > sampleNumber) return 0;
	}
	return 0;
}

GF_Err Media_GetSample(GF_MediaBox *mdia, u32 sampleNumber, GF_ISOSample **samp, u32 *sIDX, Bool no_data, u64 *out_offset)
{
	GF_Err e;
	u32 bytesRead;
	u32 dataRefIndex, chunkNumber;
	u64 offset, new_size;
	u32 sdesc_idx;
	GF_SampleEntryBox *entry;
	GF_StscEntry *stsc_entry;

	if (!mdia || !mdia->information->sampleTable) return GF_BAD_PARAM;
	if (!mdia->information->sampleTable->SampleSize)
		return GF_ISOM_INVALID_FILE;

	
	if (sampleNumber > mdia->information->sampleTable->SampleSize->sampleCount) return GF_BAD_PARAM;

	
	if (!sIDX && !no_data) return GF_BAD_PARAM;

	e = stbl_GetSampleInfos(mdia->information->sampleTable, sampleNumber, &offset, &chunkNumber, &sdesc_idx, &stsc_entry);
	if (e) return e;
	if (sIDX) (*sIDX) = sdesc_idx;

	if (out_offset) *out_offset = offset;
	if (!samp ) return GF_OK;

	if (mdia->information->sampleTable->TimeToSample) {
		
		e = stbl_GetSampleDTS(mdia->information->sampleTable->TimeToSample, sampleNumber, &(*samp)->DTS);
		if (e) return e;
	} else {
		(*samp)->DTS=0;
	}
	
	if (mdia->information->sampleTable->CompositionOffset) {
		e = stbl_GetSampleCTS(mdia->information->sampleTable->CompositionOffset , sampleNumber, &(*samp)->CTS_Offset);
		if (e) return e;
	} else {
		(*samp)->CTS_Offset = 0;
	}
	
	e = stbl_GetSampleSize(mdia->information->sampleTable->SampleSize, sampleNumber, &(*samp)->dataLength);
	if (e) return e;
	
	if (mdia->information->sampleTable->SyncSample) {
		e = stbl_GetSampleRAP(mdia->information->sampleTable->SyncSample, sampleNumber, &(*samp)->IsRAP, NULL, NULL);
		if (e) return e;
	} else {
		
		(*samp)->IsRAP = RAP;
	}

	if (mdia->information->sampleTable->SampleDep) {
		u32 isLeading, dependsOn, dependedOn, redundant;
		e = stbl_GetSampleDepType(mdia->information->sampleTable->SampleDep, sampleNumber, &isLeading, &dependsOn, &dependedOn, &redundant);
		if (!e) {
			if (dependsOn==1) (*samp)->IsRAP = RAP_NO;
			
			
			

			
			if ((dependedOn==2) && (redundant==1)) (*samp)->IsRAP = RAP_REDUNDANT;
			
		}
	}

	
	if (Media_IsSampleSyncShadow(mdia->information->sampleTable->ShadowSync, sampleNumber)) (*samp)->IsRAP = RAP_REDUNDANT;

	
	if (!sIDX && !no_data) return GF_BAD_PARAM;
	if (!sIDX && !out_offset) return GF_OK;
	if (!sIDX) return GF_OK;

	(*sIDX) = sdesc_idx;



	
	e = Media_GetSampleDesc(mdia, sdesc_idx, &entry, &dataRefIndex);
	if (e) return e;

	
	if (mdia->mediaTrack->moov->compressed_diff) {
		GF_DataEntryBox *ent = (GF_DataEntryBox*)gf_list_get(mdia->information->dataInformation->dref->child_boxes, dataRefIndex - 1);
		if (ent && (ent->flags&1) && (offset>=mdia->mediaTrack->moov->file_offset)) {
			offset -= mdia->mediaTrack->moov->compressed_diff;
		}
	}


	if (no_data) return GF_OK;

	
	
	
	if (mdia->mediaTrack->moov->mov->openMode == GF_ISOM_OPEN_READ) {
		
		if (!mdia->information->dataHandler) {
			e = gf_isom_datamap_open(mdia, dataRefIndex, stsc_entry->isEdited);
			if (e) return e;
		}
		mdia->information->dataEntryIndex = dataRefIndex;
	} else {
		e = gf_isom_datamap_open(mdia, dataRefIndex, stsc_entry->isEdited);
		if (e) return e;
	}

	if ( mdia->mediaTrack->moov->mov->read_byte_offset || mdia->mediaTrack->moov->mov->bytes_removed) {
		GF_DataEntryBox *ent = (GF_DataEntryBox*)gf_list_get(mdia->information->dataInformation->dref->child_boxes, dataRefIndex - 1);
		if (ent && (ent->flags&1)) {
			u64 real_offset = mdia->mediaTrack->moov->mov->read_byte_offset + mdia->mediaTrack->moov->mov->bytes_removed;
			if (offset < real_offset)
				return GF_IO_ERR;

			if (mdia->information->dataHandler->last_read_offset != mdia->mediaTrack->moov->mov->read_byte_offset) {
				mdia->information->dataHandler->last_read_offset = mdia->mediaTrack->moov->mov->read_byte_offset;
				gf_bs_get_refreshed_size(mdia->information->dataHandler->bs);
			}

			offset -= real_offset;
		}
	}
	if ((*samp)->dataLength != 0) {
		if (mdia->mediaTrack->pack_num_samples) {
			u32 idx_in_chunk = sampleNumber - mdia->information->sampleTable->SampleToChunk->firstSampleInCurrentChunk;
			u32 left_in_chunk = stsc_entry->samplesPerChunk - idx_in_chunk;
			if (left_in_chunk > mdia->mediaTrack->pack_num_samples)
				left_in_chunk = mdia->mediaTrack->pack_num_samples;
			(*samp)->dataLength *= left_in_chunk;
			(*samp)->nb_pack = left_in_chunk;
		}

		
		if ((*samp)->alloc_size) {
			if ((*samp)->alloc_size < (*samp)->dataLength + mdia->mediaTrack->padding_bytes) {
				(*samp)->data = (char *) gf_realloc((*samp)->data, sizeof(char) * ( (*samp)->dataLength + mdia->mediaTrack->padding_bytes) );
				if (! (*samp)->data) return GF_OUT_OF_MEM;

				(*samp)->alloc_size = (*samp)->dataLength + mdia->mediaTrack->padding_bytes;
			}
		} else {
			(*samp)->data = (char *) gf_malloc(sizeof(char) * ( (*samp)->dataLength + mdia->mediaTrack->padding_bytes) );
			if (! (*samp)->data) return GF_OUT_OF_MEM;
		}
		if (mdia->mediaTrack->padding_bytes)
			memset((*samp)->data + (*samp)->dataLength, 0, sizeof(char) * mdia->mediaTrack->padding_bytes);

		
		new_size = gf_bs_get_size(mdia->information->dataHandler->bs);
		if (offset + (*samp)->dataLength > new_size) {
			
			new_size = gf_bs_get_refreshed_size(mdia->information->dataHandler->bs);
			if (offset + (*samp)->dataLength > new_size) {
				mdia->BytesMissing = offset + (*samp)->dataLength - new_size;
				return GF_ISOM_INCOMPLETE_FILE;
			}
		}

		bytesRead = gf_isom_datamap_get_data(mdia->information->dataHandler, (*samp)->data, (*samp)->dataLength, offset);
		
		if (bytesRead < (*samp)->dataLength) {
			return GF_IO_ERR;
		}
		mdia->BytesMissing = 0;
	}

	
	
	if (mdia->handler->handlerType == GF_ISOM_MEDIA_OD) {
		if (!mdia->mediaTrack->moov->mov->disable_odf_translate) {
			e = Media_RewriteODFrame(mdia, *samp);
			if (e) return e;
		}
	}
	else if (gf_isom_is_nalu_based_entry(mdia, entry)
		&& !gf_isom_is_encrypted_entry(entry->type)
	) {
		e = gf_isom_nalu_sample_rewrite(mdia, *samp, sampleNumber, (GF_MPEGVisualSampleEntryBox *)entry);
		if (e) return e;
	}
	else if (mdia->mediaTrack->moov->mov->convert_streaming_text && ((mdia->handler->handlerType == GF_ISOM_MEDIA_TEXT) || (mdia->handler->handlerType == GF_ISOM_MEDIA_SCENE) || (mdia->handler->handlerType == GF_ISOM_MEDIA_SUBT))
	         && (entry->type == GF_ISOM_BOX_TYPE_TX3G || entry->type == GF_ISOM_BOX_TYPE_TEXT)
	        ) {
		u64 dur;
		if (sampleNumber == mdia->information->sampleTable->SampleSize->sampleCount) {
			dur = mdia->mediaHeader->duration - (*samp)->DTS;
		} else {
			stbl_GetSampleDTS(mdia->information->sampleTable->TimeToSample, sampleNumber+1, &dur);
			dur -= (*samp)->DTS;
		}
		e = gf_isom_rewrite_text_sample(*samp, sdesc_idx, (u32) dur);
		if (e) return e;
	}
	return GF_OK;
}



GF_Err Media_CheckDataEntry(GF_MediaBox *mdia, u32 dataEntryIndex)
{

	GF_DataEntryURLBox *entry;
	GF_DataMap *map;
	GF_Err e;
	if (!mdia || !dataEntryIndex || dataEntryIndex > gf_list_count(mdia->information->dataInformation->dref->child_boxes)) return GF_BAD_PARAM;

	entry = (GF_DataEntryURLBox*)gf_list_get(mdia->information->dataInformation->dref->child_boxes, dataEntryIndex - 1);
	if (!entry) return GF_ISOM_INVALID_FILE;
	if (entry->flags == 1) return GF_OK;

	
	
	if (entry->type == GF_ISOM_BOX_TYPE_URN) return GF_NOT_SUPPORTED;
	if (mdia->mediaTrack->moov->mov->openMode == GF_ISOM_OPEN_WRITE) {
		e = gf_isom_datamap_new(entry->location, NULL, GF_ISOM_DATA_MAP_READ, &map);
	} else {
		e = gf_isom_datamap_new(entry->location, mdia->mediaTrack->moov->mov->fileName, GF_ISOM_DATA_MAP_READ, &map);
	}
	if (e) return e;
	gf_isom_datamap_del(map);
	return GF_OK;
}


Bool Media_IsSelfContained(GF_MediaBox *mdia, u32 StreamDescIndex)
{
	u32 drefIndex=0;
	GF_FullBox *a=NULL;
	GF_SampleEntryBox *se = NULL;

	Media_GetSampleDesc(mdia, StreamDescIndex, &se, &drefIndex);
	if (!drefIndex) return 0;
	if (mdia && mdia->information && mdia->information->dataInformation && mdia->information->dataInformation->dref ) {



		a = (GF_FullBox*)gf_list_get(mdia->information->dataInformation->dref->child_boxes, drefIndex - 1);
	}
	if (!a) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_CONTAINER, ("[iso file] broken file: Data reference index set to %d but no data reference entry found\n", drefIndex));
		return 1;
	}
	if (a->flags & 1) return 1;
	
	if (a->type == GF_QT_BOX_TYPE_ALIS) return 1;
	return 0;
}

GF_ISOMDataRefAllType Media_SelfContainedType(GF_MediaBox *mdia)
{
	u32 nb_ext, nb_self;
	u32 i, count;

	nb_ext = nb_self = 0;
	count = mdia->information->sampleTable->SampleDescription ? gf_list_count(mdia->information->sampleTable->SampleDescription->child_boxes) : 0;
	for (i=0; i<count; i++) {
		if (Media_IsSelfContained(mdia, i+1)) nb_self++;
		else nb_ext++;
	}
	if (nb_ext==count) return ISOM_DREF_EXT;
	if (nb_self==count) return ISOM_DREF_SELF;
	return ISOM_DREF_MIXED;
}




GF_Err Media_FindSyncSample(GF_SampleTableBox *stbl, u32 searchFromSample, u32 *sampleNumber, u8 mode)
{
	GF_ISOSAPType isRAP;
	u32 next, prev, next_in_sap, prev_in_sap;
	if (!stbl || !stbl->SyncSample) return GF_BAD_PARAM;

	
	*sampleNumber = searchFromSample;

	
	if ( (mode == GF_ISOM_SEARCH_SYNC_FORWARD) && (searchFromSample == stbl->SampleSize->sampleCount) ) {
		return GF_OK;
	}
	if ( (mode == GF_ISOM_SEARCH_SYNC_BACKWARD) && !searchFromSample) {
		*sampleNumber = 1;
		return GF_OK;
	}
	
	stbl_GetSampleRAP(stbl->SyncSample, searchFromSample, &isRAP, &prev, &next);
	if (isRAP) {
		(*sampleNumber) = searchFromSample;
		return GF_OK;
	}

	
	stbl_SearchSAPs(stbl, searchFromSample, &isRAP, &prev_in_sap, &next_in_sap);
	if (isRAP) {
		(*sampleNumber) = searchFromSample;
		return GF_OK;
	}

	if (prev_in_sap > prev)
		prev = prev_in_sap;
	if (next_in_sap && next_in_sap < next)
		next = next_in_sap;

	
	if (mode == GF_ISOM_SEARCH_SYNC_FORWARD) {
		if (next) *sampleNumber = next;
	} else {
		if (prev) *sampleNumber = prev;
	}

	return GF_OK;
}


GF_Err Media_FindDataRef(GF_DataReferenceBox *dref, char *URLname, char *URNname, u32 *dataRefIndex)
{
	u32 i;
	GF_DataEntryURLBox *entry;

	if (!dref) return GF_BAD_PARAM;
	*dataRefIndex = 0;
	i=0;
	while ((entry = (GF_DataEntryURLBox*)gf_list_enum(dref->child_boxes, &i))) {
		if (entry->type == GF_ISOM_BOX_TYPE_URL) {
			
			if (entry->flags == 1) {
				
				if (!URLname && !URNname) {
					*dataRefIndex = i;
					return GF_OK;
				}
			} else {
				
				if (URLname && !strcmp(URLname, entry->location)) {
					*dataRefIndex = i;
					return GF_OK;
				}
			}
		} else {
			
			if (URNname && !strcmp(URNname, ((GF_DataEntryURNBox *)entry)->nameURN)) {
				*dataRefIndex = i;
				return GF_OK;
			}
		}
	}
	return GF_OK;
}


GF_Err Media_SetDuration(GF_TrackBox *trak)
{
	GF_Err e;
	GF_ESD *esd;
	u64 DTS;
	GF_SttsEntry *ent;
	u32 nbSamp;

	if (!trak || !trak->Media || !trak->Media->information || !trak->Media->information->sampleTable)
		return GF_ISOM_INVALID_FILE;

	if (!trak->Media->information->sampleTable->SampleSize || !trak->Media->information->sampleTable->TimeToSample)
		return GF_ISOM_INVALID_FILE;

	nbSamp = trak->Media->information->sampleTable->SampleSize->sampleCount;

	
	
	
	switch (nbSamp) {
	case 0:
		trak->Media->mediaHeader->duration = 0;
		if (Track_IsMPEG4Stream(trak->Media->handler->handlerType)) {
			Media_GetESD(trak->Media, 1, &esd, 1);
			if (esd && esd->URLString) trak->Media->mediaHeader->duration = (u64) -1;

		}
		return GF_OK;





	default:
		
		
		e = stbl_GetSampleDTS(trak->Media->information->sampleTable->TimeToSample, nbSamp, &DTS);
		if (e < 0) {
			return e;
		}
		if (trak->Media->information->sampleTable->TimeToSample->nb_entries > 0) {
			ent = &trak->Media->information->sampleTable->TimeToSample->entries[trak->Media->information->sampleTable->TimeToSample->nb_entries-1];
		} else {
			ent = NULL;
		}
		trak->Media->mediaHeader->duration = DTS;



		if (ent) trak->Media->mediaHeader->duration += ent->sampleDelta;

		if (!ent) {
			u64 DTSprev;
			stbl_GetSampleDTS(trak->Media->information->sampleTable->TimeToSample, nbSamp-1, &DTSprev);
			trak->Media->mediaHeader->duration += (DTS - DTSprev);
		} else {

			if (trak->moov->mov->editFileMap && trak->Media->information->sampleTable->CompositionOffset) {
				u32 count, i;
				u64 max_ts;
				GF_DttsEntry *cts_ent;
				GF_CompositionOffsetBox *ctts = trak->Media->information->sampleTable->CompositionOffset;
				if (ctts->w_LastSampleNumber==nbSamp) {
					count = gf_list_count(ctts->entryList);
					max_ts = trak->Media->mediaHeader->duration;
					while (count) {
						count -= 1;
						cts_ent = gf_list_get(ctts->entryList, count);
						if (nbSamp<cts_ent->sampleCount) break;

						for (i=0; i<cts_ent->sampleCount; i++) {
							stbl_GetSampleDTS(trak->Media->information->sampleTable->TimeToSample, nbSamp-i, &DTS);
							if ((s32) cts_ent->decodingOffset < 0) max_ts = DTS;
							else max_ts = DTS + cts_ent->decodingOffset;
							if (max_ts>=trak->Media->mediaHeader->duration) {
								trak->Media->mediaHeader->duration = max_ts;
							} else {
								break;
							}
						}
						if (max_ts<trak->Media->mediaHeader->duration) {
							break;
						}
						nbSamp-=cts_ent->sampleCount;
					}
				}
			}

			trak->Media->mediaHeader->duration += ent->sampleDelta;
		}

		return GF_OK;
	}
}






GF_Err Media_SetDrefURL(GF_DataEntryURLBox *dref_entry, const char *origName, const char *finalName)
{
	
	if (strstr(origName, "://") || ((origName[1]==':') && (origName[2]=='\\'))
		|| (origName[0]=='/') || (origName[0]=='\\')
	) {
		dref_entry->location = gf_strdup(origName);
	} else {
		char *fname = strrchr(origName, '/');
		if (!fname) fname = strrchr(origName, '\\');
		if (fname) fname++;

		if (!fname) {
			dref_entry->location = gf_strdup(origName);
		} else {
			u32 len = (u32) (fname - origName);
			if (!finalName || strncmp(origName, finalName, len)) {
				GF_LOG(GF_LOG_ERROR, GF_LOG_CONTAINER, ("Concatenation of relative path %s with relative path %s not supported, use absolute URLs\n", origName, finalName));
				return GF_NOT_SUPPORTED;
			} else {
				dref_entry->location = gf_strdup(fname);
			}
		}
	}
	return GF_OK;
}


GF_Err Media_CreateDataRef(GF_ISOFile *movie, GF_DataReferenceBox *dref, char *URLname, char *URNname, u32 *dataRefIndex)
{
	GF_Err e;
	Bool use_alis=GF_FALSE;
	GF_DataEntryURLBox *entry;

	if (URLname && !strcmp(URLname, "alis")) {
		URLname = NULL;
		use_alis=GF_TRUE;
	}

	if (!URLname && !URNname) {
		
		entry = (GF_DataEntryURLBox *) gf_isom_box_new_parent(&dref->child_boxes, use_alis ? GF_QT_BOX_TYPE_ALIS : GF_ISOM_BOX_TYPE_URL);
		if (!entry) return GF_OUT_OF_MEM;
		entry->flags = 1;
		*dataRefIndex = gf_list_count(dref->child_boxes);
		return GF_OK;
	} else if (!URNname && URLname) {
		
		entry = (GF_DataEntryURLBox *) gf_isom_box_new_parent(&dref->child_boxes, GF_ISOM_BOX_TYPE_URL);
		if (!entry) return GF_OUT_OF_MEM;
		entry->flags = 0;

		e = Media_SetDrefURL(entry, URLname, movie->fileName ? movie->fileName : movie->finalName);
		if (! entry->location) {
			gf_isom_box_del_parent(&dref->child_boxes, (GF_Box *)entry);
			return e ? e : GF_OUT_OF_MEM;
		}
		*dataRefIndex = gf_list_count(dref->child_boxes);
		return GF_OK;
	} else {
		
		entry = (GF_DataEntryURLBox *) gf_isom_box_new_parent(&dref->child_boxes, GF_ISOM_BOX_TYPE_URN);
		if (!entry) return GF_OUT_OF_MEM;
		((GF_DataEntryURNBox *)entry)->flags = 0;
		((GF_DataEntryURNBox *)entry)->nameURN = (char*)gf_malloc(strlen(URNname)+1);
		if (! ((GF_DataEntryURNBox *)entry)->nameURN) {
			gf_isom_box_del_parent(&dref->child_boxes, (GF_Box *)entry);
			return GF_OUT_OF_MEM;
		}
		strcpy(((GF_DataEntryURNBox *)entry)->nameURN, URNname);
		
		if (URLname) {
			((GF_DataEntryURNBox *)entry)->location = (char*)gf_malloc(strlen(URLname)+1);
			if (! ((GF_DataEntryURNBox *)entry)->location) {
				gf_isom_box_del_parent(&dref->child_boxes, (GF_Box *)entry);
				return GF_OUT_OF_MEM;
			}
			strcpy(((GF_DataEntryURNBox *)entry)->location, URLname);
		}
		*dataRefIndex = gf_list_count(dref->child_boxes);
		return GF_OK;
	}
	return GF_OK;
}


GF_Err Media_AddSample(GF_MediaBox *mdia, u64 data_offset, const GF_ISOSample *sample, u32 StreamDescIndex, u32 syncShadowNumber)
{
	GF_Err e;
	GF_SampleTableBox *stbl;
	u32 sampleNumber, i;
	if (!mdia || !sample) return GF_BAD_PARAM;

	stbl = mdia->information->sampleTable;

	
	e = stbl_AddDTS(stbl, sample->DTS, &sampleNumber, mdia->mediaHeader->timeScale, sample->nb_pack);
	if (e) return e;

	
	e = stbl_AddSize(stbl->SampleSize, sampleNumber, sample->dataLength, sample->nb_pack);
	if (e) return e;

	
	if (sample->CTS_Offset) {
		
		if (!stbl->CompositionOffset) {
			stbl->CompositionOffset = (GF_CompositionOffsetBox *) gf_isom_box_new_parent(&stbl->child_boxes, GF_ISOM_BOX_TYPE_CTTS);
			if (!stbl->CompositionOffset) return GF_OUT_OF_MEM;
		}
		
		e = stbl_AddCTS(stbl, sampleNumber, sample->CTS_Offset);
		if (e) return e;
	} else if (stbl->CompositionOffset) {
		e = stbl_AddCTS(stbl, sampleNumber, sample->CTS_Offset);
		if (e) return e;
	}

	
	if (sample->IsRAP) {
		
		if (stbl->SyncSample && (sample->IsRAP == RAP)) {
			e = stbl_AddRAP(stbl->SyncSample, sampleNumber);
			if (e) return e;
		}
	} else {
		
		if (!stbl->SyncSample) {
			stbl->SyncSample = (GF_SyncSampleBox *) gf_isom_box_new_parent(&stbl->child_boxes, GF_ISOM_BOX_TYPE_STSS);
			if (!stbl->SyncSample) return GF_OUT_OF_MEM;
			
			for (i=0; i<stbl->SampleSize->sampleCount; i++) {
				if (i+1 != sampleNumber) {
					e = stbl_AddRAP(stbl->SyncSample, i+1);
					if (e) return e;
				}
			}
		}
	}
	if (sample->IsRAP==RAP_REDUNDANT) {
		e = stbl_AddRedundant(stbl, sampleNumber);
		if (e) return e;
	}

	if (!mdia->mediaTrack->chunk_cache) {
		
		e = stbl_AddChunkOffset(mdia, sampleNumber, StreamDescIndex, data_offset, sample->nb_pack);
		if (e) return e;
	}
	
	if (!syncShadowNumber) return GF_OK;
	if (!stbl->ShadowSync) {
		stbl->ShadowSync = (GF_ShadowSyncBox *) gf_isom_box_new_parent(&stbl->child_boxes, GF_ISOM_BOX_TYPE_STSH);
		if (!stbl->ShadowSync) return GF_OUT_OF_MEM;
	}
	return stbl_AddShadow(mdia->information->sampleTable->ShadowSync, sampleNumber, syncShadowNumber);
}


static GF_Err UpdateSample(GF_MediaBox *mdia, u32 sampleNumber, u32 size, s32 CTS, u64 offset, u8 isRap)
{
	u32 i;
	GF_SampleTableBox *stbl = mdia->information->sampleTable;

	
	stbl_SetSampleSize(stbl->SampleSize, sampleNumber, size);
	stbl_SetChunkOffset(mdia, sampleNumber, offset);

	
	if (stbl->CompositionOffset) {
		stbl_SetSampleCTS(stbl, sampleNumber, CTS);
	} else {
		
		if (CTS) {
			stbl->CompositionOffset = (GF_CompositionOffsetBox *) gf_isom_box_new_parent(&stbl->child_boxes, GF_ISOM_BOX_TYPE_CTTS);
			if (!stbl->CompositionOffset) return GF_OUT_OF_MEM;
			stbl_AddCTS(stbl, sampleNumber, CTS);
		}
	}
	
	if (stbl->SyncSample) {
		stbl_SetSampleRAP(stbl->SyncSample, sampleNumber, isRap);
	} else {
		
		if (! isRap) {
			stbl->SyncSample = (GF_SyncSampleBox *) gf_isom_box_new_parent(&stbl->child_boxes, GF_ISOM_BOX_TYPE_STSS);
			if (!stbl->SyncSample) return GF_OUT_OF_MEM;
			
			for (i=0; i<stbl->SampleSize->sampleCount; i++) {
				if (i+1 != sampleNumber) stbl_AddRAP(stbl->SyncSample, i+1);
			}
		}
	}
	if (isRap==2) {
		stbl_SetRedundant(stbl, sampleNumber);
	}
	return GF_OK;
}

GF_Err Media_UpdateSample(GF_MediaBox *mdia, u32 sampleNumber, GF_ISOSample *sample, Bool data_only)
{
	GF_Err e;
	u32 drefIndex, chunkNum, descIndex;
	u64 newOffset, DTS;
	GF_DataEntryURLBox *Dentry;
	GF_SampleTableBox *stbl;

	if (!mdia || !sample || !sampleNumber || !mdia->mediaTrack->moov->mov->editFileMap)
		return GF_BAD_PARAM;

	stbl = mdia->information->sampleTable;

	if (!data_only) {
		
		e = stbl_GetSampleDTS(stbl->TimeToSample, sampleNumber, &DTS);
		if (e) return e;
		if (DTS != sample->DTS) return GF_BAD_PARAM;
	}

	
	stbl_GetSampleInfos(stbl, sampleNumber, &newOffset, &chunkNum, &descIndex, NULL);

	
	e = Media_GetSampleDesc(mdia, descIndex, NULL, &drefIndex);
	if (e) return e;
	Dentry = (GF_DataEntryURLBox*)gf_list_get(mdia->information->dataInformation->dref->child_boxes, drefIndex - 1);
	if (!Dentry) return GF_ISOM_INVALID_FILE;

	if (Dentry->flags != 1) return GF_BAD_PARAM;

	
	newOffset = gf_isom_datamap_get_offset(mdia->mediaTrack->moov->mov->editFileMap);
	if (sample->dataLength) {
		e = gf_isom_datamap_add_data(mdia->mediaTrack->moov->mov->editFileMap, sample->data, sample->dataLength);
		if (e) return e;
	}

	if (data_only) {
		stbl_SetSampleSize(stbl->SampleSize, sampleNumber, sample->dataLength);
		return stbl_SetChunkOffset(mdia, sampleNumber, newOffset);
	}
	return UpdateSample(mdia, sampleNumber, sample->dataLength, sample->CTS_Offset, newOffset, sample->IsRAP);
}

GF_Err Media_UpdateSampleReference(GF_MediaBox *mdia, u32 sampleNumber, GF_ISOSample *sample, u64 data_offset)
{
	GF_Err e;
	u32 drefIndex, chunkNum, descIndex;
	u64 off, DTS;
	GF_DataEntryURLBox *Dentry;
	GF_SampleTableBox *stbl;

	if (!mdia) return GF_BAD_PARAM;
	stbl = mdia->information->sampleTable;

	
	e = stbl_GetSampleDTS(stbl->TimeToSample, sampleNumber, &DTS);
	if (e) return e;
	if (DTS != sample->DTS) return GF_BAD_PARAM;

	
	stbl_GetSampleInfos(stbl, sampleNumber, &off, &chunkNum, &descIndex, NULL);

	
	e = Media_GetSampleDesc(mdia, descIndex, NULL, &drefIndex);
	if (e) return e;
	Dentry = (GF_DataEntryURLBox*)gf_list_get(mdia->information->dataInformation->dref->child_boxes, drefIndex - 1);
	if (!Dentry) return GF_ISOM_INVALID_FILE;

	
	if (Dentry->flags == 1) return GF_ISOM_INVALID_MODE;

	
	return UpdateSample(mdia, sampleNumber, sample->dataLength, sample->CTS_Offset, data_offset, sample->IsRAP);
}





