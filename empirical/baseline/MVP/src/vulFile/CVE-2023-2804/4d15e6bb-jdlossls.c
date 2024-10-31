



















































METHODDEF(void)
jpeg_undifference1(j_decompress_ptr cinfo, int comp_index, JDIFFROW diff_buf, JDIFFROW prev_row, JDIFFROW undiff_buf, JDIMENSION width)

{
  UNDIFFERENCE_1D(INITIAL_PREDICTOR2);
}

METHODDEF(void)
jpeg_undifference2(j_decompress_ptr cinfo, int comp_index, JDIFFROW diff_buf, JDIFFROW prev_row, JDIFFROW undiff_buf, JDIMENSION width)

{
  UNDIFFERENCE_2D(PREDICTOR2);
  (void)(Rc);
}

METHODDEF(void)
jpeg_undifference3(j_decompress_ptr cinfo, int comp_index, JDIFFROW diff_buf, JDIFFROW prev_row, JDIFFROW undiff_buf, JDIMENSION width)

{
  UNDIFFERENCE_2D(PREDICTOR3);
}

METHODDEF(void)
jpeg_undifference4(j_decompress_ptr cinfo, int comp_index, JDIFFROW diff_buf, JDIFFROW prev_row, JDIFFROW undiff_buf, JDIMENSION width)

{
  UNDIFFERENCE_2D(PREDICTOR4);
}

METHODDEF(void)
jpeg_undifference5(j_decompress_ptr cinfo, int comp_index, JDIFFROW diff_buf, JDIFFROW prev_row, JDIFFROW undiff_buf, JDIMENSION width)

{
  UNDIFFERENCE_2D(PREDICTOR5);
}

METHODDEF(void)
jpeg_undifference6(j_decompress_ptr cinfo, int comp_index, JDIFFROW diff_buf, JDIFFROW prev_row, JDIFFROW undiff_buf, JDIMENSION width)

{
  UNDIFFERENCE_2D(PREDICTOR6);
}

METHODDEF(void)
jpeg_undifference7(j_decompress_ptr cinfo, int comp_index, JDIFFROW diff_buf, JDIFFROW prev_row, JDIFFROW undiff_buf, JDIMENSION width)

{
  UNDIFFERENCE_2D(PREDICTOR7);
  (void)(Rc);
}




METHODDEF(void)
jpeg_undifference_first_row(j_decompress_ptr cinfo, int comp_index, JDIFFROW diff_buf, JDIFFROW prev_row, JDIFFROW undiff_buf, JDIMENSION width)

{
  lossless_decomp_ptr losslessd = (lossless_decomp_ptr)cinfo->idct;

  UNDIFFERENCE_1D(INITIAL_PREDICTORx);

  
  switch (cinfo->Ss) {
  case 1:
    losslessd->predict_undifference[comp_index] = jpeg_undifference1;
    break;
  case 2:
    losslessd->predict_undifference[comp_index] = jpeg_undifference2;
    break;
  case 3:
    losslessd->predict_undifference[comp_index] = jpeg_undifference3;
    break;
  case 4:
    losslessd->predict_undifference[comp_index] = jpeg_undifference4;
    break;
  case 5:
    losslessd->predict_undifference[comp_index] = jpeg_undifference5;
    break;
  case 6:
    losslessd->predict_undifference[comp_index] = jpeg_undifference6;
    break;
  case 7:
    losslessd->predict_undifference[comp_index] = jpeg_undifference7;
    break;
  }
}




METHODDEF(void)
simple_upscale(j_decompress_ptr cinfo, JDIFFROW diff_buf, _JSAMPROW output_buf, JDIMENSION width)
{
  do {
    *output_buf++ = (_JSAMPLE)(*diff_buf++ << cinfo->Al);
  } while (--width);
}

METHODDEF(void)
noscale(j_decompress_ptr cinfo, JDIFFROW diff_buf, _JSAMPROW output_buf, JDIMENSION width)
{
  do {
    *output_buf++ = (_JSAMPLE)(*diff_buf++);
  } while (--width);
}




METHODDEF(void)
start_pass_lossless(j_decompress_ptr cinfo)
{
  lossless_decomp_ptr losslessd = (lossless_decomp_ptr)cinfo->idct;
  int ci;

  
  if (cinfo->Ss < 1 || cinfo->Ss > 7 || cinfo->Se != 0 || cinfo->Ah != 0 || cinfo->Al < 0 || cinfo->Al >= cinfo->data_precision)

    ERREXIT4(cinfo, JERR_BAD_PROGRESSION, cinfo->Ss, cinfo->Se, cinfo->Ah, cinfo->Al);

  
  for (ci = 0; ci < cinfo->num_components; ci++)
    losslessd->predict_undifference[ci] = jpeg_undifference_first_row;

  
  if (cinfo->Al)
    losslessd->scaler_scale = simple_upscale;
  else losslessd->scaler_scale = noscale;
}




GLOBAL(void)
_jinit_lossless_decompressor(j_decompress_ptr cinfo)
{
  lossless_decomp_ptr losslessd;

  
  losslessd = (lossless_decomp_ptr)
    (*cinfo->mem->alloc_small) ((j_common_ptr)cinfo, JPOOL_PERMANENT, sizeof(jpeg_lossless_decompressor));
  cinfo->idct = (struct jpeg_inverse_dct *)losslessd;
  losslessd->pub.start_pass = start_pass_lossless;
}


