
















using namespace std;



static void error_callback( const char* msg, void* ){
  stringstream ss;
  ss << "OpenJPEG error :: " << msg;
  throw file_error( ss.str() );
}


static void warning_callback( const char* msg, void* ){
  logfile << "OpenJPEG warning :: " << msg << endl;
}
static void info_callback( const char* msg, void* ){
  logfile << "OpenJPEG info :: " << msg;
}




void OpenJPEGImage::openImage()
{
  string filename = getFileName( currentX, currentY );

  
  updateTimestamp( filename );

  
  _codec = opj_create_decompress( OPJ_CODEC_JP2 );

  

  opj_set_info_handler( _codec, info_callback, NULL );
  opj_set_warning_handler( _codec, warning_callback, NULL );

  opj_set_error_handler( _codec, error_callback, NULL );

  
  opj_dparameters_t parameters; 
  opj_set_default_decoder_parameters( &parameters );
  if( !opj_setup_decoder( _codec, &parameters ) ){
    throw file_error( "OpenJPEG :: openImage() :: error setting up decoder" );
  }


  Timer timer;
  timer.start();


  
  if( !(_stream = opj_stream_create_default_file_stream( filename.c_str(), true) ) ){
    throw file_error( "OpenJPEG :: Unable to open '" + filename + "'" );
  }


  logfile << "OpenJPEG :: openImage() :: " << "Stream created" << endl;


  
  if( !opj_read_header( _stream, _codec, &_image ) ){
    throw file_error( "OpenJPEG :: process() :: opj_read_header() failed" );
  }


  logfile << "OpenJPEG :: openImage() :: " << "Header read" << endl;


  
  if( bpc == 0 ) loadImageInfo( currentX, currentY );


  logfile << "OpenJPEG :: openImage() :: " << timer.getTime() << " microseconds" << endl;


}



void OpenJPEGImage::closeImage()
{

  Timer timer;
  timer.start();


  if( _codec && _stream ) opj_end_decompress( _codec, _stream );
  if( _codec ){
    opj_destroy_codec( _codec );
    _codec = NULL;
  }
  if( _stream ){
    opj_stream_destroy( _stream );
    _stream = NULL;
  }
  if( _image ){
    opj_image_destroy( _image );
    _image = NULL;
  }


  logfile << "OpenJPEG :: closeImage() :: " << timer.getTime() << " microseconds" << endl;

}



void OpenJPEGImage::loadImageInfo( int seq, int ang )
{


  Timer timer;
  timer.start();


  
  opj_codestream_info_v2_t* cst_info = opj_get_cstr_info( _codec );
  numResolutions = cst_info->m_default_tile_info.tccp_info[0].numresolutions;
  quality_layers = cst_info->m_default_tile_info.numlayers;


  

  if( (cst_info->m_default_tile_info.tccp_info[0].cblksty & J2K_CCP_CBLKSTY_HT) != 0 || (cst_info->m_default_tile_info.tccp_info[0].cblksty & J2K_CCP_CBLKSTY_HTMIXED) != 0 ){
    logfile << "OpenJPEG :: HTJ2K codestream" << endl;
  }



  
  opj_destroy_cstr_info( &cst_info );


  channels = _image->numcomps;
  bpc = _image->comps[0].prec;


  
  unsigned int w = _image->x1 - _image->x0;
  unsigned int h = _image->y1 - _image->y0;
  image_widths.push_back(w);
  image_heights.push_back(h);


  logfile << "OpenJPEG :: DWT Levels: " << numResolutions << endl;
  logfile << "OpenJPEG :: Resolution : " << w << "x" << h << endl;


  
  
  
  for( unsigned int c=1; c<numResolutions; c++ ){
    w = floor( w/2.0 );
    h = floor( h/2.0 );
    image_widths.push_back(w);
    image_heights.push_back(h);

    logfile << "OpenJPEG :: Resolution : " << w << "x" << h << endl;

  }


  
  
  unsigned int n = 1;
  w = image_widths[0];
  h = image_heights[0];
  while( (w>tile_width) || (h>tile_height) ){
    n++;
    w = floor( w/2.0 );
    h = floor( h/2.0 );
    if( n > numResolutions ){
      image_widths.push_back(w);
      image_heights.push_back(h);
    }
  }

  if( n > numResolutions ){

    logfile << "OpenJPEG :: Warning! Insufficient resolution levels in JPEG2000 stream. Will generate " << n-numResolutions << " extra levels dynamically -" << endl << "OpenJPEG :: However, you are advised to regenerate the file with at least " << n << " levels" << endl;


  }

  if( n > numResolutions ) virtual_levels = n-numResolutions-1;
  numResolutions = n;


  
  if( channels == 1 ){
    colourspace = (bpc==1)? BINARY : GREYSCALE;
  }
  else if( channels == 3 ) colourspace = sRGB;

  
  string cs;
  switch( _image->color_space ){
    case OPJ_CLRSPC_SRGB:
      cs = "sRGB";
      break;
    case  OPJ_CLRSPC_SYCC:
      cs = "YUV";
      break;
    case OPJ_CLRSPC_CMYK:
      cs = "CMYK";
      break;
    case OPJ_CLRSPC_EYCC:
      cs = "e-YCC";
      break;
    case OPJ_CLRSPC_UNSPECIFIED:
      cs = "Unspecified";
      break;
    default:
      cs = "Unknown";
      break;
  }



  logfile << "OpenJPEG :: " << bpc << " bit data" << endl << "OpenJPEG :: " << channels << " channels" << endl << "OpenJPEG :: colour space: " << cs << endl << "OpenJPEG :: " << quality_layers << " quality layers detected" << endl;




  
  if( bpc == 1 ) channels = 1;

  
  for( unsigned int i=0; i<channels; i++ ){
    min.push_back( 0.0 );
    if( bpc > 8 && bpc < 16 ) max.push_back( 1<<bpc );
    if( bpc == 16 ) max.push_back( 65535.0 );
    else max.push_back( 255.0 );
  }
  
  
  isSet = true;



  logfile << "OpenJPEG :: loadImageInfo() :: " << timer.getTime() << " microseconds" << endl;

}




RawTile OpenJPEGImage::getTile( int seq, int ang, unsigned int res, int layers, unsigned int tile )
{

  
  unsigned obpc = bpc;
  if( bpc <= 16 && bpc > 8 ) obpc = 16;
  else if( bpc <= 8 ) obpc = 8;


  Timer timer;
  timer.start();


  if( res > numResolutions ){
    ostringstream tile_no;
    tile_no << "OpenJPEG :: Asked for non-existent resolution: " << res;
    throw file_error( tile_no.str() );
  }

  int vipsres = (numResolutions - 1) - res;

  unsigned int tw = tile_width;
  unsigned int th = tile_height;
  
  
  unsigned int rem_x = image_widths[vipsres] % tile_width;
  unsigned int rem_y = image_heights[vipsres] % tile_height;

  
  unsigned int ntlx = (image_widths[vipsres] / tile_width) + (rem_x == 0 ? 0 : 1);
  unsigned int ntly = (image_heights[vipsres] / tile_height) + (rem_y == 0 ? 0 : 1);

  
  if( tile >= ntlx*ntly ){
    ostringstream tile_no;
    tile_no << "OpenJPEG :: Asked for non-existent tile: " << tile;
    throw file_error( tile_no.str() );
  }

  
  if( ( tile % ntlx == ntlx - 1 ) && ( rem_x != 0 ) ) {
    tw = rem_x;
  }

  
  if( ( tile / ntlx == ntly - 1 ) && rem_y != 0 ) {
    th = rem_y;
  }

  
  int xoffset = (tile % ntlx) * tile_width;
  int yoffset = (unsigned int) floor((double)(tile/ntlx)) * tile_height;
  

  logfile << "OpenJPEG :: Tile size: " << tw << "x" << th << " @" << channels << endl;


  
  RawTile rawtile( tile, res, seq, ang, tw, th, channels, obpc );

  if( obpc == 16 ) rawtile.data = new unsigned short[tw*th*channels];
  else if( obpc == 8 ) rawtile.data = new unsigned char[tw*th*channels];
  else throw file_error( "OpenJPEG :: Unsupported number of bits" );

  rawtile.dataLength = tw*th*channels*(obpc/8);
  rawtile.filename = getImagePath();
  rawtile.timestamp = timestamp;

  
  process( res, layers, xoffset, yoffset, tw, th, rawtile.data );


  logfile << "OpenJPEG :: getTile() :: " << timer.getTime() << " microseconds" << endl;


  return rawtile;
}




RawTile OpenJPEGImage::getRegion( int ha, int va, unsigned int res, int layers, int x, int y, unsigned int w, unsigned int h ){

  
  unsigned int obpc = bpc;
  if( bpc <= 16 && bpc > 8 ) obpc = 16;
  else if( bpc <= 8 ) obpc = 8;
  

  Timer timer;
  timer.start();


  RawTile rawtile( 0, res, ha, va, w, h, channels, obpc );

  if( obpc == 16 ) rawtile.data = new unsigned short[w * h * channels];
  else if( obpc == 8 ) rawtile.data = new unsigned char[w * h * channels];
  else throw file_error( "OpenJPEG :: Unsupported number of bits" );

  rawtile.dataLength = w*h*channels*(obpc/8);
  rawtile.filename = getImagePath();
  rawtile.timestamp = timestamp;

  process( res, layers, x, y, w, h, rawtile.data );


  logfile << "OpenJPEG :: getRegion() :: " << timer.getTime() << " microseconds" << endl;


  return rawtile;
}




void OpenJPEGImage::process( unsigned int res, int layers, int xoffset, int yoffset, unsigned int tw, unsigned int th, void *d )
{
  
  
  if( !_image ) openImage();

  
  unsigned int obpc = bpc;
  if( bpc <= 16 && bpc > 8 ) obpc = 16;
  else if( bpc <= 8 ) obpc = 8;

  unsigned int factor = 1;                  
  int vipsres = (numResolutions - 1) - res; 

  
  if( res < virtual_levels ){
    factor = 2 * (virtual_levels - res);
    xoffset *= factor;
    yoffset *= factor;
    tw *= factor;
    th *= factor;
    
    vipsres = numResolutions - 1 - virtual_levels;

  logfile << "OpenJPEG :: using smallest existing resolution " << virtual_levels << endl;

  }

  
  
  if( layers < 0 ) layers = quality_layers;
  else if( layers == 0 ) layers = ceil( quality_layers/2.0 );

  
  if( layers < 1 ) layers = 1;


  
  opj_dparameters_t params;
  params.cp_layer = layers;
  params.cp_reduce = vipsres;


  if( !opj_setup_decoder( _codec, &params ) ){
    throw file_error( "OpenJPEG :: process() :: opj_setup_decoder() failed" );
  }


  
  for( OPJ_UINT32 i = 0; i < _image->numcomps; i++ ){
    _image->comps[i].factor = vipsres;
  }

  
  unsigned int x0 = xoffset << vipsres;
  unsigned int y0 = yoffset << vipsres;
  unsigned int w0 = (xoffset + tw) << vipsres;
  unsigned int h0 = (yoffset + th) << vipsres;


  logfile << "OpenJPEG :: decoding " << layers << " quality layers" << endl;
  logfile << "OpenJPEG :: requested region on high resolution canvas: position: " << xoffset << "x" << yoffset << ". size: " << tw << "x" << th << endl;
  logfile << "OpenJPEG :: mapped resolution region size: " << (tw<<vipsres) << "x" << (th<<vipsres) << endl;



  
  if( !opj_set_decode_area( _codec, _image, x0, y0, w0, h0 ) ){
    throw file_error( "OpenJPEG :: process() :: opj_set_decode_area() failed" );
  }

  
  if( !opj_decode( _codec, _stream, _image ) ){
    throw file_error( "OpenJPEG :: process() :: opj_decode() failed" );
  }


  
  int icc_length = _image->icc_profile_len;
  const char* icc = (const char*) _image->icc_profile_buf;
  if( icc_length > 0 ) metadata["icc"] = string( icc, icc_length );

  if( icc_length > 0 ){
    logfile << "OpenJPEG :: ICC profile detected with size " << icc_length << endl;
  }



  
  unsigned int n = 0;
  unsigned int nk = 0;

  for( unsigned int j=0; j < th; j += factor ){
    for( unsigned int i = 0; i < tw; i += factor ){
      for( unsigned int k = 0; k < channels; k++ ){
        
	
	
	if( obpc == 16 ){
	  ((unsigned short*)d)[nk++] =(  (_image->comps[k].data[n]) & 0x0000ffff );
	}
	
	else if( bpc == 1 ){
	  ((unsigned char*)d)[nk++] = ((_image->comps[k].data[n]) & 0x000000f) * 255;
	}
	else{
	  ((unsigned char*)d)[nk++] = (_image->comps[k].data[n]) & 0x000000ff;
	}
      }
      n++;
    }
  }

  
  
  closeImage();

}
