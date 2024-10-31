











using namespace std;



RawTile TileManager::getNewTile( int resolution, int tile, int xangle, int yangle, int layers, CompressionType ctype ){

  RawTile ttt;

  
  ttt = image->getTile( xangle, yangle, resolution, layers, tile );


  
  
  if( watermark && watermark->isSet() ){

    if( loglevel >= 4 ) insert_timer.start();
    unsigned int tw = ttt.padded? image->getTileWidth() : ttt.width;
    unsigned int th = ttt.padded? image->getTileHeight() : ttt.height;

    watermark->apply( ttt.data, tw, th, ttt.channels, ttt.bpc );
    if( loglevel >= 4 ) *logfile << "TileManager :: Watermark applied: " << insert_timer.getTime()
				 << " microseconds" << endl;
  }


  
  if( ((ttt.width != image->getTileWidth()) || (ttt.height != image->getTileHeight())) && ttt.padded ){
    if( loglevel >= 5 ) * logfile << "TileManager :: Cropping tile" << endl;
    this->crop( &ttt );
  }


  
  if( ctype == UNCOMPRESSED ){
    
    if( loglevel >= 4 ) insert_timer.start();
    tileCache->insert( ttt );
    if( loglevel >= 4 ) *logfile << "TileManager :: Tile cache insertion time: " << insert_timer.getTime()
				 << " microseconds" << endl;
    return ttt;
  }


  switch( ctype ){

   case JPEG:
    
    if( ttt.bpc == 8 && (ttt.channels==1 || ttt.channels==3) ){
      if( loglevel >= 4 ) compression_timer.start();
      compressor->Compress( ttt );
      if( loglevel >= 4 ) *logfile << "TileManager :: JPEG Compression Time: " << compression_timer.getTime() << " microseconds" << endl;
    }
    break;


   case PNG:
    if( loglevel >=2 ) compression_timer.start();
    compressor->Compress( ttt );
    if( loglevel >= 2 ) *logfile << "TileManager :: PNG Compression Time: " << compression_timer.getTime() << " microseconds" << endl;
    break;


   case DEFLATE:
    
    if( loglevel >= 4 ) *logfile << "TileManager :: DEFLATE Compression requested: Not currently available" << endl;
    break;


   default:
     break;

  }


  
  if( loglevel >= 4 ) insert_timer.start();
  tileCache->insert( ttt );
  if( loglevel >= 4 ) *logfile << "TileManager :: Tile cache insertion time: " << insert_timer.getTime()
			       << " microseconds" << endl;


  return ttt;

}



void TileManager::crop( RawTile *ttt ){

  int tw = image->getTileWidth();
  int th = image->getTileHeight();

  if( loglevel >= 5 ){
    *logfile << "TileManager :: Edge tile: Base size: " << tw << "x" << th << ": This tile: " << ttt->width << "x" << ttt->height << endl;

  }

  
  
  int len = tw * th * ttt->channels * (ttt->bpc/8);
  unsigned char* buffer = (unsigned char*) malloc( len );
  unsigned char* src_ptr = (unsigned char*) memcpy( buffer, ttt->data, len );
  unsigned char* dst_ptr = (unsigned char*) ttt->data;

  
  len =  ttt->width * ttt->channels * (ttt->bpc/8);
  for( unsigned int i=0; i<ttt->height; i++ ){
    memcpy( dst_ptr, src_ptr, len );
    dst_ptr += len;
    src_ptr += tw * ttt->channels * (ttt->bpc/8);
  }

  free( buffer );

  
  len = ttt->width * ttt->height * ttt->channels * (ttt->bpc/8);
  ttt->dataLength = len;
  ttt->padded = false;

}




RawTile TileManager::getTile( int resolution, int tile, int xangle, int yangle, int layers, CompressionType ctype ){

  RawTile* rawtile = NULL;
  string tileCompression;
  string compName;


  
  if( loglevel >= 3 ) tile_timer.start();


  
  switch( ctype )
    {

    case JPEG:
      if( (rawtile = tileCache->getTile( image->getImagePath(), resolution, tile, xangle, yangle, JPEG, compressor->getQuality() )) ) break;
      if( (rawtile = tileCache->getTile( image->getImagePath(), resolution, tile, xangle, yangle, UNCOMPRESSED, 0 )) ) break;
      break;


    case PNG:
      if( (rawtile = tileCache->getTile( image->getImagePath(), resolution, tile, xangle, yangle, PNG, compressor->getQuality() )) ) break;
      if( (rawtile = tileCache->getTile( image->getImagePath(), resolution, tile, xangle, yangle, UNCOMPRESSED, 0 )) ) break;
      break;


    case UNCOMPRESSED:
      if( (rawtile = tileCache->getTile( image->getImagePath(), resolution, tile, xangle, yangle, UNCOMPRESSED, 0 )) ) break;
      break;


    default: 
      break;

    }



  if( loglevel >= 3 ){
    
    switch( ctype ){
      case JPEG: compName = "JPEG"; break;
      case PNG: compName = "PNG"; break;
      case DEFLATE: compName = "DEFLATE"; break;
      case UNCOMPRESSED: compName = "UNCOMPRESSED"; break;
      default: break;
    }
  }


  
  if( !rawtile || (rawtile && (rawtile->timestamp < image->timestamp)) ){

    if( rawtile && (rawtile->timestamp < image->timestamp) ){
      if( loglevel >= 3 ) *logfile << "TileManager :: Tile has old timestamp " << rawtile->timestamp << " - " << image->timestamp << " ... updating" << endl;

    }

    if( loglevel >= 4 ) *logfile << "TileManager :: Cache Miss for resolution: " << resolution << ", tile: " << tile << ", compression: " << compName << ", quality: " << compressor->getQuality() << endl << "TileManager :: Cache Size: " << tileCache->getNumElements()



				 << " tiles, " << tileCache->getMemorySize() << " MB" << endl;

    
    RawTile newtile = this->getNewTile( resolution, tile, xangle, yangle, layers, ctype );

    if( loglevel >= 3 ) *logfile << "TileManager :: Total Tile Access Time: " << tile_timer.getTime() << " microseconds" << endl;
    return newtile;
  }




  if( loglevel >= 3 ) *logfile << "TileManager :: Cache Hit for resolution: " << resolution << ", tile: " << tile << ", compression: " << compName << ", quality: " << compressor->getQuality() << endl << "TileManager :: Cache Size: " << tileCache->getNumElements() << " tiles, " << tileCache->getMemorySize() << " MB" << endl;







  
  
  
  if( (rawtile->compressionType == UNCOMPRESSED) && ( ( ctype==JPEG && rawtile->bpc==8 && (rawtile->channels==1 || rawtile->channels==3) ) || ctype==PNG ) ){

    
    RawTile ttt( *rawtile );

    
    if( ( (ttt.width != image->getTileWidth()) || (ttt.height != image->getTileHeight()) ) && ttt.padded ){
      if( loglevel >= 5 ) * logfile << "TileManager :: Cropping tile" << endl;
      this->crop( &ttt );
    }

    if( loglevel >=2 ) compression_timer.start();
    unsigned int oldlen = rawtile->dataLength;
    unsigned int newlen = compressor->Compress( ttt );
    if( loglevel >= 3 ) *logfile << "TileManager :: " << compName << " requested, but UNCOMPRESSED compression found in cache." << endl << "TileManager :: " << compName << " Compression Time: " << compression_timer.getTime() << " microseconds" << endl << "TileManager :: Compression Ratio: " << newlen << "/" << oldlen << " = " << ( (float)newlen/(float)oldlen ) << endl;




    
    if( loglevel >= 3 ) insert_timer.start();
    tileCache->insert( ttt );
    if( loglevel >= 3 ) *logfile << "TileManager :: Tile cache insertion time: " << insert_timer.getTime()
				 << " microseconds" << endl;

    if( loglevel >= 3 ) *logfile << "TileManager :: Total Tile Access Time: " << tile_timer.getTime() << " microseconds" << endl;
    return RawTile( ttt );
  }

  if( loglevel >= 3 ) *logfile << "TileManager :: Total Tile Access Time: " << tile_timer.getTime() << " microseconds" << endl;

  return RawTile( *rawtile );


}


RawTile TileManager::getRegion( unsigned int res, int seq, int ang, int layers, unsigned int x, unsigned int y, unsigned int width, unsigned int height ){

  
  if( image->regionDecoding() ){
    if( loglevel >= 3 ){
      *logfile << "TileManager getRegion :: requesting region directly from image" << endl;
    }
    return image->getRegion( seq, ang, res, layers, x, y, width, height );
  }

  

  
  unsigned int src_tile_width = image->getTileWidth();
  unsigned int src_tile_height = image->getTileHeight();

  
  unsigned int dst_tile_width = src_tile_width;
  unsigned int dst_tile_height = src_tile_height;

  
  unsigned int basic_tile_width = src_tile_width;
  unsigned int basic_tile_height = src_tile_height;

  int num_res = image->getNumResolutions();
  unsigned int im_width = image->image_widths[num_res-res-1];
  unsigned int im_height = image->image_heights[num_res-res-1];

  unsigned int rem_x = im_width % src_tile_width;
  unsigned int rem_y = im_height % src_tile_height;

  
  unsigned int ntlx = (im_width / src_tile_width) + (rem_x == 0 ? 0 : 1);
  unsigned int ntly = (im_height / src_tile_height) + (rem_y == 0 ? 0 : 1);

  
  unsigned int startx, endx, starty, endy, xoffset, yoffset;


  if( ! ( x==0 && y==0 && width==im_width && height==im_height ) ){
    
    startx = (unsigned int) ( x / src_tile_width );
    starty = (unsigned int) ( y / src_tile_height );
    xoffset = x % src_tile_width;
    yoffset = y % src_tile_height;

    endx = (unsigned int) ceil( (float)(width + x) / (float)src_tile_width );
    endy = (unsigned int) ceil( (float)(height + y) / (float)src_tile_height );

    if( loglevel >= 3 ){
      *logfile << "TileManager getRegion :: Total tiles in image: " << ntlx << "x" << ntly << " tiles" << endl << "TileManager getRegion :: Tile start: " << startx << "," << starty << " with offset: " << xoffset << "," << yoffset << endl << "TileManager getRegion :: Tile end: " << endx-1 << "," << endy-1 << endl;


    }
  }
  else{
    startx = starty = xoffset = yoffset = 0;
    endx = ntlx;
    endy = ntly;
  }


  unsigned int channels = image->getNumChannels();
  unsigned int bpc = image->getNumBitsPerPixel();
  SampleType sampleType = image->getSampleType();

  
  if( bpc == 1 ) bpc = 8;

  
  RawTile region( 0, res, seq, ang, width, height, channels, bpc );
  region.dataLength = width * height * channels * (bpc/8);
  region.sampleType = sampleType;

  
  if( bpc == 8 ) region.data = new unsigned char[width*height*channels];
  else if( bpc == 16 ) region.data = new unsigned short[width*height*channels];
  else if( bpc == 32 && sampleType == FIXEDPOINT ) region.data = new int[width*height*channels];
  else if( bpc == 32 && sampleType == FLOATINGPOINT ) region.data = new float[width*height*channels];

  unsigned int current_height = 0;

  
  for( unsigned int i=starty; i<endy; i++ ){

    unsigned int buffer_index = 0;

    
    
    unsigned int current_width = 0;

    for( unsigned int j=startx; j<endx; j++ ){

      
      if( loglevel >= 3 ) tile_timer.start();

      
      RawTile rawtile = this->getTile( res, (i*ntlx) + j, seq, ang, layers, UNCOMPRESSED );

      if( loglevel >= 5 ){
	*logfile << "TileManager getRegion :: Tile access time " << tile_timer.getTime() << " microseconds for tile " << (i*ntlx) + j << " at resolution " << res << endl;
      }


      
      if( (loglevel >= 5) && (i==starty) && (j==starty) ){
	*logfile << "TileManager getRegion :: Tile data is " << rawtile.channels << " channels, " << rawtile.bpc << " bits per channel" << endl;
      }

      
      
      
      src_tile_width = rawtile.width;
      src_tile_height = rawtile.height;
      dst_tile_width = src_tile_width;
      dst_tile_height = src_tile_height;

      
      unsigned int xf = 0;
      unsigned int yf = 0;

      
      
      if( !( x==0 && y==0 && width==im_width && height==im_height ) ){

	unsigned int remainder;  

	if( j == startx ){
	  
	  
	  if( j < endx - 1 ) dst_tile_width = src_tile_width - xoffset;
	  else dst_tile_width = width;
	  xf = xoffset;
	}
	else if( j == endx-1 ){
	  
	  remainder = (width+x) % basic_tile_width;
	  if( remainder != 0 ) dst_tile_width = remainder;
	}

	if( i == starty ){
	  
	  
	  if( i < endy - 1 ) dst_tile_height = src_tile_height - yoffset;
	  else dst_tile_height = height;
	  yf = yoffset;
	}
	else if( i == endy-1 ){
	  
	  remainder = (height+y) % basic_tile_height;
	  if( remainder != 0 ) dst_tile_height = remainder;
	}

	if( loglevel >= 5 ){
	  *logfile << "TileManager getRegion :: destination tile width: " << dst_tile_width << ", tile height: " << dst_tile_height << endl;
	}
      }


      
      
      for( unsigned int k=0; k<dst_tile_height; k++ ){

	buffer_index = (current_width*channels) + (k*width*channels) + (current_height*width*channels);
	unsigned int inx = ((k+yf)*rawtile.width*channels) + (xf*channels);

	
	if( bpc == 8 ){
	  unsigned char* ptr = (unsigned char*) rawtile.data;
	  unsigned char* buf = (unsigned char*) region.data;
	  memcpy( &buf[buffer_index], &ptr[inx], dst_tile_width*channels );
	}
	else if( bpc ==  16 ){
	  unsigned short* ptr = (unsigned short*) rawtile.data;
	  unsigned short* buf = (unsigned short*) region.data;
	  memcpy( &buf[buffer_index], &ptr[inx], dst_tile_width*channels*2 );
	}
	else if( bpc == 32 && sampleType == FIXEDPOINT ){
	  unsigned int* ptr = (unsigned int*) rawtile.data;
	  unsigned int* buf = (unsigned int*) region.data;
	  memcpy( &buf[buffer_index], &ptr[inx], dst_tile_width*channels*4 );
	}
	else if( bpc == 32 && sampleType == FLOATINGPOINT ){
	  float* ptr = (float*) rawtile.data;
	  float* buf = (float*) region.data;
	  memcpy( &buf[buffer_index], &ptr[inx], dst_tile_width*channels*4 );
	}
      }

      current_width += dst_tile_width;
    }

    current_height += dst_tile_height;

  }

  return region;

}
