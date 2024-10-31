










SampleInterleavedLSScan::SampleInterleavedLSScan(class Frame *frame,class Scan *scan, UBYTE near,const UBYTE *mapping,UBYTE point)
  : JPEGLSScan(frame,scan,near,mapping,point)
{
}




SampleInterleavedLSScan::~SampleInterleavedLSScan(void)
{
}





void SampleInterleavedLSScan::FindComponentDimensions(void)
{ 

  UBYTE cx;
  
  JPEGLSScan::FindComponentDimensions();

  
  
  for(cx = 0;cx < m_ucCount;cx++) {
    class Component *comp = ComponentOf(cx);
    if (comp->MCUHeightOf() != 1 || comp->MCUWidthOf() != 1)
      JPG_THROW(INVALID_PARAMETER,"SampleInterleavedLSScan::FindComponentDimensions", "sample interleaved JPEG LS does not support subsampling");
  }

}





bool SampleInterleavedLSScan::ParseMCU(void)
{

  int lines             = m_ulRemaining[0]; 
  UBYTE preshift        = m_ucLowBit + FractionalColorBitsOf();
  struct Line *line[4];
  UBYTE cx;

  
  
  if (m_pFrame->HeightOf() == 0) {
    assert(lines == 0);
    lines = 8;
  }
  
  
  if (lines > 8) {
    lines = 8;
  }
  if (m_pFrame->HeightOf() > 0)
    m_ulRemaining[0] -= lines;
  assert(lines > 0);
  assert(m_ucCount < 4);

  
  
  for(cx = 0;cx < m_ucCount;cx++) {
    line[cx] = CurrentLine(cx);
  }

  
  do {
    LONG length = m_ulWidth[0];
    LONG *lp[4];

    
    for(cx = 0;cx < m_ucCount;cx++) {
      lp[cx] = line[cx]->m_pData;
      StartLine(cx);
    }

    if (BeginReadMCU(m_Stream.ByteStreamOf())) { 
      
      do {
        LONG a[4],b[4],c[4],d[4]; 
        LONG d1[4],d2[4],d3[4];   
        bool isrun = true;
      
        for(cx = 0;cx < m_ucCount;cx++) {
          GetContext(cx,a[cx],b[cx],c[cx],d[cx]);

          d1[cx]  = d[cx] - b[cx];    
          d2[cx]  = b[cx] - c[cx];
          d3[cx]  = c[cx] - a[cx];

          
          
          if (isrun && !isRunMode(d1[cx],d2[cx],d3[cx]))
            isrun = false;
        }
        
        if (isrun) {
          LONG run = DecodeRun(length,m_lRunIndex[0]);
          
          
          while(run) {
            
            
            for(cx = 0;cx < m_ucCount;cx++) {
              UpdateContext(cx,a[cx]);
              
              *lp[cx]++ = a[cx] << preshift;
            }
            run--,length--;
            
          }
          
          
          
          if (length) {
            bool negative; 
            LONG errval;   
            LONG merr;     
            LONG rx;       
            UBYTE k;       
            
            
            for(cx = 0;cx < m_ucCount;cx++) {
              
              GetContext(cx,a[cx],b[cx],c[cx],d[cx]);
              
              
              negative = a[cx] > b[cx];
              
              k       = GolombParameter(false);
              
              
              merr    = GolombDecode(k,m_lLimit - m_lJ[m_lRunIndex[0]] - 1);
              
              errval  = InverseErrorMapping(merr,ErrorMappingOffset(false,merr != 0,k));
              
              rx      = Reconstruct(negative,b[cx],errval);
              
              UpdateContext(cx,rx);
              
              *lp[cx]++ = rx << preshift;
              
              UpdateState(false,errval);
            }
            
            
            
            if (m_lRunIndex[0] > 0)
              m_lRunIndex[0]--;
          } else break; 
        } else {
          UWORD ctxt;
          bool  negative; 
          LONG  px;       
          LONG  rx;       
          LONG  errval;   
          LONG  merr;     
          UBYTE k;        
          
          for(cx = 0;cx < m_ucCount;cx++) {
            
            d1[cx]  = QuantizedGradient(d1[cx]);
            d2[cx]  = QuantizedGradient(d2[cx]);
            d3[cx]  = QuantizedGradient(d3[cx]);
            
            ctxt    = Context(negative,d1[cx],d2[cx],d3[cx]); 
            
            px      = Predict(a[cx],b[cx],c[cx]);
            
            px      = CorrectPrediction(ctxt,negative,px);
            
            k       = GolombParameter(ctxt);
            
            merr    = GolombDecode(k,m_lLimit);
            
            errval  = InverseErrorMapping(merr,ErrorMappingOffset(ctxt,k));
            
            UpdateState(ctxt,errval);
            
            rx      = Reconstruct(negative,px,errval);
            
            UpdateContext(cx,rx);
            
            *lp[cx]++ = rx << preshift;
          }
        }
      } while(--length);
    } 
    
    
    for(cx = 0;cx < m_ucCount;cx++) {
      EndLine(cx);
      line[cx] = line[cx]->m_pNext;
    }
    
  } while(--lines);
  
  
  
  
  
  m_Stream.SkipStuffing();

  return false;
}




bool SampleInterleavedLSScan::WriteMCU(void)
{

  int lines             = m_ulRemaining[0]; 
  UBYTE preshift        = m_ucLowBit + FractionalColorBitsOf();
  struct Line *line[4];
  UBYTE cx;
  
  
  
  if (lines > 8) {
    lines = 8;
  }
  m_ulRemaining[0] -= lines;
  assert(lines > 0);
  assert(m_ucCount < 4);

  
  
  for(cx = 0;cx < m_ucCount;cx++) {
    line[cx] = CurrentLine(cx);
  }

  
  do {
    LONG length = m_ulWidth[0];
    LONG *lp[4];

    
    for(cx = 0;cx < m_ucCount;cx++) {
      lp[cx] = line[cx]->m_pData;
      StartLine(cx);
    }
    
    BeginWriteMCU(m_Stream.ByteStreamOf()); 
    do {
        LONG a[4],b[4],c[4],d[4]; 
        LONG d1[4],d2[4],d3[4];   
        bool isrun = true;
      
        for(cx = 0;cx < m_ucCount;cx++) {
          GetContext(cx,a[cx],b[cx],c[cx],d[cx]);

          d1[cx]  = d[cx] - b[cx];    
          d2[cx]  = b[cx] - c[cx];
          d3[cx]  = c[cx] - a[cx];

          
          
          if (isrun && !isRunMode(d1[cx],d2[cx],d3[cx]))
            isrun = false;
        }
        
        if (isrun) {
          LONG runcnt = 0;
          do {
            
            
            for(cx = 0;cx < m_ucCount;cx++) {
              LONG x  = *lp[cx] >> preshift;
              if (x - a[cx] < -m_lNear || x - a[cx] > m_lNear)
                break;
            }
            if (cx < m_ucCount)
              break; 
            
            
            
            for(cx = 0;cx < m_ucCount;cx++) {
              UpdateContext(cx,a[cx]);
              lp[cx]++;
            }
          } while(runcnt++,--length);
          
          
          EncodeRun(runcnt,length == 0,m_lRunIndex[0]);
          
          
          if (length) {       
            bool negative; 
            LONG errval;   
            LONG merr;     
            LONG rx;       
            UBYTE k;       
            
            
            for(cx = 0;cx < m_ucCount;cx++) {
              
              GetContext(cx,a[cx],b[cx],c[cx],d[cx]);
              
              
              negative = a[cx] > b[cx];
              
              errval   = (*lp[cx]++ >> preshift) - b[cx];
              if (negative)
                errval = -errval;
              
              errval = QuantizePredictionError(errval);
              
              rx     = Reconstruct(negative,b[cx],errval);
              
              UpdateContext(cx,rx);
              
              k      = GolombParameter(false);
              
              merr   = ErrorMapping(errval,ErrorMappingOffset(false,errval != 0,k));
              
              GolombCode(k,merr,m_lLimit - m_lJ[m_lRunIndex[0]] - 1);
              
              UpdateState(false,errval);
            }
            
            
            
            if (m_lRunIndex[0] > 0)
                m_lRunIndex[0]--;
          } else break; 
        } else { 
          UWORD ctxt;
          bool  negative; 
          LONG  px;       
          LONG  rx;       
          LONG  errval;   
          LONG  merr;     
          UBYTE k;        
          
          for(cx = 0;cx < m_ucCount;cx++) {
            
            d1[cx]     = QuantizedGradient(d1[cx]);
            d2[cx]     = QuantizedGradient(d2[cx]);
            d3[cx]     = QuantizedGradient(d3[cx]);
            
            ctxt   = Context(negative,d1[cx],d2[cx],d3[cx]); 
            
            px     = Predict(a[cx],b[cx],c[cx]);
            
            px     = CorrectPrediction(ctxt,negative,px);
            
            errval = (*lp[cx]++ >> preshift) - px;
            if (negative)
              errval = -errval;
            
            errval = QuantizePredictionError(errval);
            
            rx     = Reconstruct(negative,px,errval);
            
            UpdateContext(cx,rx);
            
            k      = GolombParameter(ctxt);
            
            merr   = ErrorMapping(errval,ErrorMappingOffset(ctxt,k));
            
            GolombCode(k,merr,m_lLimit);
            
            UpdateState(ctxt,errval);
          }
        }
    } while(--length);
    
    
    for(cx = 0;cx < m_ucCount;cx++) {
      EndLine(cx);
      line[cx] = line[cx]->m_pNext;
    }
    
  } while(--lines);

  return false;
}

