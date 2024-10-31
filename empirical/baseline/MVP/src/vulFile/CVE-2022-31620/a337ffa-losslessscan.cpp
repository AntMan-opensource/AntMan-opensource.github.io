























LosslessScan::LosslessScan(class Frame *frame,class Scan *scan,UBYTE predictor,UBYTE lowbit,bool differential)
  : PredictiveScan(frame,scan,predictor,lowbit,differential)
{ 

  for(int i = 0;i < 4;i++) {
    m_pDCDecoder[i]    = NULL;
    m_pDCCoder[i]      = NULL;
    m_pDCStatistics[i] = NULL;
  }

}



LosslessScan::~LosslessScan(void)
{
}




void LosslessScan::WriteFrameType(class ByteStream *io)
{

  if (m_bDifferential) {
    io->PutWord(0xffc7); 
  } else {
    io->PutWord(0xffc3); 
  }

  NOREF(io);

}



void LosslessScan::StartParseScan(class ByteStream *io,class Checksum *chk,class BufferCtrl *ctrl)
{

  int i;

  FindComponentDimensions();
  
  for(i = 0;i < m_ucCount;i++) {
    m_pDCDecoder[i]       = m_pScan->DCHuffmanDecoderOf(i);
  }
  
  assert(ctrl->isLineBased());
  m_pLineCtrl = dynamic_cast<LineBuffer *>(ctrl);
  m_pLineCtrl->ResetToStartOfScan(m_pScan);
  m_Stream.OpenForRead(io,chk);

  NOREF(io);
  NOREF(chk);
  NOREF(ctrl);
  JPG_THROW(NOT_IMPLEMENTED,"LosslessScan::StartParseScan", "Lossless JPEG not available in your code release, please contact Accusoft for a full version");

}



void LosslessScan::StartWriteScan(class ByteStream *io,class Checksum *chk,class BufferCtrl *ctrl)
{

  int i;

  FindComponentDimensions();
  
  for(i = 0;i < m_ucCount;i++) {
    m_pDCCoder[i]       = m_pScan->DCHuffmanCoderOf(i);
    m_pDCStatistics[i]  = NULL;
  }
  
  assert(ctrl->isLineBased());
  m_pLineCtrl = dynamic_cast<LineBuffer *>(ctrl);
  m_pLineCtrl->ResetToStartOfScan(m_pScan); 

  EntropyParser::StartWriteScan(io,chk,ctrl);
  
  m_pScan->WriteMarker(io);
  m_Stream.OpenForWrite(io,chk); 

  m_bMeasure = false;

  NOREF(io);
  NOREF(chk);
  NOREF(ctrl);
  JPG_THROW(NOT_IMPLEMENTED,"LosslessScan::StartWriteScan", "Lossless JPEG not available in your code release, please contact Accusoft for a full version");

}



void LosslessScan::StartMeasureScan(class BufferCtrl *ctrl)
{

  int i;

  FindComponentDimensions();
  
  for(i = 0;i < m_ucCount;i++) {
    m_pDCCoder[i]       = NULL;
    m_pDCStatistics[i]  = m_pScan->DCHuffmanStatisticsOf(i);
  }
 
  assert(ctrl->isLineBased());
  m_pLineCtrl = dynamic_cast<LineBuffer *>(ctrl);
  m_pLineCtrl->ResetToStartOfScan(m_pScan);
  
  m_Stream.OpenForWrite(NULL,NULL);
  
  m_bMeasure = true;

  NOREF(ctrl);

}






bool LosslessScan::WriteMCU(void)
{

  int i;
  struct Line *top[4],*prev[4];
  int lines      = 8; 
  
  for(i = 0;i < m_ucCount;i++) {
    class Component *comp = ComponentOf(i);
    UBYTE idx       = comp->IndexOf();
    top[i]          = m_pLineCtrl->CurrentLineOf(idx);
    prev[i]         = m_pLineCtrl->PreviousLineOf(idx);
    m_ulX[i]        = 0;
    m_ulY[i]        = m_pLineCtrl->CurrentYOf(idx);
  }
  
  
  do {
    do {
      BeginWriteMCU(m_Stream.ByteStreamOf());    
      
      if (m_bMeasure) {
        MeasureMCU(prev,top);
      } else {
        WriteMCU(prev,top);
      }
    } while(AdvanceToTheRight());
    
    
  } while(AdvanceToTheNextLine(prev,top) && --lines);

  return false;
}





void LosslessScan::WriteMCU(struct Line **prev,struct Line **top)
{

  UBYTE i;
  
  
  for(i = 0;i < m_ucCount;i++) {
    class HuffmanCoder *dc = m_pDCCoder[i];
    struct Line *line = top[i];
    struct Line *pline= prev[i];
    class PredictorBase *mcupred = m_pPredict[i];
    UBYTE ym = m_ucMCUHeight[i];
    LONG *lp = line->m_pData + m_ulX[i];
    LONG *pp = (pline)?(pline->m_pData + m_ulX[i]):(NULL);
    
    
    do {
      class PredictorBase *pred = mcupred;
      UBYTE xm = m_ucMCUWidth[i];
      do {
        
        
        LONG v = pred->EncodeSample(lp,pp);
        
        if (v == 0) {
          dc->Put(&m_Stream,0);
        } else if (v == MIN_WORD) {
          dc->Put(&m_Stream,16); 
        } else {
          UBYTE symbol = 0;
          do {
            symbol++;
            if (v > -(1 << symbol) && v < (1 << symbol)) {
              dc->Put(&m_Stream,symbol);
              if (v >= 0) {
                m_Stream.Put(symbol,v);
              } else {
                m_Stream.Put(symbol,v - 1);
              }
              break;
            }
          } while(true);
        }
        
        
        
      } while(--xm && (lp++,pp++,pred = pred->MoveRight(),true));
      
      
    } while(--ym && (pp = line->m_pData + m_ulX[i],line = (line->m_pNext)?(line->m_pNext):(line), lp = line->m_pData + m_ulX[i],mcupred = mcupred->MoveDown(),true));
  }

  NOREF(prev);
  NOREF(top);

}






void LosslessScan::MeasureMCU(struct Line **prev,struct Line **top)
{

  UBYTE i;
  
  
  for(i = 0;i < m_ucCount;i++) {
    class HuffmanStatistics *dcstat = m_pDCStatistics[i];
    struct Line *line = top[i];
    struct Line *pline= prev[i];
    class PredictorBase *mcupred = m_pPredict[i];
    UBYTE ym = m_ucMCUHeight[i];
    LONG *lp = line->m_pData + m_ulX[i];
    LONG *pp = (pline)?(pline->m_pData + m_ulX[i]):(NULL);
    
    
    
    do {
      class PredictorBase *pred = mcupred;
      UBYTE xm = m_ucMCUWidth[i];
      do {
        
        
        LONG v = pred->EncodeSample(lp,pp);
        
        if (v == 0) {
          dcstat->Put(0);
        } else if (v == -32768) {
          dcstat->Put(16); 
        } else {
          UBYTE symbol = 0;
          do {
            symbol++;
            if (v > -(1 << symbol) && v < (1 << symbol)) {
              dcstat->Put(symbol);
              break;
            }
          } while(true);
        }
        
        
        
      } while(--xm && (lp++,pp++,pred = pred->MoveRight(),true));
      
      
    } while(--ym && (pp = line->m_pData + m_ulX[i],line = (line->m_pNext)?(line->m_pNext):(line), lp = line->m_pData + m_ulX[i],mcupred = mcupred->MoveDown(),true));
  }

  NOREF(prev);
  NOREF(top);

}





void LosslessScan::ParseMCU(struct Line **prev,struct Line **top)
{ 

  UBYTE i;
  
  
  for(i = 0;i < m_ucCount;i++) {
    class HuffmanDecoder *dc = m_pDCDecoder[i];
    struct Line *line = top[i];
    struct Line *pline= prev[i];
    UBYTE ym = m_ucMCUHeight[i];
    class PredictorBase *mcupred = m_pPredict[i];
    LONG *lp = line->m_pData + m_ulX[i];
    LONG *pp = (pline)?(pline->m_pData + m_ulX[i]):(NULL);
    
    
    do {
      class PredictorBase *pred = mcupred;
      UBYTE xm = m_ucMCUWidth[i];
      do {
        LONG v;
        UBYTE symbol = dc->Get(&m_Stream);
        
        if (symbol == 0) {
          v = 0;
        } else if (symbol == 16) {
          v = -32768;
        } else {
          LONG thre = 1L << (symbol - 1);
          LONG diff = m_Stream.Get(symbol); 
          if (diff < thre) {
            diff += (-1L << symbol) + 1;
          }
          v = diff;
        }
        
        
        lp[0] = pred->DecodeSample(v,lp,pp);
        
        
        
      } while(--xm && (lp++,pp++,pred = pred->MoveRight(),true));
      
      
    } while(--ym && (pp = line->m_pData + m_ulX[i],line = (line->m_pNext)?(line->m_pNext):(line), lp = line->m_pData + m_ulX[i],mcupred = mcupred->MoveDown(),true));
  }

  NOREF(prev);
  NOREF(top);

}






bool LosslessScan::ParseMCU(void)
{

  int i;
  struct Line *top[4],*prev[4];
  int lines      = 8; 
 
  for(i = 0;i < m_ucCount;i++) {
    class Component *comp = ComponentOf(i);
    UBYTE idx       = comp->IndexOf();
    top[i]          = m_pLineCtrl->CurrentLineOf(idx);
    prev[i]         = m_pLineCtrl->PreviousLineOf(idx);
    m_ulX[i]        = 0;
    m_ulY[i]        = m_pLineCtrl->CurrentYOf(idx);
  }

  
  do {
    bool startofline = true;
    do {
      if (BeginReadMCU(m_Stream.ByteStreamOf())) {
        ParseMCU(prev,top);
      } else {
        
        if (m_ulPixelHeight != 0 && !hasFoundDNL()) {
          ClearMCU(top);
        } else if (!startofline) {
          
          
          
          ParseMCU(prev,top);
        } else break;
      }
      startofline = false;
    } while(AdvanceToTheRight());
    
    
  } while(AdvanceToTheNextLine(prev,top) && --lines);

  return false; 
}




bool LosslessScan::StartMCURow(void)
{

  return m_pLineCtrl->StartMCUQuantizerRow(m_pScan);

  return false;

}




void LosslessScan::Flush(bool)
{  

  if (!m_bMeasure)
    m_Stream.Flush();

  PredictiveScan::FlushOnMarker();

}




void LosslessScan::Restart(void)
{ 

  m_Stream.OpenForRead(m_Stream.ByteStreamOf(),m_Stream.ChecksumOf());

  PredictiveScan::RestartOnMarker();

}

