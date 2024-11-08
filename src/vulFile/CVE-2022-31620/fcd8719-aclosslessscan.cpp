





















ACLosslessScan::ACLosslessScan(class Frame *frame,class Scan *scan,UBYTE predictor,UBYTE lowbit,bool differential)
  : PredictiveScan(frame,scan,predictor,lowbit,differential)
{ 

  m_ucCount = scan->ComponentsInScan();
  
  for(int i = 0;i < m_ucCount;i++) {
    m_ucSmall[i]     = 0;
    m_ucLarge[i]     = 1;
  }

  memset(m_plDa,0,sizeof(m_plDa));
  memset(m_plDb,0,sizeof(m_plDb));

}



ACLosslessScan::~ACLosslessScan(void)
{

  UBYTE i;
  
  for(i = 0;i < m_ucCount;i++) {
    if (m_plDa[i])
      m_pEnviron->FreeMem(m_plDa[i],sizeof(LONG) * m_ucMCUHeight[i]);
    if (m_plDb[i])
      m_pEnviron->FreeMem(m_plDb[i],sizeof(LONG) * m_ucMCUWidth[i] * m_ulWidth[i]);
  }

}




void ACLosslessScan::WriteFrameType(class ByteStream *io)
{

  if (m_bDifferential) {
    io->PutWord(0xffcf); 
  } else {
    io->PutWord(0xffcb); 
  }

  NOREF(io);

}





void ACLosslessScan::FindComponentDimensions(void)
{
  UBYTE i;

  PredictiveScan::FindComponentDimensions();

  for(i = 0;i < m_ucCount;i++) {
    assert(m_plDa[i] == NULL && m_plDb[i] == NULL);

    m_plDa[i] = (LONG *)(m_pEnviron->AllocMem(sizeof(LONG) * m_ucMCUHeight[i]));
    m_plDb[i] = (LONG *)(m_pEnviron->AllocMem(sizeof(LONG) * m_ucMCUWidth[i] * m_ulWidth[i]));
  }
}




void ACLosslessScan::StartParseScan(class ByteStream *io,class Checksum *chk,class BufferCtrl *ctrl)
{

  class ACTemplate *dc;
  int i;

  FindComponentDimensions();

  for(i = 0;i < m_ucCount;i++) {
    dc = m_pScan->DCConditionerOf(i);
    if (dc) {
      m_ucSmall[i]    = dc->LowerThresholdOf();
      m_ucLarge[i]    = dc->UpperThresholdOf();
    } else {
      m_ucSmall[i]    = 0;
      m_ucLarge[i]    = 1;
    }
    memset(m_plDa[i],0,sizeof(LONG) * m_ucMCUHeight[i]); 
    memset(m_plDb[i],0,sizeof(LONG) * m_ucMCUWidth[i] * m_ulWidth[i]);
    m_ucContext[i]    = m_pScan->DCTableIndexOf(i); 
  }
  for(i = 0;i < 4;i++) {
    m_Context[i].Init();
  }
  
  assert(ctrl->isLineBased());
  m_pLineCtrl = dynamic_cast<LineBuffer *>(ctrl);
  m_pLineCtrl->ResetToStartOfScan(m_pScan);
  m_Coder.OpenForRead(io,chk);

  NOREF(io);
  NOREF(chk);
  NOREF(ctrl);
  JPG_THROW(NOT_IMPLEMENTED,"ACLosslessScan::StartParseScan", "JPEG lossless not available your code release, please contact Accusoft for a full version");

}



void ACLosslessScan::StartWriteScan(class ByteStream *io,class Checksum *chk,class BufferCtrl *ctrl)
{

  class ACTemplate *dc;
  int i;

  FindComponentDimensions();

  for(i = 0;i < m_ucCount;i++) {
    dc = m_pScan->DCConditionerOf(i);

    if (dc) {
      m_ucSmall[i]    = dc->LowerThresholdOf();
      m_ucLarge[i]    = dc->UpperThresholdOf();
    } else {
      m_ucSmall[i]    = 0;
      m_ucLarge[i]    = 1;
    }  
    memset(m_plDa[i],0,sizeof(LONG) * m_ucMCUHeight[i]);
    memset(m_plDb[i],0,sizeof(LONG) * m_ucMCUWidth[i] * m_ulWidth[i]);
    m_ucContext[i]    = m_pScan->DCTableIndexOf(i); 
  }
  for(i = 0;i < 4;i++) {
    m_Context[i].Init();
  }
    
  assert(ctrl->isLineBased());
  m_pLineCtrl = dynamic_cast<LineBuffer *>(ctrl);
  m_pLineCtrl->ResetToStartOfScan(m_pScan); 

  EntropyParser::StartWriteScan(io,chk,ctrl);
  
  m_pScan->WriteMarker(io);
  m_Coder.OpenForWrite(io,chk);

  NOREF(io);
  NOREF(chk);
  NOREF(ctrl);
  JPG_THROW(NOT_IMPLEMENTED,"ACLosslessScan::StartWriteScan", "JPEG lossless not available your code release, please contact Accusoft for a full version");

}



void ACLosslessScan::StartMeasureScan(class BufferCtrl *)
{
  JPG_THROW(NOT_IMPLEMENTED,"ACLosslessScan::StartMeasureScan", "arithmetic coding is always adaptive and does not require a measurement phase");
}





void ACLosslessScan::WriteMCU(struct Line **prev,struct Line **top)
{ 

  UBYTE c;
  
  
  for(c = 0;c < m_ucCount;c++) {
    struct QMContextSet &contextset = m_Context[m_ucContext[c]];
    struct Line *line = top[c];
    struct Line *pline= prev[c];
    UBYTE ym = m_ucMCUHeight[c];
    class PredictorBase *mcupred = m_pPredict[c];
    ULONG  x = m_ulX[c];
    LONG *lp = line->m_pData + x;
    LONG *pp = (pline)?(pline->m_pData + x):(NULL);
    
    
    do {
      class PredictorBase *pred = mcupred;
      UBYTE xm = m_ucMCUWidth[c];
      do {
        
        
        LONG v = pred->EncodeSample(lp,pp);
        
        
        struct QMContextSet::ContextZeroSet &zset = contextset.ClassifySignZero(m_plDa[c][ym-1],m_plDb[c][x], m_ucSmall[c],m_ucLarge[c]);
        
        if (v) {
          LONG sz;
          m_Coder.Put(zset.S0,true);
          
          if (v < 0) {
            m_Coder.Put(zset.SS,true);
            sz = -(v + 1);
          } else {
            m_Coder.Put(zset.SS,false);
            sz =   v - 1;
          }
          
          if (sz >= 1) {
            struct QMContextSet::MagnitudeSet &mset = contextset.ClassifyMagnitude(m_plDb[c][x],m_ucLarge[c]);
            int  i = 0;
            LONG m = 2;
            
            m_Coder.Put((v > 0)?(zset.SP):(zset.SN),true);
            
            while(sz >= m) {
              m_Coder.Put(mset.X[i],true);
              m <<= 1;
              i++;
            }
            m_Coder.Put(mset.X[i],false);
            
            m >>= 1;
            while((m >>= 1)) {
              m_Coder.Put(mset.M[i],(m & sz)?(true):(false));
            }
          } else {
            m_Coder.Put((v > 0)?(zset.SP):(zset.SN),false);
          }
        } else {
          m_Coder.Put(zset.S0,false);
        }
        
        
        
        
        m_plDb[c][x]    = v;
        m_plDa[c][ym-1] = v;
        
        
        
      } while(--xm && (lp++,pp++,x++,pred = pred->MoveRight(),true));
      
      
    } while(--ym && (pp = line->m_pData + (x = m_ulX[c]),line = (line->m_pNext)?(line->m_pNext):(line), lp = line->m_pData + x,mcupred = mcupred->MoveDown(),true));
  }

  NOREF(prev);
  NOREF(top);

}





void ACLosslessScan::ParseMCU(struct Line **prev,struct Line **top)
{ 

  UBYTE c;
  
  
  for(c = 0;c < m_ucCount;c++) {
    struct QMContextSet &contextset = m_Context[m_ucContext[c]];
    struct Line *line = top[c];
    struct Line *pline= prev[c];
    UBYTE ym = m_ucMCUHeight[c];
    ULONG  x = m_ulX[c];
    class PredictorBase *mcupred = m_pPredict[c];
    LONG *lp = line->m_pData + x;
    LONG *pp = (pline)?(pline->m_pData + x):(NULL);
    
    
    do {
      class PredictorBase *pred = mcupred;
      UBYTE xm = m_ucMCUWidth[c];
      do {
        
        
        LONG v;
        
        
        struct QMContextSet::ContextZeroSet &zset = contextset.ClassifySignZero(m_plDa[c][ym-1],m_plDb[c][x], m_ucSmall[c],m_ucLarge[c]);
        
        if (m_Coder.Get(zset.S0)) {
          LONG sz   = 0;
          bool sign = m_Coder.Get(zset.SS); 
          
          if (m_Coder.Get((sign)?(zset.SN):(zset.SP))) {
            struct QMContextSet::MagnitudeSet &mset = contextset.ClassifyMagnitude(m_plDb[c][x],m_ucLarge[c]);
            int  i = 0;
            LONG m = 2;
            
            while(m_Coder.Get(mset.X[i])) {
              m <<= 1;
              i++;
            }
            
            m >>= 1;
            sz  = m;
            while((m >>= 1)) {
              if (m_Coder.Get(mset.M[i])) {
                sz |= m;
              }
            }
          }
          
          if (sign) {
            v = -sz - 1;
          } else {
            v =  sz + 1;
          }
        } else {
          v = 0;
        }
        
        
        lp[0] = pred->DecodeSample(v,lp,pp);
        
        
        
        m_plDb[c][x]    = v;
        m_plDa[c][ym-1] = v;
        
        
        
      } while(--xm && (lp++,pp++,x++,pred = pred->MoveRight(),true));
      
      
    } while(--ym && (pp = line->m_pData + (x = m_ulX[c]),line = (line->m_pNext)?(line->m_pNext):(line), lp = line->m_pData + x,mcupred = mcupred->MoveDown(),true));
  }

  NOREF(prev);
  NOREF(top);

}






bool ACLosslessScan::WriteMCU(void)
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
      BeginWriteMCU(m_Coder.ByteStreamOf());
      
      WriteMCU(prev,top);
    } while(AdvanceToTheRight());
    
    
    for(i = 0;i < m_ucCount;i++) {
      memset(m_plDa[i],0,sizeof(LONG) * m_ucMCUHeight[i]);
    }
    
    
  } while(AdvanceToTheNextLine(prev,top) && --lines);

  return false;
}






bool ACLosslessScan::ParseMCU(void)
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
      if (BeginReadMCU(m_Coder.ByteStreamOf())) {
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
    
    
    for(i = 0;i < m_ucCount;i++) {
      memset(m_plDa[i],0,sizeof(LONG) * m_ucMCUHeight[i]);
    }
    
  } while(AdvanceToTheNextLine(prev,top) && --lines);

  return false; 
}




bool ACLosslessScan::StartMCURow(void)
{

  return m_pLineCtrl->StartMCUQuantizerRow(m_pScan);

  return false;

}



void ACLosslessScan::Flush(bool)
{

  int i;
  
  m_Coder.Flush();

  for(i = 0;i < m_ucCount;i++) {
    memset(m_plDa[i],0,sizeof(LONG) * m_ucMCUHeight[i]);
    memset(m_plDb[i],0,sizeof(LONG) * m_ucMCUWidth[i] * m_ulWidth[i]); 
  }
  for(i = 0;i < 4;i++) {
    m_Context[i].Init();
  }
  
  PredictiveScan::FlushOnMarker();
  
  m_Coder.OpenForWrite(m_Coder.ByteStreamOf(),m_Coder.ChecksumOf());

}




void ACLosslessScan::Restart(void)
{ 

  int i;
  
  for(i = 0;i < m_ucCount;i++) {
    memset(m_plDa[i],0,sizeof(LONG) * m_ucMCUHeight[i]);
    memset(m_plDb[i],0,sizeof(LONG) * m_ucMCUWidth[i] * m_ulWidth[i]);
  }
  for(i = 0;i < 4;i++) {
    m_Context[i].Init();
  }
  
  PredictiveScan::RestartOnMarker();

  m_Coder.OpenForRead(m_Coder.ByteStreamOf(),m_Coder.ChecksumOf());

}

