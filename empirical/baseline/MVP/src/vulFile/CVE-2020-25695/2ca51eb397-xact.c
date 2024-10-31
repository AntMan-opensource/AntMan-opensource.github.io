













































































int			DefaultXactIsoLevel = XACT_READ_COMMITTED;
int			XactIsoLevel;

bool		DefaultXactReadOnly = false;
bool		XactReadOnly;

bool		DefaultXactDeferrable = false;
bool		XactDeferrable;

int			synchronous_commit = SYNCHRONOUS_COMMIT_ON;


FullTransactionId XactTopFullTransactionId = {InvalidTransactionId};
int			nParallelCurrentXids = 0;
TransactionId *ParallelCurrentXids;

int32 gp_subtrans_warn_limit = 16777216; 


bool		seqXlogWrite;


int			MyXactFlags;


typedef enum TransState {
	TRANS_DEFAULT,				 TRANS_START, TRANS_INPROGRESS, TRANS_COMMIT, TRANS_ABORT, TRANS_PREPARE } TransState;







typedef enum TBlockState {
	
	TBLOCK_DEFAULT,				 TBLOCK_STARTED,   TBLOCK_BEGIN, TBLOCK_INPROGRESS, TBLOCK_IMPLICIT_INPROGRESS, TBLOCK_PARALLEL_INPROGRESS, TBLOCK_END, TBLOCK_ABORT, TBLOCK_ABORT_END, TBLOCK_ABORT_PENDING, TBLOCK_PREPARE,   TBLOCK_SUBBEGIN, TBLOCK_SUBINPROGRESS, TBLOCK_SUBRELEASE, TBLOCK_SUBCOMMIT, TBLOCK_SUBABORT, TBLOCK_SUBABORT_END, TBLOCK_SUBABORT_PENDING, TBLOCK_SUBRESTART, TBLOCK_SUBABORT_RESTART } TBlockState;

























typedef struct TransactionStateData {
	FullTransactionId fullTransactionId;	
	SubTransactionId subTransactionId;	
	char	   *name;			
	int			savepointLevel; 
	TransState	state;			
	TBlockState blockState;		
	int			nestingLevel;	
	int			gucNestLevel;	
	MemoryContext curTransactionContext;	
	ResourceOwner curTransactionOwner;	
	TransactionId *childXids;	
	int			nChildXids;		
	int			maxChildXids;	
	Oid			prevUser;		
	int			prevSecContext; 
	bool		prevXactReadOnly;	
	bool		startedInRecovery;	
	bool		didLogXid;		
	int			parallelModeLevel;	
	bool		chain;			
	bool		executorSaysXactDoesWrites;	

	struct TransactionStateData *parent;	
	struct TransactionStateData *fastLink;	
} TransactionStateData;

static bool	TopXactexecutorDidWriteXLog;	

typedef TransactionStateData *TransactionState;


static int fastNodeCount;
static TransactionState previousFastLink;


typedef struct SerializedTransactionState {
	int			xactIsoLevel;
	bool		xactDeferrable;
	FullTransactionId topFullTransactionId;
	FullTransactionId currentFullTransactionId;
	CommandId	currentCommandId;
	int			nParallelCurrentXids;
	TransactionId parallelCurrentXids[FLEXIBLE_ARRAY_MEMBER];
} SerializedTransactionState;





static TransactionStateData TopTransactionStateData = {
	.state = TRANS_DEFAULT, .blockState = TBLOCK_DEFAULT, };



static int	nUnreportedXids;
static TransactionId unreportedXids[PGPROC_MAX_CACHED_SUBXIDS];

static TransactionState CurrentTransactionState = &TopTransactionStateData;


static SubTransactionId currentSubTransactionId;
static CommandId currentCommandId;
static bool currentCommandIdUsed;


static TimestampTz xactStartTimestamp;
static TimestampTz stmtStartTimestamp;
static TimestampTz xactStopTimestamp;


static int currentSavepointTotal;


static char *prepareGID;


static bool forceSyncCommit = false;


bool		xact_is_sampled = false;


static MemoryContext TransactionAbortContext = NULL;


typedef struct XactCallbackItem {
	struct XactCallbackItem *next;
	XactCallback callback;
	void	   *arg;
} XactCallbackItem;

static XactCallbackItem *Xact_callbacks = NULL;
static XactCallbackItem *Xact_callbacks_once = NULL;


typedef struct SubXactCallbackItem {
	struct SubXactCallbackItem *next;
	SubXactCallback callback;
	void	   *arg;
} SubXactCallbackItem;

static SubXactCallbackItem *SubXact_callbacks = NULL;


File subxip_file = 0;


static void AssignTransactionId(TransactionState s);
static void AbortTransaction(void);
static void AtAbort_Memory(void);
static void AtCleanup_Memory(void);
static void AtAbort_ResourceOwner(void);
static void AtCCI_LocalCache(void);
static void AtCommit_Memory(void);
static void AtStart_Cache(void);
static void AtStart_Memory(void);
static void AtStart_ResourceOwner(void);
static void CallXactCallbacks(XactEvent event);
static void CallXactCallbacksOnce(XactEvent event);
static void CallSubXactCallbacks(SubXactEvent event, SubTransactionId mySubid, SubTransactionId parentSubid);

static void CleanupTransaction(void);
static void CheckTransactionBlock(bool isTopLevel, bool throwError, const char *stmtType);
static void CommitTransaction(void);
static TransactionId RecordTransactionAbort(bool isSubXact);
static void StartTransaction(void);

static void StartSubTransaction(void);
static void CommitSubTransaction(void);
static void AbortSubTransaction(void);
static void CleanupSubTransaction(void);
static void PushTransaction(void);
static void PopTransaction(void);

static void AtSubAbort_Memory(void);
static void AtSubCleanup_Memory(void);
static void AtSubAbort_ResourceOwner(void);
static void AtSubCommit_Memory(void);
static void AtSubStart_Memory(void);
static void AtSubStart_ResourceOwner(void);

static void EndLocalDistribXact(bool isCommit);
static void ShowTransactionState(const char *str);
static void ShowTransactionStateRec(const char *str, TransactionState state);
static const char *BlockStateAsString(TBlockState blockState);
static const char *TransStateAsString(TransState state);
static void DispatchRollbackToSavepoint(char *name);

static bool IsCurrentTransactionIdForReader(TransactionId xid);




bool IsTransactionState(void)
{
	TransactionState s = CurrentTransactionState;

	
	return (s->state == TRANS_INPROGRESS);
}

bool IsAbortInProgress(void)
{
	TransactionState s = CurrentTransactionState;

	return (s->state == TRANS_ABORT);
}

bool IsTransactionPreparing(void)
{
	TransactionState s = CurrentTransactionState;

	return (s->state == TRANS_PREPARE);
}

bool IsAbortedTransactionBlockState(void)
{
	TransactionState s = CurrentTransactionState;

	if (s->blockState == TBLOCK_ABORT || s->blockState == TBLOCK_SUBABORT)
		return true;

	return false;
}

bool TransactionDidWriteXLog(void)
{
	TransactionState s = CurrentTransactionState;
	return s->didLogXid;
}

bool TopXactExecutorDidWriteXLog(void)
{
	return TopXactexecutorDidWriteXLog;
}

void GetAllTransactionXids( DistributedTransactionId	*distribXid, TransactionId				*localXid, TransactionId				*subXid)



{
	TransactionState s = CurrentTransactionState;

	*distribXid = getDistributedTransactionId();
	*localXid = XidFromFullTransactionId(s->fullTransactionId);
	*subXid = s->subTransactionId;
}


TransactionId GetTopTransactionId(void)
{
	if (!FullTransactionIdIsValid(XactTopFullTransactionId))
		AssignTransactionId(&TopTransactionStateData);
	return XidFromFullTransactionId(XactTopFullTransactionId);
}


TransactionId GetTopTransactionIdIfAny(void)
{
	return XidFromFullTransactionId(XactTopFullTransactionId);
}


TransactionId GetCurrentTransactionId(void)
{
	TransactionState s = CurrentTransactionState;

	if (!FullTransactionIdIsValid(s->fullTransactionId))
		AssignTransactionId(s);
	return XidFromFullTransactionId(s->fullTransactionId);
}


TransactionId GetCurrentTransactionIdIfAny(void)
{
	return XidFromFullTransactionId(CurrentTransactionState->fullTransactionId);
}


FullTransactionId GetTopFullTransactionId(void)
{
	if (!FullTransactionIdIsValid(XactTopFullTransactionId))
		AssignTransactionId(&TopTransactionStateData);
	return XactTopFullTransactionId;
}


FullTransactionId GetTopFullTransactionIdIfAny(void)
{
	return XactTopFullTransactionId;
}


FullTransactionId GetCurrentFullTransactionId(void)
{
	TransactionState s = CurrentTransactionState;

	if (!FullTransactionIdIsValid(s->fullTransactionId))
		AssignTransactionId(s);
	return s->fullTransactionId;
}


FullTransactionId GetCurrentFullTransactionIdIfAny(void)
{
	return CurrentTransactionState->fullTransactionId;
}


void MarkCurrentTransactionIdLoggedIfAny(void)
{
	if (FullTransactionIdIsValid(CurrentTransactionState->fullTransactionId))
		CurrentTransactionState->didLogXid = true;
}

void MarkTopTransactionWriteXLogOnExecutor(void)
{
	TopXactexecutorDidWriteXLog = true;
}


TransactionId GetStableLatestTransactionId(void)
{
	static LocalTransactionId lxid = InvalidLocalTransactionId;
	static TransactionId stablexid = InvalidTransactionId;

	if (lxid != MyProc->lxid)
	{
		lxid = MyProc->lxid;
		stablexid = GetTopTransactionIdIfAny();
		if (!TransactionIdIsValid(stablexid))
			stablexid = ReadNewTransactionId();
	}

	Assert(TransactionIdIsValid(stablexid));

	return stablexid;
}


static void AssignTransactionId(TransactionState s)
{
	bool		isSubXact = (s->parent != NULL);
	ResourceOwner currentOwner;
	bool		log_unknown_top = false;

	
	Assert(!FullTransactionIdIsValid(s->fullTransactionId));
	Assert(s->state == TRANS_INPROGRESS);

	if (DistributedTransactionContext == DTX_CONTEXT_QE_READER || DistributedTransactionContext == DTX_CONTEXT_QE_ENTRY_DB_SINGLETON)
	{
		elog(ERROR, "AssignTransactionId() called by %s process", DtxContextToString(DistributedTransactionContext));
	}

	
	if (IsInParallelMode() || IsParallelWorker())
		elog(ERROR, "cannot assign XIDs during a parallel operation");

	
	if (isSubXact && !FullTransactionIdIsValid(s->parent->fullTransactionId))
	{
		TransactionState p = s->parent;
		TransactionState *parents;
		size_t		parentOffset = 0;

		parents = palloc(sizeof(TransactionState) * s->nestingLevel);
		while (p != NULL && !FullTransactionIdIsValid(p->fullTransactionId))
		{
			parents[parentOffset++] = p;
			p = p->parent;
		}

		
		while (parentOffset != 0)
			AssignTransactionId(parents[--parentOffset]);

		pfree(parents);
	}

	
	if (isSubXact && XLogLogicalInfoActive() && !TopTransactionStateData.didLogXid)
		log_unknown_top = true;

	
	s->fullTransactionId = GetNewTransactionId(isSubXact);

	ereportif(Debug_print_full_dtm, LOG, (errmsg("AssignTransactionId(): assigned xid " UINT64_FORMAT, U64FromFullTransactionId(s->fullTransactionId))));


	if (!isSubXact)
		XactTopFullTransactionId = s->fullTransactionId;

	if (isSubXact)
	{
		Assert(TransactionIdPrecedes(U64FromFullTransactionId(s->parent->fullTransactionId), U64FromFullTransactionId(s->fullTransactionId)));
		SubTransSetParent(XidFromFullTransactionId(s->fullTransactionId), XidFromFullTransactionId(s->parent->fullTransactionId));
	}

	
	if (!isSubXact)
		RegisterPredicateLockingXid(XidFromFullTransactionId(s->fullTransactionId));

	
	currentOwner = CurrentResourceOwner;
	CurrentResourceOwner = s->curTransactionOwner;

	XactLockTableInsert(XidFromFullTransactionId(s->fullTransactionId));

	CurrentResourceOwner = currentOwner;

	
	if (isSubXact && XLogStandbyInfoActive())
	{
		unreportedXids[nUnreportedXids] = XidFromFullTransactionId(s->fullTransactionId);
		nUnreportedXids++;

		
		if (nUnreportedXids >= PGPROC_MAX_CACHED_SUBXIDS || log_unknown_top)
		{
			xl_xact_assignment xlrec;

			
			xlrec.xtop = GetTopTransactionId();
			Assert(TransactionIdIsValid(xlrec.xtop));
			xlrec.nsubxacts = nUnreportedXids;

			XLogBeginInsert();
			XLogRegisterData((char *) &xlrec, MinSizeOfXactAssignment);
			XLogRegisterData((char *) unreportedXids, nUnreportedXids * sizeof(TransactionId));

			(void) XLogInsert(RM_XACT_ID, XLOG_XACT_ASSIGNMENT);

			nUnreportedXids = 0;
			
			TopTransactionStateData.didLogXid = true;
		}
	}
}


SubTransactionId GetCurrentSubTransactionId(void)
{
	TransactionState s = CurrentTransactionState;

	return s->subTransactionId;
}


bool SubTransactionIsActive(SubTransactionId subxid)
{
	TransactionState s;

	for (s = CurrentTransactionState; s != NULL; s = s->parent)
	{
		if (s->state == TRANS_ABORT)
			continue;
		if (s->subTransactionId == subxid)
			return true;
	}
	return false;
}



CommandId GetCurrentCommandId(bool used)
{
	
	if (used)
	{
		
		Assert(!IsParallelWorker());
		currentCommandIdUsed = true;
	}
	return currentCommandId;
}


void SetParallelStartTimestamps(TimestampTz xact_ts, TimestampTz stmt_ts)
{
	Assert(IsParallelWorker());
	xactStartTimestamp = xact_ts;
	stmtStartTimestamp = stmt_ts;
}


TimestampTz GetCurrentTransactionStartTimestamp(void)
{
	return xactStartTimestamp;
}


TimestampTz GetCurrentStatementStartTimestamp(void)
{
	return stmtStartTimestamp;
}


TimestampTz GetCurrentTransactionStopTimestamp(void)
{
	if (xactStopTimestamp != 0)
		return xactStopTimestamp;
	return GetCurrentTimestamp();
}


void SetCurrentStatementStartTimestamp(void)
{
	if (!IsParallelWorker())
		stmtStartTimestamp = GetCurrentTimestamp();
	else Assert(stmtStartTimestamp != 0);
}


static inline void SetCurrentTransactionStopTimestamp(void)
{
	xactStopTimestamp = GetCurrentTimestamp();
}


int GetCurrentTransactionNestLevel(void)
{
	TransactionState s = CurrentTransactionState;

	return s->nestingLevel;
}


static bool TransactionIdIsCurrentTransactionIdInternal(TransactionId xid)
{
	TransactionState s = CurrentTransactionState;

	while (s != NULL)
	{
		if (s->state != TRANS_ABORT && FullTransactionIdIsValid(s->fullTransactionId))
		{
			int			low, high;

			if (TransactionIdEquals(xid, XidFromFullTransactionId(s->fullTransactionId)))
				return true;

			
			low = 0;
			high = s->nChildXids - 1;
			while (low <= high)
			{
				int				middle;
				TransactionId	probe;

				middle = low + (high - low) / 2;
				probe = s->childXids[middle];
				if (TransactionIdEquals(probe, xid))
					return true;
				else if (TransactionIdPrecedes(probe, xid))
					low = middle + 1;
				else high = middle - 1;
			}

			
			if (TransactionIdFollows(xid, XidFromFullTransactionId(s->fullTransactionId)))
				break;
		}

		if (s->fastLink)
		{
			if (TransactionIdPrecedesOrEquals(xid, XidFromFullTransactionId(s->fastLink->fullTransactionId)))
			{
				s = s->fastLink;
				continue;
			}
		}

		s = s->parent;
	}

	return false;
}


static bool IsCurrentTransactionIdForReader(TransactionId xid)
{
	Assert(!Gp_is_writer);

	Assert(SharedLocalSnapshotSlot);

	LWLockAcquire(SharedLocalSnapshotSlot->slotLock, LW_SHARED);

	PGPROC* writer_proc = SharedLocalSnapshotSlot->writer_proc;
	PGXACT* writer_xact = SharedLocalSnapshotSlot->writer_xact;

	if (!writer_proc)
	{
		LWLockRelease(SharedLocalSnapshotSlot->slotLock);
		elog(ERROR, "reference to writer proc not found in shared snapshot");
	}
	else if (!writer_proc->pid)
	{
		LWLockRelease(SharedLocalSnapshotSlot->slotLock);
		elog(ERROR, "writer proc reference shared with reader is invalid");
	}

	TransactionId writer_xid = writer_xact->xid;
	bool overflowed = writer_xact->overflowed;
	bool isCurrent = false;

	if (TransactionIdIsValid(writer_xid))
	{
		
		if (TransactionIdEquals(xid, writer_xid))
		{
			ereportif(Debug_print_full_dtm, LOG, (errmsg("reader encountered writer's top xid %u", xid)));
			isCurrent = true;
		}
		else {
			
			int subx_index = writer_xact->nxids - 1;
			while (!isCurrent &&  subx_index >= 0)
			{
				isCurrent = TransactionIdEquals(writer_proc->subxids.xids[subx_index], xid);
				subx_index--;
			}
		}
	}

	
	LWLockRelease(SharedLocalSnapshotSlot->slotLock);

	
	if (!isCurrent && overflowed)
	{
		Assert(TransactionIdIsValid(writer_xid));
		
		if (TransactionIdFollowsOrEquals(xid, TransactionXmin) && TransactionIdEquals(SubTransGetTopmostTransaction(xid), writer_xid))
		{
			
			isCurrent = TransactionIdDidAbortForReader(xid) ? false : true;
		}
	}

	ereportif(isCurrent && Debug_print_full_dtm, LOG, (errmsg("reader encountered writer's subxact ID %u", xid)));

	return isCurrent;
}


bool TransactionIdIsCurrentTransactionId(TransactionId xid)
{
	bool		isCurrentTransactionId = false;

	
	if (!TransactionIdIsNormal(xid))
		return false;

	
	if (nParallelCurrentXids > 0)
	{
		int			low, high;

		low = 0;
		high = nParallelCurrentXids - 1;
		while (low <= high)
		{
			int			middle;
			TransactionId probe;

			middle = low + (high - low) / 2;
			probe = ParallelCurrentXids[middle];
			if (probe == xid)
				return true;
			else if (probe < xid)
				low = middle + 1;
			else high = middle - 1;
		}
		return false;
	}

    if (DistributedTransactionContext == DTX_CONTEXT_QE_READER || DistributedTransactionContext == DTX_CONTEXT_QE_ENTRY_DB_SINGLETON)
	{
		isCurrentTransactionId = IsCurrentTransactionIdForReader(xid);

		ereportif(Debug_print_full_dtm, LOG, (errmsg("qExec Reader xid = %u, is current = %s", xid, (isCurrentTransactionId ? "true" : "false"))));


		return isCurrentTransactionId;
	}

	
	Assert(DistributedTransactionContext != DTX_CONTEXT_QE_ENTRY_DB_SINGLETON);

	return TransactionIdIsCurrentTransactionIdInternal(xid);
}


bool TransactionStartedDuringRecovery(void)
{
	return CurrentTransactionState->startedInRecovery;
}


void EnterParallelMode(void)
{
	TransactionState s = CurrentTransactionState;

	Assert(s->parallelModeLevel >= 0);

	++s->parallelModeLevel;
}


void ExitParallelMode(void)
{
	TransactionState s = CurrentTransactionState;

	Assert(s->parallelModeLevel > 0);
	Assert(s->parallelModeLevel > 1 || !ParallelContextActive());

	--s->parallelModeLevel;
}


bool IsInParallelMode(void)
{
	return CurrentTransactionState->parallelModeLevel != 0;
}


void CommandCounterIncrement(void)
{
	
	if (currentCommandIdUsed)
	{
		
		if (IsInParallelMode() || IsParallelWorker())
			elog(ERROR, "cannot start commands during a parallel operation");

		currentCommandId += 1;
		if (currentCommandId == InvalidCommandId)
		{
			currentCommandId -= 1;
			ereport(ERROR, (errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED), errmsg("cannot have more than 2^32-2 commands in a transaction")));

		}
		currentCommandIdUsed = false;

		
		SnapshotSetCommandId(currentCommandId);

		
		AtCCI_LocalCache();
	}
}


void ForceSyncCommit(void)
{
	forceSyncCommit = true;
}





static void AtStart_Cache(void)
{
	AcceptInvalidationMessages();
}


static void AtStart_Memory(void)
{
	TransactionState s = CurrentTransactionState;

	
	if (TransactionAbortContext == NULL)
		TransactionAbortContext = AllocSetContextCreate(TopMemoryContext, "TransactionAbortContext", 32 * 1024, 32 * 1024, 32 * 1024);





	
	Assert(TopTransactionContext == NULL);

	
	TopTransactionContext = AllocSetContextCreate(TopMemoryContext, "TopTransactionContext", ALLOCSET_DEFAULT_SIZES);



	
	CurTransactionContext = TopTransactionContext;
	s->curTransactionContext = CurTransactionContext;

	
	MemoryContextSwitchTo(CurTransactionContext);
}


static void AtStart_ResourceOwner(void)
{
	TransactionState s = CurrentTransactionState;

	
	Assert(TopTransactionResourceOwner == NULL);

	
	s->curTransactionOwner = ResourceOwnerCreate(NULL, "TopTransaction");

	TopTransactionResourceOwner = s->curTransactionOwner;
	CurTransactionResourceOwner = s->curTransactionOwner;
	CurrentResourceOwner = s->curTransactionOwner;
}




static void AtSubStart_Memory(void)
{
	TransactionState s = CurrentTransactionState;

	Assert(CurTransactionContext != NULL);

	
	CurTransactionContext = AllocSetContextCreate(CurTransactionContext, "CurTransactionContext", ALLOCSET_DEFAULT_SIZES);

	s->curTransactionContext = CurTransactionContext;

	
	MemoryContextSwitchTo(CurTransactionContext);
}


static void AtSubStart_ResourceOwner(void)
{
	TransactionState s = CurrentTransactionState;

	Assert(s->parent != NULL);

	
	s->curTransactionOwner = ResourceOwnerCreate(s->parent->curTransactionOwner, "SubTransaction");


	CurTransactionResourceOwner = s->curTransactionOwner;
	CurrentResourceOwner = s->curTransactionOwner;
}




static TransactionId RecordTransactionCommit(void)
{
	TransactionId xid;
	bool		markXidCommitted;
	TransactionId latestXid = InvalidTransactionId;
	int			nrels;
	RelFileNodePendingDelete *rels;
	DbDirNode	*deldbs;
	int			ndeldbs;
	int			nchildren;
	TransactionId *children;
	int			nmsgs = 0;
	SharedInvalidationMessage *invalMessages = NULL;
	bool		RelcacheInitFileInval = false;
	bool		wrote_xlog;
	bool		isDtxPrepared = 0;
	bool		isOnePhaseQE = (Gp_role == GP_ROLE_EXECUTE && MyTmGxactLocal->isOnePhaseCommit);

	
	if (DistributedTransactionContext == DTX_CONTEXT_QE_ENTRY_DB_SINGLETON || DistributedTransactionContext == DTX_CONTEXT_QE_READER)
	{
		xid = InvalidTransactionId;
	}
	else xid = GetTopTransactionIdIfAny();
	markXidCommitted = TransactionIdIsValid(xid);

	
	nrels = smgrGetPendingDeletes(true, &rels);
	ndeldbs = GetPendingDbDeletes(true, &deldbs);
	nchildren = xactGetCommittedChildren(&children);
	if (XLogStandbyInfoActive())
		nmsgs = xactGetCommittedInvalidationMessages(&invalMessages, &RelcacheInitFileInval);
	wrote_xlog = (XactLastRecEnd != 0);

	isDtxPrepared = isPreparedDtxTransaction();

	
	if (!markXidCommitted)
	{
		
		if (nrels != 0)
			elog(ERROR, "cannot commit a transaction that deleted files but has no xid");

		
		Assert(nchildren == 0);

		
		if (nmsgs != 0)
		{
			LogStandbyInvalidations(nmsgs, invalMessages, RelcacheInitFileInval);
			wrote_xlog = true;	
		}

		
		if (!isDtxPrepared && !wrote_xlog)
			goto cleanup;
	}

	
	if (markXidCommitted || isDtxPrepared)
	{
		bool		replorigin;

		
		replorigin = (replorigin_session_origin != InvalidRepOriginId && replorigin_session_origin != DoNotReplicateId);

		
		
		if (markXidCommitted)
			BufmgrCommit();

		if (isDtxPrepared)
			SIMPLE_FAULT_INJECTOR("before_xlog_xact_distributed_commit");

		
		START_CRIT_SECTION();
		MyPgXact->delayChkpt = true;

		SetCurrentTransactionStopTimestamp();

		SIMPLE_FAULT_INJECTOR("onephase_transaction_commit");

		XactLogCommitRecord(xactStopTimestamp, GetPendingTablespaceForDeletionForCommit(), nchildren, children, nrels, rels, nmsgs, invalMessages, ndeldbs, deldbs, RelcacheInitFileInval, forceSyncCommit, MyXactFlags, InvalidTransactionId, NULL  );







		if (replorigin)
			
			replorigin_session_advance(replorigin_session_origin_lsn, XactLastRecEnd);

		

		if (!replorigin || replorigin_session_origin_timestamp == 0)
			replorigin_session_origin_timestamp = xactStopTimestamp;

		TransactionTreeSetCommitTsData(xid, nchildren, children, replorigin_session_origin_timestamp, replorigin_session_origin, false);

	}


	
	if ((wrote_xlog && markXidCommitted && synchronous_commit > SYNCHRONOUS_COMMIT_OFF) || forceSyncCommit || nrels > 0)


	{
		XLogFlush(XactLastRecEnd);


		if (isDtxPrepared == 0 && CurrentTransactionState->blockState == TBLOCK_END)
		{
			FaultInjector_InjectFaultIfSet("local_tm_record_transaction_commit", DDLNotSpecified, "", "");


		}


		
		if (markXidCommitted)
		{
			
			
			if (isDtxPrepared || isOnePhaseQE)
				DistributedLog_SetCommittedTree(xid, nchildren, children, getDistributedTransactionId(), false);


			TransactionIdCommitTree(xid, nchildren, children);
		}
	}

	else {
		
		XLogSetAsyncXactLSN(XactLastRecEnd);

		
		if (markXidCommitted)
			TransactionIdAsyncCommitTree(xid, nchildren, children, XactLastRecEnd);
	}



	if (isDtxPrepared)
	{
		FaultInjector_InjectFaultIfSet("dtm_xlog_distributed_commit", DDLNotSpecified, "", "");


	}


	
	if (markXidCommitted || isDtxPrepared)
	{
		MyPgXact->delayChkpt = false;
		END_CRIT_SECTION();
		SIMPLE_FAULT_INJECTOR("after_xlog_xact_distributed_commit");
	}

	
	latestXid = TransactionIdLatest(xid, nchildren, children);

	
	if ((wrote_xlog && markXidCommitted) || isDtxPrepared)
		SyncRepWaitForLSN(XactLastRecEnd, true);

	
	XactLastCommitEnd = XactLastRecEnd;

	
	XactLastRecEnd = 0;
cleanup:
	

	return latestXid;
}


void RecordDistributedForgetCommitted(DistributedTransactionId gxid)
{
	xl_xact_distributed_forget xlrec;

	xlrec.gxid = gxid;

	XLogBeginInsert();
	XLogRegisterData((char *) &xlrec, sizeof(xl_xact_distributed_forget));

	XLogInsert(RM_XACT_ID, XLOG_XACT_DISTRIBUTED_FORGET);
}


static void AtCCI_LocalCache(void)
{
	
	AtCCI_RelationMap();

	
	CommandEndInvalidationMessages();
}


static void AtCommit_Memory(void)
{
	
	MemoryContextSwitchTo(TopMemoryContext);

	
	Assert(TopTransactionContext != NULL);
	MemoryContextDelete(TopTransactionContext);
	TopTransactionContext = NULL;
	CurTransactionContext = NULL;
	CurrentTransactionState->curTransactionContext = NULL;
}





static void AtSubCommit_Memory(void)
{
	TransactionState s = CurrentTransactionState;

	Assert(s->parent != NULL);

	
	CurTransactionContext = s->parent->curTransactionContext;
	MemoryContextSwitchTo(CurTransactionContext);

	
	if (MemoryContextIsEmpty(s->curTransactionContext))
	{
		MemoryContextDelete(s->curTransactionContext);
		s->curTransactionContext = NULL;
	}
}


static void AtSubCommit_childXids(void)
{
	TransactionState s = CurrentTransactionState;
	int			new_nChildXids;

	Assert(s->parent != NULL);

	
	new_nChildXids = s->parent->nChildXids + s->nChildXids + 1;

	
	if (s->parent->maxChildXids < new_nChildXids)
	{
		int			new_maxChildXids;
		TransactionId *new_childXids;

		
		new_maxChildXids = Min(new_nChildXids * 2, (int) (MaxAllocSize / sizeof(TransactionId)));

		if (new_maxChildXids < new_nChildXids)
			ereport(ERROR, (errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED), errmsg("maximum number of committed subtransactions (%d) exceeded", (int) (MaxAllocSize / sizeof(TransactionId)))));



		
		if (s->parent->childXids == NULL)
			new_childXids = MemoryContextAlloc(TopTransactionContext, new_maxChildXids * sizeof(TransactionId));

		else new_childXids = repalloc(s->parent->childXids, new_maxChildXids * sizeof(TransactionId));


		s->parent->childXids = new_childXids;
		s->parent->maxChildXids = new_maxChildXids;
	}

	
	s->parent->childXids[s->parent->nChildXids] = XidFromFullTransactionId(s->fullTransactionId);

	if (s->nChildXids > 0)
		memcpy(&s->parent->childXids[s->parent->nChildXids + 1], s->childXids, s->nChildXids * sizeof(TransactionId));


	s->parent->nChildXids = new_nChildXids;

	
	if (s->childXids != NULL)
		pfree(s->childXids);
	
	s->childXids = NULL;
	s->nChildXids = 0;
	s->maxChildXids = 0;
}




static TransactionId RecordTransactionAbort(bool isSubXact)
{
	TransactionId xid;
	TransactionId latestXid;
	int			nrels;
	RelFileNodePendingDelete *rels;
	int			nchildren;
	TransactionId *children;
	TimestampTz xact_time;
	DbDirNode	*deldbs;
	int			ndeldbs;
	bool		isQEReader;

	
	isQEReader = (DistributedTransactionContext == DTX_CONTEXT_QE_READER || DistributedTransactionContext == DTX_CONTEXT_QE_ENTRY_DB_SINGLETON);
	
	if (isQEReader || getCurrentDtxState() == DTX_STATE_NOTIFYING_COMMIT_PREPARED || CurrentDtxIsRollingback() || MyProc->localDistribXactData.state == LOCALDISTRIBXACT_STATE_ABORTED)


		xid = InvalidTransactionId;
	else xid = GetCurrentTransactionIdIfAny();

	
	SetCurrentTransactionStopTimestamp();
	if (!TransactionIdIsValid(xid))
	{
		
		if (!isSubXact)
			XactLastRecEnd = 0;
		return InvalidTransactionId;
	}

	

	
	if (TransactionIdDidCommit(xid))
		elog(PANIC, "cannot abort transaction %u, it was already committed", xid);

	
	nrels = smgrGetPendingDeletes(false, &rels);
	ndeldbs = GetPendingDbDeletes(false, &deldbs);
	nchildren = xactGetCommittedChildren(&children);

	
	START_CRIT_SECTION();

	
	if (isSubXact)
		xact_time = GetCurrentTimestamp();
	else {
		SetCurrentTransactionStopTimestamp();
		xact_time = xactStopTimestamp;
	}

	XactLogAbortRecord(xact_time, GetPendingTablespaceForDeletionForAbort(), nchildren, children, nrels, rels, ndeldbs, deldbs, MyXactFlags, InvalidTransactionId, NULL);






	
	if (!isSubXact)
		XLogSetAsyncXactLSN(XactLastRecEnd);

	
	TransactionIdAbortTree(xid, nchildren, children);

	END_CRIT_SECTION();

	
	latestXid = TransactionIdLatest(xid, nchildren, children);

	
	if (isSubXact)
		XidCacheRemoveRunningXids(xid, nchildren, children, latestXid);

	
	if (!isSubXact)
		XactLastRecEnd = 0;

	if (max_wal_senders > 0)
		WalSndWakeup();

	return latestXid;
}


static void AtAbort_Memory(void)
{
	
	if (TransactionAbortContext != NULL)
		MemoryContextSwitchTo(TransactionAbortContext);
	else MemoryContextSwitchTo(TopMemoryContext);
}


static void AtSubAbort_Memory(void)
{
	Assert(TransactionAbortContext != NULL);

	MemoryContextSwitchTo(TransactionAbortContext);
}



static void AtAbort_ResourceOwner(void)
{
	
	CurrentResourceOwner = TopTransactionResourceOwner;
}


static void AtSubAbort_ResourceOwner(void)
{
	TransactionState s = CurrentTransactionState;

	
	CurrentResourceOwner = s->curTransactionOwner;
}



static void AtSubAbort_childXids(void)
{
	TransactionState s = CurrentTransactionState;

	
	if (s->childXids != NULL)
		pfree(s->childXids);
	s->childXids = NULL;
	s->nChildXids = 0;
	s->maxChildXids = 0;

	
}




static void AtCleanup_Memory(void)
{
	Assert(CurrentTransactionState->parent == NULL);

	
	MemoryContextSwitchTo(TopMemoryContext);

	
	if (TransactionAbortContext != NULL)
		MemoryContextResetAndDeleteChildren(TransactionAbortContext);

	
	if (TopTransactionContext != NULL)
		MemoryContextDelete(TopTransactionContext);
	TopTransactionContext = NULL;
	CurTransactionContext = NULL;
	CurrentTransactionState->curTransactionContext = NULL;
}





static void AtSubCleanup_Memory(void)
{
	TransactionState s = CurrentTransactionState;

	Assert(s->parent != NULL);

	
	MemoryContextSwitchTo(s->parent->curTransactionContext);
	CurTransactionContext = s->parent->curTransactionContext;

	
	if (TransactionAbortContext != NULL)
		MemoryContextResetAndDeleteChildren(TransactionAbortContext);

	
	if (s->curTransactionContext)
		MemoryContextDelete(s->curTransactionContext);
	s->curTransactionContext = NULL;
}



void SetSharedTransactionId_writer(DtxContext distributedTransactionContext)
{
	Assert(SharedLocalSnapshotSlot != NULL);
	Assert(LWLockHeldByMe(SharedLocalSnapshotSlot->slotLock));

	Assert(distributedTransactionContext == DTX_CONTEXT_QD_DISTRIBUTED_CAPABLE || distributedTransactionContext == DTX_CONTEXT_QE_TWO_PHASE_EXPLICIT_WRITER || distributedTransactionContext == DTX_CONTEXT_QE_TWO_PHASE_IMPLICIT_WRITER || distributedTransactionContext == DTX_CONTEXT_QE_AUTO_COMMIT_IMPLICIT);



	ereportif(Debug_print_full_dtm, LOG, (errmsg("%s setting shared xid " UINT64_FORMAT " -> " UINT64_FORMAT, DtxContextToString(distributedTransactionContext), U64FromFullTransactionId(SharedLocalSnapshotSlot->fullXid), U64FromFullTransactionId(TopTransactionStateData.fullTransactionId))));



	SharedLocalSnapshotSlot->fullXid = TopTransactionStateData.fullTransactionId;
}

void SetSharedTransactionId_reader(FullTransactionId xid, CommandId cid, DtxContext distributedTransactionContext)
{
	Assert(distributedTransactionContext == DTX_CONTEXT_QE_READER || distributedTransactionContext == DTX_CONTEXT_QE_ENTRY_DB_SINGLETON);

	
	TopTransactionStateData.fullTransactionId = xid;
	currentCommandId = cid;
	ereportif(Debug_print_full_dtm, LOG, (errmsg("qExec READER setting local xid= " UINT64_FORMAT ", cid=%u " "(distributedXid "UINT64_FORMAT"/%u)", U64FromFullTransactionId(TopTransactionStateData.fullTransactionId), currentCommandId, QEDtxContextInfo.distributedXid, QEDtxContextInfo.segmateSync)));




}


static void StartTransaction(void)
{
	TransactionState s;
	VirtualTransactionId vxid;

	if (DistributedTransactionContext == DTX_CONTEXT_QE_ENTRY_DB_SINGLETON)
	{
		SIMPLE_FAULT_INJECTOR("transaction_start_under_entry_db_singleton");
	}

	
	s = &TopTransactionStateData;
	CurrentTransactionState = s;

	Assert(!FullTransactionIdIsValid(XactTopFullTransactionId));

	
	Assert(s->state == TRANS_DEFAULT);

	
	s->state = TRANS_START;
	s->fullTransactionId = InvalidFullTransactionId;	

	
	xact_is_sampled = log_xact_sample_rate != 0 && (log_xact_sample_rate == 1 || random() <= log_xact_sample_rate * MAX_RANDOM_VALUE);


	
	s->nestingLevel = 1;
	s->gucNestLevel = 1;
	s->childXids = NULL;
	s->nChildXids = 0;
	s->maxChildXids = 0;

	
	GetUserIdAndSecContext(&s->prevUser, &s->prevSecContext);

	
	Assert(s->prevSecContext == 0);

	
	if (RecoveryInProgress())
	{
		s->startedInRecovery = true;
		XactReadOnly = true;
	}
	else {
		s->startedInRecovery = false;
		XactReadOnly = DefaultXactReadOnly;
	}
	XactDeferrable = DefaultXactDeferrable;
	XactIsoLevel = DefaultXactIsoLevel;
	forceSyncCommit = false;
	seqXlogWrite = false;
	MyXactFlags = 0;

	
	s->subTransactionId = TopSubTransactionId;
	currentSubTransactionId = TopSubTransactionId;
	currentCommandId = FirstCommandId;
	currentCommandIdUsed = false;
	currentSavepointTotal = 0;

	fastNodeCount = 0;
	previousFastLink = NULL;

	
	nUnreportedXids = 0;
	s->didLogXid = false;
	TopXactexecutorDidWriteXLog = false;

	
	AtStart_Memory();
	AtStart_ResourceOwner();

	
	AssertImply(DistributedTransactionContext != DTX_CONTEXT_LOCAL_ONLY, !s->startedInRecovery);
	
	switch (DistributedTransactionContext)
	{
		case DTX_CONTEXT_LOCAL_ONLY:
		case DTX_CONTEXT_QD_RETRY_PHASE_2:
		case DTX_CONTEXT_QE_FINISH_PREPARED:
		{
			if (DistributedTransactionContext == DTX_CONTEXT_LOCAL_ONLY && Gp_role == GP_ROLE_UTILITY)
			{
				LocalDistribXactData *ele = &MyProc->localDistribXactData;
				ele->state = LOCALDISTRIBXACT_STATE_ACTIVE;
			}
			
		}
		break;

		case DTX_CONTEXT_QD_DISTRIBUTED_CAPABLE:
		{
			if (SharedLocalSnapshotSlot != NULL)
			{
				LWLockAcquire(SharedLocalSnapshotSlot->slotLock, LW_EXCLUSIVE);
				ereportif(Debug_print_full_dtm, LOG, (errmsg("setting shared snapshot startTimestamp = " INT64_FORMAT "[old=" INT64_FORMAT "])", stmtStartTimestamp, SharedLocalSnapshotSlot->startTimestamp)));



				SharedLocalSnapshotSlot->startTimestamp = stmtStartTimestamp;
				LWLockRelease(SharedLocalSnapshotSlot->slotLock);
			}
			LocalDistribXactData *ele = &MyProc->localDistribXactData;
			ele->state = LOCALDISTRIBXACT_STATE_ACTIVE;
		}
		break;

		case DTX_CONTEXT_QE_TWO_PHASE_EXPLICIT_WRITER:
		case DTX_CONTEXT_QE_TWO_PHASE_IMPLICIT_WRITER:
		case DTX_CONTEXT_QE_AUTO_COMMIT_IMPLICIT:
		{
			
			if (gp_enable_slow_writer_testmode)
				pg_usleep(500000);

			if (DistributedTransactionContext != DTX_CONTEXT_QE_AUTO_COMMIT_IMPLICIT && QEDtxContextInfo.distributedXid == InvalidDistributedTransactionId)
			{
				elog(ERROR, "distributed transaction id is invalid in context %s", DtxContextToString(DistributedTransactionContext));

			}

			
			Assert(!FirstSnapshotSet);

			
			XactIsoLevel = mppTxOptions_IsoLevel( QEDtxContextInfo.distributedTxnOptions);
			XactReadOnly = isMppTxOptions_ReadOnly( QEDtxContextInfo.distributedTxnOptions);

			
			MyTmGxact->gxid = QEDtxContextInfo.distributedXid;

			if (DistributedTransactionContext == DTX_CONTEXT_QE_TWO_PHASE_EXPLICIT_WRITER || DistributedTransactionContext == DTX_CONTEXT_QE_TWO_PHASE_IMPLICIT_WRITER)


			{
				Assert(QEDtxContextInfo.distributedXid != InvalidDistributedTransactionId);

				
				LocalDistribXactData *ele = &MyProc->localDistribXactData;
				ele->distribXid = QEDtxContextInfo.distributedXid;
				ele->state = LOCALDISTRIBXACT_STATE_ACTIVE;
			}

			if (SharedLocalSnapshotSlot != NULL)
			{
				LWLockAcquire(SharedLocalSnapshotSlot->slotLock, LW_EXCLUSIVE);

				SharedLocalSnapshotSlot->ready = false;
				SharedLocalSnapshotSlot->fullXid = s->fullTransactionId;
				SharedLocalSnapshotSlot->startTimestamp = stmtStartTimestamp;
				SharedLocalSnapshotSlot->distributedXid = QEDtxContextInfo.distributedXid;
				SharedLocalSnapshotSlot->writer_proc = MyProc;
				SharedLocalSnapshotSlot->writer_xact = MyPgXact;

				ereportif(Debug_print_full_dtm, LOG, (errmsg( "qExec writer setting distributedXid: "UINT64_FORMAT " sharedQDxid (shared xid " UINT64_FORMAT " -> " UINT64_FORMAT ") ready %s" " (shared timeStamp = " INT64_FORMAT " -> " INT64_FORMAT ")", SharedLocalSnapshotSlot->distributedXid, U64FromFullTransactionId(SharedLocalSnapshotSlot->fullXid), U64FromFullTransactionId(s->fullTransactionId), SharedLocalSnapshotSlot->ready ? "true" : "false", SharedLocalSnapshotSlot->startTimestamp, xactStartTimestamp)));










				LWLockRelease(SharedLocalSnapshotSlot->slotLock);
			}
		}
		break;

		case DTX_CONTEXT_QE_ENTRY_DB_SINGLETON:
		case DTX_CONTEXT_QE_READER:
		{
			
			Assert (SharedLocalSnapshotSlot != NULL);
			MyTmGxact->gxid = QEDtxContextInfo.distributedXid;

			
			Assert(!FirstSnapshotSet);

			
			XactIsoLevel = mppTxOptions_IsoLevel( QEDtxContextInfo.distributedTxnOptions);
			XactReadOnly = isMppTxOptions_ReadOnly( QEDtxContextInfo.distributedTxnOptions);

			if (unlikely(Debug_print_full_dtm))
			{
				LWLockAcquire(SharedSnapshotLock, LW_SHARED); 
				ereport(LOG, (errmsg("qExec reader: distributedXid "UINT64_FORMAT" currcid %d " "gxid = "UINT64_FORMAT" DtxContext '%s' sharedsnapshots: %s", QEDtxContextInfo.distributedXid, QEDtxContextInfo.curcid, getDistributedTransactionId(), DtxContextToString(DistributedTransactionContext), SharedSnapshotDump())));





				LWLockRelease(SharedSnapshotLock);
			}
		}
		break;

		case DTX_CONTEXT_QE_PREPARED:
			elog(FATAL, "Unexpected segment distribute transaction context: '%s'", DtxContextToString(DistributedTransactionContext));
			break;

		default:
			elog(PANIC, "Unrecognized DTX transaction context: %d", (int) DistributedTransactionContext);
			break;
	}

	ereportif(Debug_print_snapshot_dtm, LOG, (errmsg("[Distributed Snapshot #%u] *StartTransaction* " "(gxid = "UINT64_FORMAT", xid = " UINT64_FORMAT ", '%s')", (!FirstSnapshotSet ? 0 :


					   GetTransactionSnapshot()-> distribSnapshotWithLocalMapping.ds.distribSnapshotId), getDistributedTransactionId(), U64FromFullTransactionId(s->fullTransactionId), DtxContextToString(DistributedTransactionContext))));




	
	vxid.backendId = MyBackendId;
	vxid.localTransactionId = GetNextLocalTransactionId();

	
	VirtualXactLockTableInsert(vxid);

	
	Assert(MyProc->backendId == vxid.backendId);
	MyProc->lxid = vxid.localTransactionId;

	TRACE_POSTGRESQL_TRANSACTION_START(vxid.localTransactionId);

	
	if (!IsParallelWorker())
	{
		if (!SPI_inside_nonatomic_context())
			xactStartTimestamp = stmtStartTimestamp;
		else xactStartTimestamp = GetCurrentTimestamp();
	}
	else Assert(xactStartTimestamp != 0);
	pgstat_report_xact_timestamp(xactStartTimestamp);
	
	xactStopTimestamp = 0;

	
	AtStart_GUC();
	AtStart_Cache();
	AfterTriggerBeginXact();

	
	s->state = TRANS_INPROGRESS;

	
	if (Gp_role == GP_ROLE_DISPATCH && OidIsValid(MyDatabaseId))
		cdbcomponent_updateCdbComponents();

	
	if (ShouldAssignResGroupOnMaster())
		AssignResGroupOnMaster();

	initialize_wal_bytes_written();
	ShowTransactionState("StartTransaction");

	ereportif(Debug_print_full_dtm, LOG, (errmsg("StartTransaction in DTX Context = '%s', " "isolation level %s, read-only = %d, %s", DtxContextToString(DistributedTransactionContext), IsoLevelAsUpperString(XactIsoLevel), XactReadOnly, LocalDistribXact_DisplayString(MyProc->pgprocno))));




}


static void CommitTransaction(void)
{
	TransactionState s = CurrentTransactionState;
	TransactionId latestXid;
	bool		is_parallel_worker;

	is_parallel_worker = (s->blockState == TBLOCK_PARALLEL_INPROGRESS);

	
	if (is_parallel_worker)
		EnterParallelMode();

	ShowTransactionState("CommitTransaction");

	
	if (s->state != TRANS_INPROGRESS)
		elog(WARNING, "CommitTransaction while in %s state", TransStateAsString(s->state));
	Assert(s->parent == NULL);

	if (Gp_role == GP_ROLE_EXECUTE && !Gp_is_writer)
		elog(DEBUG1,"CommitTransaction: called as segment Reader");

	
	for (;;)
	{
		
		AfterTriggerFireDeferred();

		
		if (!PreCommit_Portals(false))
			break;
	}

	CallXactCallbacks(is_parallel_worker ? XACT_EVENT_PARALLEL_PRE_COMMIT : XACT_EVENT_PRE_COMMIT);

	

	
	if (IsInParallelMode())
		AtEOXact_Parallel(true);

	
	AfterTriggerEndXact(true);

	AtEOXact_SharedSnapshot();

	
	if (Gp_role == GP_ROLE_DISPATCH && IsResQueueEnabled())
		AtCommit_ResScheduler();

	
	PreCommit_on_commit_actions();

	
	AtEOXact_DispatchOids(true);

	
	AtEOXact_LargeObject(true);

	
	if (!is_parallel_worker)
		PreCommit_CheckForSerializationFailure();

	
	PreCommit_Notify();

	
	prepareDtxTransaction();


	if (isPreparedDtxTransaction())
	{
		FaultInjector_InjectFaultIfSet( "transaction_abort_after_distributed_prepared", DDLNotSpecified, "", "");



	}


	if (Debug_abort_after_distributed_prepared && isPreparedDtxTransaction())
	{
		ereport(ERROR, (errcode(ERRCODE_FAULT_INJECT), errmsg("Raise an error as directed by Debug_abort_after_distributed_prepared")));

	}

	
	HOLD_INTERRUPTS();

	
	AtEOXact_RelationMap(true, is_parallel_worker);

	
	s->state = TRANS_COMMIT;
	s->parallelModeLevel = 0;

	if (!is_parallel_worker)
	{
		
		latestXid = RecordTransactionCommit();
	}
	else {
		
		latestXid = InvalidTransactionId;

		
		ParallelWorkerReportLastRecEnd(XactLastRecEnd);
	}

	TRACE_POSTGRESQL_TRANSACTION_COMMIT(MyProc->lxid);

	
	if (notifyCommittedDtxTransactionIsNeeded())
		notifyCommittedDtxTransaction();

	
	ProcArrayEndTransaction(MyProc, latestXid);

	EndLocalDistribXact(true);

	

	CallXactCallbacks(is_parallel_worker ? XACT_EVENT_PARALLEL_COMMIT : XACT_EVENT_COMMIT);
	CallXactCallbacksOnce(XACT_EVENT_COMMIT);

	ResourceOwnerRelease(TopTransactionResourceOwner, RESOURCE_RELEASE_BEFORE_LOCKS, true, true);


	
	AtEOXact_ComboCid_Dsm_Detach();

	
	AtEOXact_Buffers(true);

	
	AtEOXact_RelationCache(true);

	
	AtEOXact_Inval(true);

	AtEOXact_MultiXact();

	ResourceOwnerRelease(TopTransactionResourceOwner, RESOURCE_RELEASE_LOCKS, true, true);

	ResourceOwnerRelease(TopTransactionResourceOwner, RESOURCE_RELEASE_AFTER_LOCKS, true, true);


	
	smgrDoPendingDeletes(true);
	DoPendingDbDeletes(true);

	
	if(Gp_role == GP_ROLE_DISPATCH)
		MoveDbSessionLockRelease();

	AtCommit_TablespaceStorage();

	AtCommit_Notify();
	AtEOXact_GUC(true, 1);
	AtEOXact_SPI(true);
	AtEOXact_Enum();
	AtEOXact_on_commit_actions(true);
	AtEOXact_Namespace(true, is_parallel_worker);
	AtEOXact_SMgr();
	AtEOXact_Files(true);
	AtEOXact_ComboCid();
	AtEOXact_HashTables(true);
	AtEOXact_PgStat(true, is_parallel_worker);
	AtEOXact_Snapshot(true, false);
	AtEOXact_ApplyLauncher(true);
	AtEOXact_WorkFile();
	pgstat_report_xact_timestamp(0);

	CurrentResourceOwner = NULL;
	ResourceOwnerDelete(TopTransactionResourceOwner);
	s->curTransactionOwner = NULL;
	CurTransactionResourceOwner = NULL;
	TopTransactionResourceOwner = NULL;

	AtCommit_Memory();

	finishDistributedTransactionContext("CommitTransaction", false);

	if (gp_local_distributed_cache_stats)
	{
		LocalDistribXactCache_ShowStats("CommitTransaction");
	}

	s->fullTransactionId = InvalidFullTransactionId;
	s->subTransactionId = InvalidSubTransactionId;
	s->nestingLevel = 0;
	s->gucNestLevel = 0;
	s->childXids = NULL;
	s->nChildXids = 0;
	s->maxChildXids = 0;
	s->executorSaysXactDoesWrites = false;

	XactTopFullTransactionId = InvalidFullTransactionId;
	nParallelCurrentXids = 0;

	
	s->state = TRANS_DEFAULT;

	
	RESUME_INTERRUPTS();

	
	if (ShouldUnassignResGroup())
		UnassignResGroup(false);
}


static void PrepareTransaction(void)
{
	TransactionState s = CurrentTransactionState;
	TransactionId xid = GetCurrentTransactionId();
	GlobalTransaction gxact;
	TimestampTz prepared_at;

	Assert(!IsInParallelMode());

	ShowTransactionState("PrepareTransaction");

	
	if (s->state != TRANS_INPROGRESS)
		elog(WARNING, "PrepareTransaction while in %s state", TransStateAsString(s->state));
	Assert(s->parent == NULL);

	
	for (;;)
	{
		
		AfterTriggerFireDeferred();

		
		if (!PreCommit_Portals(true))
			break;
	}

	CallXactCallbacks(XACT_EVENT_PRE_PREPARE);

	

	
	AfterTriggerEndXact(true);

	
	PreCommit_on_commit_actions();

	AtEOXact_DispatchOids(true);

	
	AtEOXact_LargeObject(true);

	
	PreCommit_CheckForSerializationFailure();

	

	

	
	if ((MyXactFlags & XACT_FLAGS_ACCESSEDTEMPNAMESPACE))
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot PREPARE a transaction that has operated on temporary objects")));


	SIMPLE_FAULT_INJECTOR("start_prepare");

	
	if (XactHasExportedSnapshots())
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot PREPARE a transaction that has exported snapshots")));


	
	if (XactManipulatesLogicalReplicationWorkers())
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot PREPARE a transaction that has manipulated logical replication workers")));


	
	HOLD_INTERRUPTS();

	
	PrePrepare_Locks();

	
	s->state = TRANS_PREPARE;

	prepared_at = GetCurrentTimestamp();

	
	BufmgrCommit();

	
	if (TransactionIdDidAbort(xid))
		elog(ERROR, "xid %u is already aborted", xid);

	
	gxact = MarkAsPreparing(xid, &MyProc->localDistribXactData, prepareGID, prepared_at, GetUserId(), MyDatabaseId);

	prepareGID = NULL;

	
	StartPrepare(gxact);

	AtPrepare_Notify();
	AtPrepare_Locks();
	AtPrepare_PredicateLocks();
	AtPrepare_PgStat();
	AtPrepare_MultiXact();
	AtPrepare_RelationMap();

	
	EndPrepare(gxact);

	

	
	XactLastRecEnd = 0;

	
	LWLockAcquire(ProcArrayLock, LW_EXCLUSIVE);
	ProcArrayClearTransaction(MyProc);
	LWLockRelease(ProcArrayLock);

	

	CallXactCallbacks(XACT_EVENT_PREPARE);
	CallXactCallbacksOnce(XACT_EVENT_PREPARE);

	ResourceOwnerRelease(TopTransactionResourceOwner, RESOURCE_RELEASE_BEFORE_LOCKS, true, true);


	
	AtEOXact_ComboCid_Dsm_Detach();
	
	AtEOXact_Buffers(true);

	
	AtEOXact_RelationCache(true);

	

	PostPrepare_PgStat();

	PostPrepare_Inval();

	PostPrepare_smgr();

	PostPrepare_DatabaseStorage();

	PostPrepare_MultiXact(xid);

	PostPrepare_Locks(xid);
	PostPrepare_PredicateLocks(xid);

	ResourceOwnerRelease(TopTransactionResourceOwner, RESOURCE_RELEASE_LOCKS, true, true);

	ResourceOwnerRelease(TopTransactionResourceOwner, RESOURCE_RELEASE_AFTER_LOCKS, true, true);


	
	PostPrepare_Twophase();

	
	AtEOXact_GUC(true, 1);
	AtEOXact_SPI(true);
	AtEOXact_Enum();
	AtEOXact_on_commit_actions(true);
	AtEOXact_Namespace(true, false);
	AtEOXact_SMgr();
	AtEOXact_Files(true);
	AtEOXact_ComboCid();
	AtEOXact_HashTables(true);
	
	AtEOXact_Snapshot(true, true);
	AtEOXact_WorkFile();
	pgstat_report_xact_timestamp(0);

	CurrentResourceOwner = NULL;
	ResourceOwnerDelete(TopTransactionResourceOwner);
	s->curTransactionOwner = NULL;
	CurTransactionResourceOwner = NULL;
	TopTransactionResourceOwner = NULL;

	AtCommit_Memory();

	if (gp_local_distributed_cache_stats)
	{
		LocalDistribXactCache_ShowStats("PrepareTransaction");
	}

	s->fullTransactionId = InvalidFullTransactionId;
	s->subTransactionId = InvalidSubTransactionId;
	s->nestingLevel = 0;
	s->gucNestLevel = 0;
	s->childXids = NULL;
	s->nChildXids = 0;
	s->maxChildXids = 0;
	s->executorSaysXactDoesWrites = false;

	XactTopFullTransactionId = InvalidFullTransactionId;
	nParallelCurrentXids = 0;

	
	s->state = TRANS_DEFAULT;

	RESUME_INTERRUPTS();

	
	if (ShouldUnassignResGroup())
		UnassignResGroup(false);
}



static void AbortTransaction(void)
{
	TransactionState s = CurrentTransactionState;
	TransactionId latestXid;
	bool		is_parallel_worker;

	SIMPLE_FAULT_INJECTOR("transaction_abort_failure");

	
	HOLD_INTERRUPTS();

	
	AtAbort_Memory();
	AtAbort_ResourceOwner();

	
	LWLockReleaseAll();

	
	pgstat_report_wait_end();
	pgstat_progress_end_command();

	
	AbortBufferIO();
	UnlockBuffers();

	
	XLogResetInsertion();

	
	ConditionVariableCancelSleep();

	
	LockErrorCleanup();

	
	reschedule_timeouts();

	
	PG_SETMASK(&UnBlockSig);

	
	is_parallel_worker = (s->blockState == TBLOCK_PARALLEL_INPROGRESS);
	if (s->state != TRANS_INPROGRESS && s->state != TRANS_PREPARE)
		elog(DEBUG1, "WARNING: AbortTransaction while in %s state", TransStateAsString(s->state));
	Assert(s->parent == NULL);

	
	s->state = TRANS_ABORT;

	
	SetUserIdAndSecContext(s->prevUser, s->prevSecContext);

	
	if (IsInParallelMode())
	{
		AtEOXact_Parallel(false);
		s->parallelModeLevel = 0;
	}

	
	AfterTriggerEndXact(false); 
	AtAbort_Portals();
	AtAbort_DispatcherState();
	AtEOXact_SharedSnapshot();

	
	if (Gp_role == GP_ROLE_DISPATCH && IsResQueueEnabled())
		AtAbort_ResScheduler();

	AtEOXact_DispatchOids(false);

	AtEOXact_LargeObject(false);
	AtAbort_Notify();
	AtEOXact_RelationMap(false, is_parallel_worker);
	AtAbort_Twophase();

	
	if (!is_parallel_worker)
		latestXid = RecordTransactionAbort(false);
	else {
		latestXid = InvalidTransactionId;

		
		XLogSetAsyncXactLSN(XactLastRecEnd);
	}

	TRACE_POSTGRESQL_TRANSACTION_ABORT(MyProc->lxid);

	
	rollbackDtxTransaction();

	
	ProcArrayEndTransaction(MyProc, latestXid);

	EndLocalDistribXact(false);

	SIMPLE_FAULT_INJECTOR("abort_after_procarray_end");
	
	if (TopTransactionResourceOwner != NULL)
	{
		if (is_parallel_worker)
			CallXactCallbacks(XACT_EVENT_PARALLEL_ABORT);
		else CallXactCallbacks(XACT_EVENT_ABORT);
		CallXactCallbacksOnce(XACT_EVENT_ABORT);

		ResourceOwnerRelease(TopTransactionResourceOwner, RESOURCE_RELEASE_BEFORE_LOCKS, false, true);

		AtEOXact_ComboCid_Dsm_Detach();
		AtEOXact_Buffers(false);
		AtEOXact_RelationCache(false);
		AtEOXact_Inval(false);
		AtEOXact_MultiXact();

		ResourceOwnerRelease(TopTransactionResourceOwner, RESOURCE_RELEASE_LOCKS, false, true);

		ResourceOwnerRelease(TopTransactionResourceOwner, RESOURCE_RELEASE_AFTER_LOCKS, false, true);

		smgrDoPendingDeletes(false);

		DoPendingDbDeletes(false);
		DatabaseStorageResetSessionLock();

		AtAbort_TablespaceStorage();
		gp_guc_need_restore = true;
		AtEOXact_GUC(false, 1);
		gp_guc_need_restore = false;
		AtEOXact_SPI(false);
		AtEOXact_Enum();
		AtEOXact_on_commit_actions(false);
		AtEOXact_Namespace(false, is_parallel_worker);
		AtEOXact_SMgr();
		AtEOXact_Files(false);
		AtEOXact_ComboCid();
		AtEOXact_HashTables(false);
		AtEOXact_PgStat(false, is_parallel_worker);
		AtEOXact_ApplyLauncher(false);
		AtEOXact_WorkFile();
		pgstat_report_xact_timestamp(0);
	}

	
	AtEOXact_Snapshot(false, true);	

	
	TopTransactionStateData.fullTransactionId = InvalidFullTransactionId;
	MyProc->localDistribXactData.state = LOCALDISTRIBXACT_STATE_NONE;

	
	RESUME_INTERRUPTS();

	
	if (QueryCancelCleanup)
	{
		QueryCancelCleanup = false;
		cdbcomponent_cleanupIdleQEs(false);
	}

	
	if (elog_geterrcode() == ERRCODE_GP_MEMPROT_KILL)
		DisconnectAndDestroyAllGangs(true);

	
	if (ShouldUnassignResGroup())
		UnassignResGroup(false);
}


static void CleanupTransaction(void)
{
	TransactionState s = CurrentTransactionState;

	
	if (s->state != TRANS_ABORT)
		elog(FATAL, "CleanupTransaction: unexpected state %s", TransStateAsString(s->state));

	
	AtCleanup_Portals();		
	AtEOXact_Snapshot(false, true); 

	CurrentResourceOwner = NULL;	
	if (TopTransactionResourceOwner)
		ResourceOwnerDelete(TopTransactionResourceOwner);
	s->curTransactionOwner = NULL;
	CurTransactionResourceOwner = NULL;
	TopTransactionResourceOwner = NULL;

	AtCleanup_Memory();			

	s->fullTransactionId = InvalidFullTransactionId;
	s->subTransactionId = InvalidSubTransactionId;
	s->nestingLevel = 0;
	s->gucNestLevel = 0;
	s->childXids = NULL;
	s->nChildXids = 0;
	s->maxChildXids = 0;
	s->parallelModeLevel = 0;
	s->executorSaysXactDoesWrites = false;

	XactTopFullTransactionId = InvalidFullTransactionId;
	nParallelCurrentXids = 0;

	
	s->state = TRANS_DEFAULT;

	finishDistributedTransactionContext("CleanupTransaction", true);

	
	if (ShouldUnassignResGroup())
		UnassignResGroup(false);
}


void StartTransactionCommand(void)
{
	if (Gp_role == GP_ROLE_DISPATCH)
		setupRegularDtxContext();

	TransactionState s = CurrentTransactionState;

	switch (s->blockState)
	{
			
		case TBLOCK_DEFAULT:
			StartTransaction();

			if (DistributedTransactionContext == DTX_CONTEXT_QE_TWO_PHASE_IMPLICIT_WRITER)
			{
				
				s->blockState = TBLOCK_INPROGRESS;
			}
			else {
				
				s->blockState = TBLOCK_STARTED;
			}
			break;

			
		case TBLOCK_INPROGRESS:
		case TBLOCK_IMPLICIT_INPROGRESS:
		case TBLOCK_SUBINPROGRESS:
			
			if (Gp_role == GP_ROLE_EXECUTE && Gp_is_writer && SharedLocalSnapshotSlot != NULL)
			{
				LWLockAcquire(SharedLocalSnapshotSlot->slotLock, LW_EXCLUSIVE);

				FullTransactionId oldFullXid = SharedLocalSnapshotSlot->fullXid;
				TimestampTz oldStartTimestamp = SharedLocalSnapshotSlot->startTimestamp;

				
				if (FullTransactionIdIsValid(s->fullTransactionId))
				{
					SharedLocalSnapshotSlot->fullXid = s->fullTransactionId;
				}

				SharedLocalSnapshotSlot->startTimestamp = xactStartTimestamp;
				SharedLocalSnapshotSlot->distributedXid = QEDtxContextInfo.distributedXid;

				LWLockRelease(SharedLocalSnapshotSlot->slotLock);

				ereportif(Debug_print_full_dtm, LOG, (errmsg("qExec WRITER updating shared xid: " UINT64_FORMAT " -> " UINT64_FORMAT " " "(StartTransactionCommand) timestamp: " INT64_FORMAT " -> " INT64_FORMAT ")", U64FromFullTransactionId(oldFullXid), U64FromFullTransactionId(s->fullTransactionId), oldStartTimestamp, xactStartTimestamp)));





			}
			break;

			
		case TBLOCK_ABORT:
		case TBLOCK_SUBABORT:
			break;

			
		case TBLOCK_STARTED:
		case TBLOCK_BEGIN:
		case TBLOCK_PARALLEL_INPROGRESS:
		case TBLOCK_SUBBEGIN:
		case TBLOCK_END:
		case TBLOCK_SUBRELEASE:
		case TBLOCK_SUBCOMMIT:
		case TBLOCK_ABORT_END:
		case TBLOCK_SUBABORT_END:
		case TBLOCK_ABORT_PENDING:
		case TBLOCK_SUBABORT_PENDING:
		case TBLOCK_SUBRESTART:
		case TBLOCK_SUBABORT_RESTART:
		case TBLOCK_PREPARE:
			elog(ERROR, "StartTransactionCommand: unexpected state %s", BlockStateAsString(s->blockState));
			break;
	}

	
	Assert(CurTransactionContext != NULL);
	MemoryContextSwitchTo(CurTransactionContext);
}



static int	save_XactIsoLevel;
static bool save_XactReadOnly;
static bool save_XactDeferrable;

void SaveTransactionCharacteristics(void)
{
	save_XactIsoLevel = XactIsoLevel;
	save_XactReadOnly = XactReadOnly;
	save_XactDeferrable = XactDeferrable;
}

void RestoreTransactionCharacteristics(void)
{
	XactIsoLevel = save_XactIsoLevel;
	XactReadOnly = save_XactReadOnly;
	XactDeferrable = save_XactDeferrable;
}



void CommitTransactionCommand(void)
{
	TransactionState s = CurrentTransactionState;

	if (Gp_role == GP_ROLE_EXECUTE && !Gp_is_writer)
		elog(DEBUG1,"CommitTransactionCommand: called as segment Reader in state %s", BlockStateAsString(s->blockState));

	if (s->chain)
		SaveTransactionCharacteristics();

	switch (s->blockState)
	{
			
		case TBLOCK_DEFAULT:
		case TBLOCK_PARALLEL_INPROGRESS:
			elog(FATAL, "CommitTransactionCommand: unexpected state %s", BlockStateAsString(s->blockState));
			break;

			
		case TBLOCK_STARTED:
			CommitTransaction();
			s->blockState = TBLOCK_DEFAULT;
			break;

			
		case TBLOCK_BEGIN:
			s->blockState = TBLOCK_INPROGRESS;
			break;

			
		case TBLOCK_INPROGRESS:
		case TBLOCK_IMPLICIT_INPROGRESS:
		case TBLOCK_SUBINPROGRESS:
			CommandCounterIncrement();
			break;

			
		case TBLOCK_END:
			CommitTransaction();
			s->blockState = TBLOCK_DEFAULT;
			if (s->chain)
			{
				StartTransaction();
				s->blockState = TBLOCK_INPROGRESS;
				s->chain = false;
				RestoreTransactionCharacteristics();
			}
			break;

			
		case TBLOCK_ABORT:
		case TBLOCK_SUBABORT:
			break;

			
		case TBLOCK_ABORT_END:
			CleanupTransaction();
			s->blockState = TBLOCK_DEFAULT;
			if (s->chain)
			{
				StartTransaction();
				s->blockState = TBLOCK_INPROGRESS;
				s->chain = false;
				RestoreTransactionCharacteristics();
			}
			break;

			
		case TBLOCK_ABORT_PENDING:
			AbortTransaction();
			CleanupTransaction();
			s->blockState = TBLOCK_DEFAULT;
			if (s->chain)
			{
				StartTransaction();
				s->blockState = TBLOCK_INPROGRESS;
				s->chain = false;
				RestoreTransactionCharacteristics();
			}
			break;

			
		case TBLOCK_PREPARE:
			PrepareTransaction();
			s->blockState = TBLOCK_DEFAULT;
			break;

			
		case TBLOCK_SUBBEGIN:
			StartSubTransaction();
			s->blockState = TBLOCK_SUBINPROGRESS;
			break;

			
		case TBLOCK_SUBRELEASE:
			do {
				CommitSubTransaction();
				s = CurrentTransactionState;	
			} while (s->blockState == TBLOCK_SUBRELEASE);

			Assert(s->blockState == TBLOCK_INPROGRESS || s->blockState == TBLOCK_SUBINPROGRESS);
			break;

			
		case TBLOCK_SUBCOMMIT:
			do {
				CommitSubTransaction();
				s = CurrentTransactionState;	
			} while (s->blockState == TBLOCK_SUBCOMMIT);
			
			if (s->blockState == TBLOCK_END)
			{
				Assert(s->parent == NULL);
				CommitTransaction();
				s->blockState = TBLOCK_DEFAULT;
			}
			else if (s->blockState == TBLOCK_PREPARE)
			{
				Assert(s->parent == NULL);
				PrepareTransaction();
				s->blockState = TBLOCK_DEFAULT;
			}
			else elog(ERROR, "CommitTransactionCommand: unexpected state %s", BlockStateAsString(s->blockState));

			break;

			
		case TBLOCK_SUBABORT_END:
			CleanupSubTransaction();
			CommitTransactionCommand();
			break;

			
		case TBLOCK_SUBABORT_PENDING:
			AbortSubTransaction();
			CleanupSubTransaction();
			CommitTransactionCommand();
			break;

			
		case TBLOCK_SUBRESTART:
			{
				char	   *name;
				int			savepointLevel;

				
				name = s->name;
				s->name = NULL;
				savepointLevel = s->savepointLevel;

				AbortSubTransaction();
				CleanupSubTransaction();

				if (Gp_role == GP_ROLE_DISPATCH)
				{
					DispatchRollbackToSavepoint(name);
				}

				DefineSavepoint(name);
				s = CurrentTransactionState;	
				if (name)
				{
					pfree(name);
				}
				s->savepointLevel = savepointLevel;

				
				AssertState(s->blockState == TBLOCK_SUBBEGIN);
				StartSubTransaction();
				s->blockState = TBLOCK_SUBINPROGRESS;
			}
			break;

			
		case TBLOCK_SUBABORT_RESTART:
			{
				char	   *name;
				int			savepointLevel;

				
				name = s->name;
				s->name = NULL;
				savepointLevel = s->savepointLevel;

				CleanupSubTransaction();

				if (Gp_role == GP_ROLE_DISPATCH)
				{
					DispatchRollbackToSavepoint(name);
				}

				DefineSavepoint(name);
				s = CurrentTransactionState;	
				s->name = name;
				s->savepointLevel = savepointLevel;

				
				AssertState(s->blockState == TBLOCK_SUBBEGIN);
				StartSubTransaction();
				s->blockState = TBLOCK_SUBINPROGRESS;
			}
			break;
	}
}


void AbortCurrentTransaction(void)
{
	TransactionState s = CurrentTransactionState;

	elog(DEBUG5, "AbortCurrentTransaction for " UINT64_FORMAT " in state: %d", U64FromFullTransactionId(s->fullTransactionId), s->blockState);


	switch (s->blockState)
	{
		case TBLOCK_DEFAULT:
			if (s->state == TRANS_DEFAULT)
			{
				
			}
			else {
				
				if (s->state == TRANS_START)
					s->state = TRANS_INPROGRESS;
				AbortTransaction();
				CleanupTransaction();
			}
			break;

			
		case TBLOCK_STARTED:
		case TBLOCK_IMPLICIT_INPROGRESS:
			AbortTransaction();
			CleanupTransaction();
			s->blockState = TBLOCK_DEFAULT;
			break;

			
		case TBLOCK_BEGIN:
			AbortTransaction();
			CleanupTransaction();
			s->blockState = TBLOCK_DEFAULT;
			break;

			
		case TBLOCK_INPROGRESS:
		case TBLOCK_PARALLEL_INPROGRESS:
			AbortTransaction();
			s->blockState = TBLOCK_ABORT;
			
			break;

			
		case TBLOCK_END:
			AbortTransaction();
			CleanupTransaction();
			s->blockState = TBLOCK_DEFAULT;
			break;

			
		case TBLOCK_ABORT:
		case TBLOCK_SUBABORT:
			break;

			
		case TBLOCK_ABORT_END:
			CleanupTransaction();
			s->blockState = TBLOCK_DEFAULT;

			Assert(DistributedTransactionContext == DTX_CONTEXT_LOCAL_ONLY);
			break;

			
		case TBLOCK_ABORT_PENDING:
			AbortTransaction();
			CleanupTransaction();
			s->blockState = TBLOCK_DEFAULT;

			Assert(DistributedTransactionContext == DTX_CONTEXT_LOCAL_ONLY);
			break;

			
		case TBLOCK_PREPARE:
			AbortTransaction();
			CleanupTransaction();
			s->blockState = TBLOCK_DEFAULT;

			Assert(DistributedTransactionContext == DTX_CONTEXT_LOCAL_ONLY);
			break;

			
		case TBLOCK_SUBINPROGRESS:
			AbortSubTransaction();
			s->blockState = TBLOCK_SUBABORT;
			break;

			
		case TBLOCK_SUBBEGIN:
		case TBLOCK_SUBRELEASE:
		case TBLOCK_SUBCOMMIT:
		case TBLOCK_SUBABORT_PENDING:
		case TBLOCK_SUBRESTART:
			AbortSubTransaction();
			CleanupSubTransaction();
			AbortCurrentTransaction();
			break;

			
		case TBLOCK_SUBABORT_END:
		case TBLOCK_SUBABORT_RESTART:
			CleanupSubTransaction();
			AbortCurrentTransaction();
			break;
	}
}


void PreventInTransactionBlock(bool isTopLevel, const char *stmtType)
{
	
	if (IsTransactionBlock())
		ereport(ERROR, (errcode(ERRCODE_ACTIVE_SQL_TRANSACTION),  errmsg("%s cannot run inside a transaction block", stmtType)));




	
	if (IsSubTransaction())
		ereport(ERROR, (errcode(ERRCODE_ACTIVE_SQL_TRANSACTION),  errmsg("%s cannot run inside a subtransaction", stmtType)));




	
	if (!isTopLevel)
		ereport(ERROR, (errcode(ERRCODE_ACTIVE_SQL_TRANSACTION),  errmsg("%s cannot be executed from a function", stmtType)));



	
	if (CurrentTransactionState->blockState != TBLOCK_DEFAULT && CurrentTransactionState->blockState != TBLOCK_STARTED)
		elog(FATAL, "cannot prevent transaction chain");
	
}


void WarnNoTransactionBlock(bool isTopLevel, const char *stmtType)
{
	CheckTransactionBlock(isTopLevel, false, stmtType);
}

void RequireTransactionBlock(bool isTopLevel, const char *stmtType)
{
	CheckTransactionBlock(isTopLevel, true, stmtType);
}


static void CheckTransactionBlock(bool isTopLevel, bool throwError, const char *stmtType)
{
	
	if (IsTransactionBlock())
		return;

	
	if (IsSubTransaction())
		return;

	
	if (!isTopLevel)
		return;

	ereport(throwError ? ERROR : WARNING, (errcode(ERRCODE_NO_ACTIVE_SQL_TRANSACTION),  errmsg("%s can only be used in transaction blocks", stmtType)));



	return;
}


bool IsInTransactionBlock(bool isTopLevel)
{
	
	if (IsTransactionBlock())
		return true;

	if (IsSubTransaction())
		return true;

	if (!isTopLevel)
		return true;

	if (CurrentTransactionState->blockState != TBLOCK_DEFAULT && CurrentTransactionState->blockState != TBLOCK_STARTED)
		return true;

	return false;
}



void RegisterXactCallback(XactCallback callback, void *arg)
{
	XactCallbackItem *item;

	item = (XactCallbackItem *)
		MemoryContextAlloc(TopMemoryContext, sizeof(XactCallbackItem));
	item->callback = callback;
	item->arg = arg;
	item->next = Xact_callbacks;
	Xact_callbacks = item;
}

void UnregisterXactCallback(XactCallback callback, void *arg)
{
	XactCallbackItem *item;
	XactCallbackItem *prev;

	prev = NULL;
	for (item = Xact_callbacks; item; prev = item, item = item->next)
	{
		if (item->callback == callback && item->arg == arg)
		{
			if (prev)
				prev->next = item->next;
			else Xact_callbacks = item->next;
			pfree(item);
			break;
		}
	}
}

static void CallXactCallbacks(XactEvent event)
{
	XactCallbackItem *item;

	for (item = Xact_callbacks; item; item = item->next)
		item->callback(event, item->arg);
}


void RegisterXactCallbackOnce(XactCallback callback, void *arg)
{
	XactCallbackItem *item;

	item = (XactCallbackItem *)
		MemoryContextAlloc(TopMemoryContext, sizeof(XactCallbackItem));
	item->callback = callback;
	item->arg = arg;
	item->next = Xact_callbacks_once;
	Xact_callbacks_once = item;
}

void UnregisterXactCallbackOnce(XactCallback callback, void *arg)
{
	XactCallbackItem *item;
	XactCallbackItem *prev;

	prev = NULL;
	for (item = Xact_callbacks_once; item; prev = item, item = item->next)
	{
		if (item->callback == callback && item->arg == arg)
		{
			if (prev)
				prev->next = item->next;
			else Xact_callbacks_once = item->next;
			pfree(item);
			break;
		}
	}
}

static void CallXactCallbacksOnce(XactEvent event)
{
	
	if (event == XACT_EVENT_PREPARE)
		return;

	while(Xact_callbacks_once)
	{
		XactCallbackItem *next = Xact_callbacks_once->next;
		XactCallback callback=Xact_callbacks_once->callback;
		void*arg=Xact_callbacks_once->arg;
		pfree(Xact_callbacks_once);
		Xact_callbacks_once = next;
		callback(event,arg);
	}
}


void RegisterSubXactCallback(SubXactCallback callback, void *arg)
{
	SubXactCallbackItem *item;

	item = (SubXactCallbackItem *)
		MemoryContextAlloc(TopMemoryContext, sizeof(SubXactCallbackItem));
	item->callback = callback;
	item->arg = arg;
	item->next = SubXact_callbacks;
	SubXact_callbacks = item;
}

void UnregisterSubXactCallback(SubXactCallback callback, void *arg)
{
	SubXactCallbackItem *item;
	SubXactCallbackItem *prev;

	prev = NULL;
	for (item = SubXact_callbacks; item; prev = item, item = item->next)
	{
		if (item->callback == callback && item->arg == arg)
		{
			if (prev)
				prev->next = item->next;
			else SubXact_callbacks = item->next;
			pfree(item);
			break;
		}
	}
}

static void CallSubXactCallbacks(SubXactEvent event, SubTransactionId mySubid, SubTransactionId parentSubid)


{
	SubXactCallbackItem *item;

	for (item = SubXact_callbacks; item; item = item->next)
		item->callback(event, mySubid, parentSubid, item->arg);
}





void BeginTransactionBlock(void)
{
	TransactionState s = CurrentTransactionState;

	switch (s->blockState)
	{
			
		case TBLOCK_STARTED:
			s->blockState = TBLOCK_BEGIN;
			break;

			
		case TBLOCK_IMPLICIT_INPROGRESS:
			s->blockState = TBLOCK_BEGIN;
			break;

			
		case TBLOCK_INPROGRESS:
		case TBLOCK_PARALLEL_INPROGRESS:
		case TBLOCK_SUBINPROGRESS:
		case TBLOCK_ABORT:
		case TBLOCK_SUBABORT:
			if (Gp_role == GP_ROLE_EXECUTE)
				ereport(DEBUG1, (errcode(ERRCODE_ACTIVE_SQL_TRANSACTION), errmsg("there is already a transaction in progress")));

			else ereport(WARNING, (errcode(ERRCODE_ACTIVE_SQL_TRANSACTION), errmsg("there is already a transaction in progress")));


			break;

			
		case TBLOCK_DEFAULT:
		case TBLOCK_BEGIN:
		case TBLOCK_SUBBEGIN:
		case TBLOCK_END:
		case TBLOCK_SUBRELEASE:
		case TBLOCK_SUBCOMMIT:
		case TBLOCK_ABORT_END:
		case TBLOCK_SUBABORT_END:
		case TBLOCK_ABORT_PENDING:
		case TBLOCK_SUBABORT_PENDING:
		case TBLOCK_SUBRESTART:
		case TBLOCK_SUBABORT_RESTART:
		case TBLOCK_PREPARE:
			elog(FATAL, "BeginTransactionBlock: unexpected state %s", BlockStateAsString(s->blockState));
			break;
	}
}


bool PrepareTransactionBlock(const char *gid)
{
	TransactionState s;
	bool		result;

	
	result = EndTransactionBlock(false);

	
	if (result)
	{
		s = CurrentTransactionState;

		while (s->parent != NULL)
			s = s->parent;

		if (s->blockState == TBLOCK_END)
		{
			
			prepareGID = MemoryContextStrdup(TopTransactionContext, gid);

			s->blockState = TBLOCK_PREPARE;
		}
		else {
			
			Assert(s->blockState == TBLOCK_STARTED || s->blockState == TBLOCK_IMPLICIT_INPROGRESS);
			
			result = false;
		}
	}

	return result;
}


bool EndTransactionBlock(bool chain)
{
	TransactionState s = CurrentTransactionState;
	bool		result = false;

	switch (s->blockState)
	{
			
		case TBLOCK_INPROGRESS:
			s->blockState = TBLOCK_END;
			result = true;
			break;

			
		case TBLOCK_IMPLICIT_INPROGRESS:
			if (chain)
				ereport(ERROR, (errcode(ERRCODE_NO_ACTIVE_SQL_TRANSACTION),  errmsg("%s can only be used in transaction blocks", "COMMIT AND CHAIN")));



			else ereport(WARNING, (errcode(ERRCODE_NO_ACTIVE_SQL_TRANSACTION), errmsg("there is no transaction in progress")));


			s->blockState = TBLOCK_END;
			result = true;
			break;

			
		case TBLOCK_ABORT:
			s->blockState = TBLOCK_ABORT_END;
			break;

			
		case TBLOCK_SUBINPROGRESS:
			while (s->parent != NULL)
			{
				if (s->blockState == TBLOCK_SUBINPROGRESS)
					s->blockState = TBLOCK_SUBCOMMIT;
				else elog(FATAL, "EndTransactionBlock: unexpected state %s", BlockStateAsString(s->blockState));

				s = s->parent;
			}
			if (s->blockState == TBLOCK_INPROGRESS)
				s->blockState = TBLOCK_END;
			else elog(FATAL, "EndTransactionBlock: unexpected state %s", BlockStateAsString(s->blockState));

			result = true;
			break;

			
		case TBLOCK_SUBABORT:
			while (s->parent != NULL)
			{
				if (s->blockState == TBLOCK_SUBINPROGRESS)
					s->blockState = TBLOCK_SUBABORT_PENDING;
				else if (s->blockState == TBLOCK_SUBABORT)
					s->blockState = TBLOCK_SUBABORT_END;
				else elog(FATAL, "EndTransactionBlock: unexpected state %s", BlockStateAsString(s->blockState));

				s = s->parent;
			}
			if (s->blockState == TBLOCK_INPROGRESS)
				s->blockState = TBLOCK_ABORT_PENDING;
			else if (s->blockState == TBLOCK_ABORT)
				s->blockState = TBLOCK_ABORT_END;
			else elog(FATAL, "EndTransactionBlock: unexpected state %s", BlockStateAsString(s->blockState));

			break;

			
		case TBLOCK_STARTED:
			if (chain)
				ereport(ERROR, (errcode(ERRCODE_NO_ACTIVE_SQL_TRANSACTION),  errmsg("%s can only be used in transaction blocks", "COMMIT AND CHAIN")));



			else ereport((Gp_role == GP_ROLE_EXECUTE) ? DEBUG2 : WARNING, (errcode(ERRCODE_NO_ACTIVE_SQL_TRANSACTION), errmsg("there is no transaction in progress")));


			result = true;
			break;

			
		case TBLOCK_PARALLEL_INPROGRESS:
			ereport(FATAL, (errcode(ERRCODE_INVALID_TRANSACTION_STATE), errmsg("cannot commit during a parallel operation")));

			break;

			
		case TBLOCK_DEFAULT:
		case TBLOCK_BEGIN:
		case TBLOCK_SUBBEGIN:
		case TBLOCK_END:
		case TBLOCK_SUBRELEASE:
		case TBLOCK_SUBCOMMIT:
		case TBLOCK_ABORT_END:
		case TBLOCK_SUBABORT_END:
		case TBLOCK_ABORT_PENDING:
		case TBLOCK_SUBABORT_PENDING:
		case TBLOCK_SUBRESTART:
		case TBLOCK_SUBABORT_RESTART:
		case TBLOCK_PREPARE:
			elog(FATAL, "EndTransactionBlock: unexpected state %s", BlockStateAsString(s->blockState));
			break;
	}

	Assert(s->blockState == TBLOCK_STARTED || s->blockState == TBLOCK_END || s->blockState == TBLOCK_ABORT_END || s->blockState == TBLOCK_ABORT_PENDING);



	s->chain = chain;

	return result;
}


void UserAbortTransactionBlock(bool chain)
{
	TransactionState s = CurrentTransactionState;

	switch (s->blockState)
	{
			
		case TBLOCK_INPROGRESS:
			s->blockState = TBLOCK_ABORT_PENDING;
			break;

			
		case TBLOCK_ABORT:
			s->blockState = TBLOCK_ABORT_END;
			break;

			
		case TBLOCK_SUBINPROGRESS:
		case TBLOCK_SUBABORT:
			while (s->parent != NULL)
			{
				if (s->blockState == TBLOCK_SUBINPROGRESS)
					s->blockState = TBLOCK_SUBABORT_PENDING;
				else if (s->blockState == TBLOCK_SUBABORT)
					s->blockState = TBLOCK_SUBABORT_END;
				else elog(FATAL, "UserAbortTransactionBlock: unexpected state %s", BlockStateAsString(s->blockState));

				s = s->parent;
			}
			if (s->blockState == TBLOCK_INPROGRESS)
				s->blockState = TBLOCK_ABORT_PENDING;
			else if (s->blockState == TBLOCK_ABORT)
				s->blockState = TBLOCK_ABORT_END;
			else elog(FATAL, "UserAbortTransactionBlock: unexpected state %s", BlockStateAsString(s->blockState));

			break;

			
		case TBLOCK_STARTED:
		case TBLOCK_IMPLICIT_INPROGRESS:
			if (chain)
				ereport(ERROR, (errcode(ERRCODE_NO_ACTIVE_SQL_TRANSACTION),  errmsg("%s can only be used in transaction blocks", "ROLLBACK AND CHAIN")));



			else ereport((Gp_role == GP_ROLE_EXECUTE) ? DEBUG2 : WARNING, (errcode(ERRCODE_NO_ACTIVE_SQL_TRANSACTION), errmsg("there is no transaction in progress")));


			s->blockState = TBLOCK_ABORT_PENDING;
			break;

			
		case TBLOCK_PARALLEL_INPROGRESS:
			ereport(FATAL, (errcode(ERRCODE_INVALID_TRANSACTION_STATE), errmsg("cannot abort during a parallel operation")));

			break;

			
		case TBLOCK_DEFAULT:
		case TBLOCK_BEGIN:
		case TBLOCK_SUBBEGIN:
		case TBLOCK_END:
		case TBLOCK_SUBRELEASE:
		case TBLOCK_SUBCOMMIT:
		case TBLOCK_ABORT_END:
		case TBLOCK_SUBABORT_END:
		case TBLOCK_ABORT_PENDING:
		case TBLOCK_SUBABORT_PENDING:
		case TBLOCK_SUBRESTART:
		case TBLOCK_SUBABORT_RESTART:
		case TBLOCK_PREPARE:
			elog(FATAL, "UserAbortTransactionBlock: unexpected state %s", BlockStateAsString(s->blockState));
			break;
	}

	Assert(s->blockState == TBLOCK_ABORT_END || s->blockState == TBLOCK_ABORT_PENDING);

	s->chain = chain;
}


void BeginImplicitTransactionBlock(void)
{
	TransactionState s = CurrentTransactionState;

	
	if (s->blockState == TBLOCK_STARTED)
		s->blockState = TBLOCK_IMPLICIT_INPROGRESS;
}


void EndImplicitTransactionBlock(void)
{
	TransactionState s = CurrentTransactionState;

	
	if (s->blockState == TBLOCK_IMPLICIT_INPROGRESS)
		s->blockState = TBLOCK_STARTED;
}

void DefineDispatchSavepoint(char *name)
{
	TransactionState s = CurrentTransactionState;

	if ((s->blockState != TBLOCK_INPROGRESS) && (s->blockState != TBLOCK_SUBINPROGRESS))
	{
		elog(FATAL, "DefineSavepoint: unexpected state %s", BlockStateAsString(s->blockState));
	}

	
	if (Gp_role == GP_ROLE_DISPATCH)
	{
		char	   *cmd;

		cmd = psprintf("SAVEPOINT %s", quote_identifier(name));

		
		if (!dispatchDtxCommand(cmd))
			elog(ERROR, "Could not create a new savepoint (%s)", cmd);

		pfree(cmd);
	}

	DefineSavepoint(name);
}


void DefineSavepoint(const char *name)
{
	TransactionState s = CurrentTransactionState;

	
	if (IsInParallelMode())
		ereport(ERROR, (errcode(ERRCODE_INVALID_TRANSACTION_STATE), errmsg("cannot define savepoints during a parallel operation")));


	switch (s->blockState)
	{
		case TBLOCK_INPROGRESS:
		case TBLOCK_SUBINPROGRESS:
			
			PushTransaction();
			s = CurrentTransactionState;	

			
			if (name)
				s->name = MemoryContextStrdup(TopTransactionContext, name);
			break;

			
		case TBLOCK_IMPLICIT_INPROGRESS:
			ereport(ERROR, (errcode(ERRCODE_NO_ACTIVE_SQL_TRANSACTION),  errmsg("%s can only be used in transaction blocks", "SAVEPOINT")));



			break;

			
		case TBLOCK_DEFAULT:
		case TBLOCK_STARTED:
		case TBLOCK_BEGIN:
		case TBLOCK_PARALLEL_INPROGRESS:
		case TBLOCK_SUBBEGIN:
		case TBLOCK_END:
		case TBLOCK_SUBRELEASE:
		case TBLOCK_SUBCOMMIT:
		case TBLOCK_ABORT:
		case TBLOCK_SUBABORT:
		case TBLOCK_ABORT_END:
		case TBLOCK_SUBABORT_END:
		case TBLOCK_ABORT_PENDING:
		case TBLOCK_SUBABORT_PENDING:
		case TBLOCK_SUBRESTART:
		case TBLOCK_SUBABORT_RESTART:
		case TBLOCK_PREPARE:
			elog(FATAL, "DefineSavepoint: unexpected state %s", BlockStateAsString(s->blockState));
			break;
	}
}


void ReleaseSavepoint(const char *name)
{
	TransactionState s = CurrentTransactionState;
	TransactionState target, xact;

	
	if (IsInParallelMode())
		ereport(ERROR, (errcode(ERRCODE_INVALID_TRANSACTION_STATE), errmsg("cannot release savepoints during a parallel operation")));


	switch (s->blockState)
	{
			
		case TBLOCK_INPROGRESS:
			ereport(ERROR, (errcode(ERRCODE_S_E_INVALID_SPECIFICATION), errmsg("savepoint \"%s\" does not exist", name)));

			break;

		case TBLOCK_IMPLICIT_INPROGRESS:
			
			ereport(ERROR, (errcode(ERRCODE_NO_ACTIVE_SQL_TRANSACTION),  errmsg("%s can only be used in transaction blocks", "RELEASE SAVEPOINT")));



			break;

			
		case TBLOCK_SUBINPROGRESS:
			break;

			
		case TBLOCK_DEFAULT:
		case TBLOCK_STARTED:
		case TBLOCK_BEGIN:
		case TBLOCK_PARALLEL_INPROGRESS:
		case TBLOCK_SUBBEGIN:
		case TBLOCK_END:
		case TBLOCK_SUBRELEASE:
		case TBLOCK_SUBCOMMIT:
		case TBLOCK_ABORT:
		case TBLOCK_SUBABORT:
		case TBLOCK_ABORT_END:
		case TBLOCK_SUBABORT_END:
		case TBLOCK_ABORT_PENDING:
		case TBLOCK_SUBABORT_PENDING:
		case TBLOCK_SUBRESTART:
		case TBLOCK_SUBABORT_RESTART:
		case TBLOCK_PREPARE:
			elog(FATAL, "ReleaseSavepoint: unexpected state %s", BlockStateAsString(s->blockState));
			break;
	}

	if (Gp_role == GP_ROLE_DISPATCH)
	{
		char	   *cmd;

		cmd = psprintf("RELEASE SAVEPOINT %s", quote_identifier(name));

		
		if (!dispatchDtxCommand(cmd))
			elog(ERROR, "Could not release savepoint (%s)", cmd);

		pfree(cmd);
	}

	for (target = s; PointerIsValid(target); target = target->parent)
	{
		if (PointerIsValid(target->name) && strcmp(target->name, name) == 0)
			break;
	}

	if (!PointerIsValid(target))
		ereport(ERROR, (errcode(ERRCODE_S_E_INVALID_SPECIFICATION), errmsg("savepoint \"%s\" does not exist", name)));


	
	if (target->savepointLevel != s->savepointLevel)
		ereport(ERROR, (errcode(ERRCODE_S_E_INVALID_SPECIFICATION), errmsg("savepoint \"%s\" does not exist within current savepoint level", name)));


	
	xact = CurrentTransactionState;
	for (;;)
	{
		Assert(xact->blockState == TBLOCK_SUBINPROGRESS);
		xact->blockState = TBLOCK_SUBRELEASE;
		if (xact == target)
			break;
		xact = xact->parent;
		Assert(PointerIsValid(xact));
	}
}


void RollbackToSavepoint(const char *name)
{
	TransactionState s = CurrentTransactionState;
	TransactionState target, xact;

	
	if (IsInParallelMode())
		ereport(ERROR, (errcode(ERRCODE_INVALID_TRANSACTION_STATE), errmsg("cannot rollback to savepoints during a parallel operation")));


	switch (s->blockState)
	{
			
		case TBLOCK_INPROGRESS:
		case TBLOCK_ABORT:
			ereport(ERROR, (errcode(ERRCODE_S_E_INVALID_SPECIFICATION), errmsg("savepoint \"%s\" does not exist", name)));

			break;

		case TBLOCK_IMPLICIT_INPROGRESS:
			
			ereport(ERROR, (errcode(ERRCODE_NO_ACTIVE_SQL_TRANSACTION),  errmsg("%s can only be used in transaction blocks", "ROLLBACK TO SAVEPOINT")));



			break;

			
		case TBLOCK_SUBINPROGRESS:
		case TBLOCK_SUBABORT:
			break;

			
		case TBLOCK_DEFAULT:
		case TBLOCK_STARTED:
		case TBLOCK_BEGIN:
		case TBLOCK_PARALLEL_INPROGRESS:
		case TBLOCK_SUBBEGIN:
		case TBLOCK_END:
		case TBLOCK_SUBRELEASE:
		case TBLOCK_SUBCOMMIT:
		case TBLOCK_ABORT_END:
		case TBLOCK_SUBABORT_END:
		case TBLOCK_ABORT_PENDING:
		case TBLOCK_SUBABORT_PENDING:
		case TBLOCK_SUBRESTART:
		case TBLOCK_SUBABORT_RESTART:
		case TBLOCK_PREPARE:
			elog(FATAL, "RollbackToSavepoint: unexpected state %s", BlockStateAsString(s->blockState));
			break;
	}

	for (target = s; PointerIsValid(target); target = target->parent)
	{
		if (PointerIsValid(target->name) && strcmp(target->name, name) == 0)
			break;
	}

	if (!PointerIsValid(target))
		ereport(ERROR, (errcode(ERRCODE_S_E_INVALID_SPECIFICATION), errmsg("savepoint \"%s\" does not exist", name)));


	
	if (target->savepointLevel != s->savepointLevel)
		ereport(ERROR, (errcode(ERRCODE_S_E_INVALID_SPECIFICATION), errmsg("savepoint \"%s\" does not exist within current savepoint level", name)));


	
	xact = CurrentTransactionState;
	for (;;)
	{
		if (xact == target)
			break;
		if (xact->blockState == TBLOCK_SUBINPROGRESS)
			xact->blockState = TBLOCK_SUBABORT_PENDING;
		else if (xact->blockState == TBLOCK_SUBABORT)
			xact->blockState = TBLOCK_SUBABORT_END;
		else elog(FATAL, "RollbackToSavepoint: unexpected state %s", BlockStateAsString(xact->blockState));

		xact = xact->parent;
		Assert(PointerIsValid(xact));
	}

	
	if (xact->blockState == TBLOCK_SUBINPROGRESS)
		xact->blockState = TBLOCK_SUBRESTART;
	else if (xact->blockState == TBLOCK_SUBABORT)
		xact->blockState = TBLOCK_SUBABORT_RESTART;
	else elog(FATAL, "RollbackToSavepoint: unexpected state %s", BlockStateAsString(xact->blockState));

}

static void DispatchRollbackToSavepoint(char *name)
{
	char	   *cmd;

	if (!name)
		elog(ERROR, "could not find savepoint name for ROLLBACK TO SAVEPOINT");

	cmd = psprintf("ROLLBACK TO SAVEPOINT %s", quote_identifier(name));

	
	if (!dispatchDtxCommand(cmd))
		ereport(ERROR, (errcode(ERRCODE_GP_INTERCONNECTION_ERROR), errmsg("Could not rollback to savepoint (%s)", cmd)));

	pfree(cmd);
}


void BeginInternalSubTransaction(const char *name)
{
	TransactionState s = CurrentTransactionState;

	if (Gp_role == GP_ROLE_DISPATCH)
	{
		if (!doDispatchSubtransactionInternalCmd( DTX_PROTOCOL_COMMAND_SUBTRANSACTION_BEGIN_INTERNAL))
		{
			elog(ERROR, "Could not BeginInternalSubTransaction dispatch failed");
		}
	}

	
	if (IsInParallelMode())
		ereport(ERROR, (errcode(ERRCODE_INVALID_TRANSACTION_STATE), errmsg("cannot start subtransactions during a parallel operation")));


	switch (s->blockState)
	{
		case TBLOCK_STARTED:
		case TBLOCK_INPROGRESS:
		case TBLOCK_IMPLICIT_INPROGRESS:
		case TBLOCK_END:
		case TBLOCK_PREPARE:
		case TBLOCK_SUBINPROGRESS:
			
			PushTransaction();
			s = CurrentTransactionState;	

			
			if (name)
				s->name = MemoryContextStrdup(TopTransactionContext, name);
			break;

			
		case TBLOCK_DEFAULT:
		case TBLOCK_BEGIN:
		case TBLOCK_PARALLEL_INPROGRESS:
		case TBLOCK_SUBBEGIN:
		case TBLOCK_SUBRELEASE:
		case TBLOCK_SUBCOMMIT:
		case TBLOCK_ABORT:
		case TBLOCK_SUBABORT:
		case TBLOCK_ABORT_END:
		case TBLOCK_SUBABORT_END:
		case TBLOCK_ABORT_PENDING:
		case TBLOCK_SUBABORT_PENDING:
		case TBLOCK_SUBRESTART:
		case TBLOCK_SUBABORT_RESTART:
			elog(FATAL, "BeginInternalSubTransaction: unexpected state %s", BlockStateAsString(s->blockState));
			break;
	}

	CommitTransactionCommand();
	StartTransactionCommand();
}


void ReleaseCurrentSubTransaction(void)
{
	TransactionState s = CurrentTransactionState;

	
	if (IsInParallelMode())
		ereport(ERROR, (errcode(ERRCODE_INVALID_TRANSACTION_STATE), errmsg("cannot commit subtransactions during a parallel operation")));


	if (s->blockState != TBLOCK_SUBINPROGRESS)
		elog(ERROR, "ReleaseCurrentSubTransaction: unexpected state %s", BlockStateAsString(s->blockState));
	Assert(s->state == TRANS_INPROGRESS);

	if (Gp_role == GP_ROLE_DISPATCH)
	{
		if (!doDispatchSubtransactionInternalCmd( DTX_PROTOCOL_COMMAND_SUBTRANSACTION_RELEASE_INTERNAL))
		{
			elog(ERROR, "Could not ReleaseCurrentSubTransaction dispatch failed");
		}
	}

	MemoryContextSwitchTo(CurTransactionContext);
	CommitSubTransaction();
	s = CurrentTransactionState;	
	Assert(s->state == TRANS_INPROGRESS);
}


void RollbackAndReleaseCurrentSubTransaction(void)
{
	TransactionState s = CurrentTransactionState;

	

	switch (s->blockState)
	{
			
		case TBLOCK_SUBINPROGRESS:
		case TBLOCK_SUBABORT:
			break;

			
		case TBLOCK_DEFAULT:
		case TBLOCK_STARTED:
		case TBLOCK_BEGIN:
		case TBLOCK_IMPLICIT_INPROGRESS:
		case TBLOCK_PARALLEL_INPROGRESS:
		case TBLOCK_SUBBEGIN:
		case TBLOCK_INPROGRESS:
		case TBLOCK_END:
		case TBLOCK_SUBRELEASE:
		case TBLOCK_SUBCOMMIT:
		case TBLOCK_ABORT:
		case TBLOCK_ABORT_END:
		case TBLOCK_SUBABORT_END:
		case TBLOCK_ABORT_PENDING:
		case TBLOCK_SUBABORT_PENDING:
		case TBLOCK_SUBRESTART:
		case TBLOCK_SUBABORT_RESTART:
		case TBLOCK_PREPARE:
			elog(FATAL, "RollbackAndReleaseCurrentSubTransaction: unexpected state %s", BlockStateAsString(s->blockState));
			break;
	}

	
	if (s->blockState == TBLOCK_SUBINPROGRESS)
		AbortSubTransaction();

	
	CleanupSubTransaction();

	s = CurrentTransactionState;	
	AssertState(s->blockState == TBLOCK_SUBINPROGRESS || s->blockState == TBLOCK_INPROGRESS || s->blockState == TBLOCK_IMPLICIT_INPROGRESS || s->blockState == TBLOCK_STARTED);



	if (Gp_role == GP_ROLE_DISPATCH)
	{
		if (!doDispatchSubtransactionInternalCmd( DTX_PROTOCOL_COMMAND_SUBTRANSACTION_ROLLBACK_INTERNAL))
		{
			ereport(ERROR, (errcode(ERRCODE_GP_INTERCONNECTION_ERROR), errmsg("DTX RollbackAndReleaseCurrentSubTransaction dispatch failed")));
		}
	}
}


void AbortOutOfAnyTransaction(void)
{
	TransactionState s = CurrentTransactionState;

	
	AtAbort_Memory();

	
	do {
		switch (s->blockState)
		{
			case TBLOCK_DEFAULT:
				if (s->state == TRANS_DEFAULT)
				{
					
				}
				else {
					
					if (s->state == TRANS_START)
						s->state = TRANS_INPROGRESS;
					AbortTransaction();
					CleanupTransaction();
				}
				break;
			case TBLOCK_STARTED:
			case TBLOCK_BEGIN:
			case TBLOCK_INPROGRESS:
			case TBLOCK_IMPLICIT_INPROGRESS:
			case TBLOCK_PARALLEL_INPROGRESS:
			case TBLOCK_END:
			case TBLOCK_ABORT_PENDING:
			case TBLOCK_PREPARE:
				
				AbortTransaction();
				CleanupTransaction();
				s->blockState = TBLOCK_DEFAULT;

				Assert(DistributedTransactionContext == DTX_CONTEXT_LOCAL_ONLY);
				break;
			case TBLOCK_ABORT:
			case TBLOCK_ABORT_END:

				
				AtAbort_Portals();
				CleanupTransaction();
				s->blockState = TBLOCK_DEFAULT;

				Assert(DistributedTransactionContext == DTX_CONTEXT_LOCAL_ONLY);
				break;

				
			case TBLOCK_SUBBEGIN:
			case TBLOCK_SUBINPROGRESS:
			case TBLOCK_SUBRELEASE:
			case TBLOCK_SUBCOMMIT:
			case TBLOCK_SUBABORT_PENDING:
			case TBLOCK_SUBRESTART:
				AbortSubTransaction();
				CleanupSubTransaction();
				s = CurrentTransactionState;	
				break;

			case TBLOCK_SUBABORT:
			case TBLOCK_SUBABORT_END:
			case TBLOCK_SUBABORT_RESTART:
				
				if (s->curTransactionOwner)
				{
					
					AtSubAbort_Portals(s->subTransactionId, s->parent->subTransactionId, s->curTransactionOwner, s->parent->curTransactionOwner);


				}
				CleanupSubTransaction();
				s = CurrentTransactionState;	
				break;
		}
	} while (s->blockState != TBLOCK_DEFAULT);

	
	Assert(s->parent == NULL);

	
	AtCleanup_Memory();
}


bool IsTransactionBlock(void)
{
	TransactionState s = CurrentTransactionState;

	if (s->blockState == TBLOCK_DEFAULT || s->blockState == TBLOCK_STARTED)
		return false;

	return true;
}


bool IsTransactionOrTransactionBlock(void)
{
	TransactionState s = CurrentTransactionState;

	if (s->blockState == TBLOCK_DEFAULT)
		return false;

	return true;
}

void ExecutorMarkTransactionUsesSequences(void)
{
	seqXlogWrite = true;

	ForceSyncCommit();
}

void ExecutorMarkTransactionDoesWrites(void)
{
	
	if (!TopTransactionStateData.executorSaysXactDoesWrites)
	{
		ereportif(Debug_print_full_dtm, LOG, (errmsg("ExecutorMarkTransactionDoesWrites called")));
		TopTransactionStateData.executorSaysXactDoesWrites = true;
	}
}

bool ExecutorSaysTransactionDoesWrites(void)
{
	return TopTransactionStateData.executorSaysXactDoesWrites;
}


char TransactionBlockStatusCode(void)
{
	TransactionState s = CurrentTransactionState;

	switch (s->blockState)
	{
		case TBLOCK_DEFAULT:
		case TBLOCK_STARTED:
			return 'I';			
		case TBLOCK_BEGIN:
		case TBLOCK_SUBBEGIN:
		case TBLOCK_INPROGRESS:
		case TBLOCK_IMPLICIT_INPROGRESS:
		case TBLOCK_PARALLEL_INPROGRESS:
		case TBLOCK_SUBINPROGRESS:
		case TBLOCK_END:
		case TBLOCK_SUBRELEASE:
		case TBLOCK_SUBCOMMIT:
		case TBLOCK_PREPARE:
			return 'T';			
		case TBLOCK_ABORT:
		case TBLOCK_SUBABORT:
		case TBLOCK_ABORT_END:
		case TBLOCK_SUBABORT_END:
		case TBLOCK_ABORT_PENDING:
		case TBLOCK_SUBABORT_PENDING:
		case TBLOCK_SUBRESTART:
		case TBLOCK_SUBABORT_RESTART:
			return 'E';			
	}

	
	elog(FATAL, "invalid transaction block state: %s", BlockStateAsString(s->blockState));
	return 0;					
}


bool IsSubTransaction(void)
{
	TransactionState s = CurrentTransactionState;

	if (s->nestingLevel >= 2)
		return true;

	return false;
}


static void StartSubTransaction(void)
{
	TransactionState s = CurrentTransactionState;

	if (s->state != TRANS_DEFAULT)
		elog(WARNING, "StartSubTransaction while in %s state", TransStateAsString(s->state));

	s->state = TRANS_START;

	
	AtSubStart_Memory();
	AtSubStart_ResourceOwner();
	AtSubStart_Notify();
	AfterTriggerBeginSubXact();

	s->state = TRANS_INPROGRESS;

	
	CallSubXactCallbacks(SUBXACT_EVENT_START_SUB, s->subTransactionId, s->parent->subTransactionId);

	ShowTransactionState("StartSubTransaction");
}


static void CommitSubTransaction(void)
{
	TransactionState s = CurrentTransactionState;

	ShowTransactionState("CommitSubTransaction");

	if (s->state != TRANS_INPROGRESS)
		elog(WARNING, "CommitSubTransaction while in %s state", TransStateAsString(s->state));

	

	CallSubXactCallbacks(SUBXACT_EVENT_PRE_COMMIT_SUB, s->subTransactionId, s->parent->subTransactionId);

	
	if (IsInParallelMode())
	{
		AtEOSubXact_Parallel(true, s->subTransactionId);
		s->parallelModeLevel = 0;
	}

	
	s->state = TRANS_COMMIT;

	
	CommandCounterIncrement();

	

	
	if (FullTransactionIdIsValid(s->fullTransactionId))
		AtSubCommit_childXids();
	AfterTriggerEndSubXact(true);
	AtSubCommit_Portals(s->subTransactionId, s->parent->subTransactionId, s->parent->curTransactionOwner);

	AtEOSubXact_LargeObject(true, s->subTransactionId, s->parent->subTransactionId);
	AtSubCommit_Notify();

	CallSubXactCallbacks(SUBXACT_EVENT_COMMIT_SUB, s->subTransactionId, s->parent->subTransactionId);

	ResourceOwnerRelease(s->curTransactionOwner, RESOURCE_RELEASE_BEFORE_LOCKS, true, false);

	AtEOSubXact_RelationCache(true, s->subTransactionId, s->parent->subTransactionId);
	AtEOSubXact_Inval(true);
	AtSubCommit_smgr();

	
	CurrentResourceOwner = s->curTransactionOwner;
	if (FullTransactionIdIsValid(s->fullTransactionId))
		XactLockTableDelete(XidFromFullTransactionId(s->fullTransactionId));

	
	ResourceOwnerRelease(s->curTransactionOwner, RESOURCE_RELEASE_LOCKS, true, false);

	ResourceOwnerRelease(s->curTransactionOwner, RESOURCE_RELEASE_AFTER_LOCKS, true, false);


	AtEOXact_GUC(true, s->gucNestLevel);
	AtEOSubXact_SPI(true, s->subTransactionId);
	AtEOSubXact_on_commit_actions(true, s->subTransactionId, s->parent->subTransactionId);
	AtEOSubXact_Namespace(true, s->subTransactionId, s->parent->subTransactionId);
	AtEOSubXact_Files(true, s->subTransactionId, s->parent->subTransactionId);
	AtEOSubXact_HashTables(true, s->nestingLevel);
	AtEOSubXact_PgStat(true, s->nestingLevel);
	AtSubCommit_Snapshot(s->nestingLevel);
	AtEOSubXact_ApplyLauncher(true, s->nestingLevel);

	
	XactReadOnly = s->prevXactReadOnly;

	CurrentResourceOwner = s->parent->curTransactionOwner;
	CurTransactionResourceOwner = s->parent->curTransactionOwner;
	ResourceOwnerDelete(s->curTransactionOwner);
	s->curTransactionOwner = NULL;

	AtSubCommit_Memory();

	s->state = TRANS_DEFAULT;

	PopTransaction();
}


static void AbortSubTransaction(void)
{
	TransactionState s = CurrentTransactionState;

	
	HOLD_INTERRUPTS();

	
	AtSubAbort_Memory();
	AtSubAbort_ResourceOwner();

	
	LWLockReleaseAll();

	pgstat_report_wait_end();
	pgstat_progress_end_command();
	AbortBufferIO();
	UnlockBuffers();

	
	XLogResetInsertion();

	
	ConditionVariableCancelSleep();

	
	LockErrorCleanup();

	
	reschedule_timeouts();

	
	PG_SETMASK(&UnBlockSig);

	
	ShowTransactionState("AbortSubTransaction");

	if (s->state != TRANS_INPROGRESS)
		elog(WARNING, "AbortSubTransaction while in %s state", TransStateAsString(s->state));

	s->state = TRANS_ABORT;

	
	SetUserIdAndSecContext(s->prevUser, s->prevSecContext);

	
	if (IsInParallelMode())
	{
		AtEOSubXact_Parallel(false, s->subTransactionId);
		s->parallelModeLevel = 0;
	}

	
	if (s->curTransactionOwner)
	{
		AfterTriggerEndSubXact(false);
		AtSubAbort_Portals(s->subTransactionId, s->parent->subTransactionId, s->curTransactionOwner, s->parent->curTransactionOwner);


		AtSubAbort_DispatcherState();
		AtEOXact_DispatchOids(false);
		AtEOSubXact_LargeObject(false, s->subTransactionId, s->parent->subTransactionId);
		AtSubAbort_Notify();

		
		(void) RecordTransactionAbort(true);

		
		if (FullTransactionIdIsValid(s->fullTransactionId))
			AtSubAbort_childXids();

		CallSubXactCallbacks(SUBXACT_EVENT_ABORT_SUB, s->subTransactionId, s->parent->subTransactionId);

		ResourceOwnerRelease(s->curTransactionOwner, RESOURCE_RELEASE_BEFORE_LOCKS, false, false);

		AtEOSubXact_RelationCache(false, s->subTransactionId, s->parent->subTransactionId);
		AtEOSubXact_Inval(false);
		ResourceOwnerRelease(s->curTransactionOwner, RESOURCE_RELEASE_LOCKS, false, false);

		ResourceOwnerRelease(s->curTransactionOwner, RESOURCE_RELEASE_AFTER_LOCKS, false, false);

		AtSubAbort_smgr();

		AtEOXact_GUC(false, s->gucNestLevel);
		AtEOSubXact_SPI(false, s->subTransactionId);
		AtEOSubXact_on_commit_actions(false, s->subTransactionId, s->parent->subTransactionId);
		AtEOSubXact_Namespace(false, s->subTransactionId, s->parent->subTransactionId);
		AtEOSubXact_Files(false, s->subTransactionId, s->parent->subTransactionId);
		AtEOSubXact_HashTables(false, s->nestingLevel);
		AtEOSubXact_PgStat(false, s->nestingLevel);
		AtSubAbort_Snapshot(s->nestingLevel);
		AtEOSubXact_ApplyLauncher(false, s->nestingLevel);
	}

	
	XactReadOnly = s->prevXactReadOnly;

	RESUME_INTERRUPTS();
}


static void CleanupSubTransaction(void)
{
	TransactionState s = CurrentTransactionState;

	ShowTransactionState("CleanupSubTransaction");

	if (s->state != TRANS_ABORT)
		elog(WARNING, "CleanupSubTransaction while in %s state", TransStateAsString(s->state));

	AtSubCleanup_Portals(s->subTransactionId);

	CurrentResourceOwner = s->parent->curTransactionOwner;
	CurTransactionResourceOwner = s->parent->curTransactionOwner;
	if (s->curTransactionOwner)
		ResourceOwnerDelete(s->curTransactionOwner);
	s->curTransactionOwner = NULL;

	AtSubCleanup_Memory();

	s->state = TRANS_DEFAULT;

	PopTransaction();
}


static void PushTransaction(void)
{
	TransactionState p = CurrentTransactionState;
	TransactionState s;

	currentSavepointTotal++;

	if ((currentSavepointTotal >= gp_subtrans_warn_limit) && (currentSavepointTotal % gp_subtrans_warn_limit == 0))
	{
		ereport(WARNING, (errmsg("Using too many subtransactions in one transaction."), errhint("Close open transactions soon to avoid wraparound " "problems.")));


	}

	
	s = (TransactionState)
		MemoryContextAllocZero(TopTransactionContext, sizeof(TransactionStateData));

	
	currentSubTransactionId += 1;
	if (currentSubTransactionId == InvalidSubTransactionId)
	{
		currentSubTransactionId -= 1;
		pfree(s);
		ereport(ERROR, (errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED), errmsg("cannot have more than 2^32-1 subtransactions in a transaction")));

	}

	
	s->fullTransactionId = InvalidFullTransactionId;	
	s->subTransactionId = currentSubTransactionId;
	s->parent = p;
	s->nestingLevel = p->nestingLevel + 1;
	s->gucNestLevel = NewGUCNestLevel();
	s->savepointLevel = p->savepointLevel;
	s->state = TRANS_DEFAULT;
	s->blockState = TBLOCK_SUBBEGIN;
	GetUserIdAndSecContext(&s->prevUser, &s->prevSecContext);
	s->prevXactReadOnly = XactReadOnly;
	s->parallelModeLevel = 0;
	s->executorSaysXactDoesWrites = false;

	fastNodeCount++;
	if (fastNodeCount == NUM_NODES_TO_SKIP_FOR_FAST_SEARCH)
	{
		fastNodeCount = 0;
		s->fastLink = previousFastLink;
		previousFastLink = s;
	}

	CurrentTransactionState = s;

	
}


static void PopTransaction(void)
{
	TransactionState s = CurrentTransactionState;

	if (s->state != TRANS_DEFAULT)
		elog(WARNING, "PopTransaction while in %s state", TransStateAsString(s->state));

	if (s->parent == NULL)
		elog(FATAL, "PopTransaction with no parent");

	CurrentTransactionState = s->parent;

	
	CurTransactionContext = s->parent->curTransactionContext;
	MemoryContextSwitchTo(CurTransactionContext);

	
	CurTransactionResourceOwner = s->parent->curTransactionOwner;
	CurrentResourceOwner = s->parent->curTransactionOwner;

	if (fastNodeCount)
	{
		fastNodeCount--;
	}

	
	if (previousFastLink == s)
	{
		fastNodeCount = NUM_NODES_TO_SKIP_FOR_FAST_SEARCH - 1;
		previousFastLink = s->fastLink;
	}

	
	if (s->name)
		pfree(s->name);
	pfree(s);
}


Size EstimateTransactionStateSpace(void)
{
	TransactionState s;
	Size		nxids = 0;
	Size		size = SerializedTransactionStateHeaderSize;

	for (s = CurrentTransactionState; s != NULL; s = s->parent)
	{
		if (FullTransactionIdIsValid(s->fullTransactionId))
			nxids = add_size(nxids, 1);
		nxids = add_size(nxids, s->nChildXids);
	}

	return add_size(size, mul_size(sizeof(TransactionId), nxids));
}


void SerializeTransactionState(Size maxsize, char *start_address)
{
	TransactionState s;
	Size		nxids = 0;
	Size		i = 0;
	TransactionId *workspace;
	SerializedTransactionState *result;

	result = (SerializedTransactionState *) start_address;

	result->xactIsoLevel = XactIsoLevel;
	result->xactDeferrable = XactDeferrable;
	result->topFullTransactionId = XactTopFullTransactionId;
	result->currentFullTransactionId = CurrentTransactionState->fullTransactionId;
	result->currentCommandId = currentCommandId;

	
	if (nParallelCurrentXids > 0)
	{
		result->nParallelCurrentXids = nParallelCurrentXids;
		memcpy(&result->parallelCurrentXids[0], ParallelCurrentXids, nParallelCurrentXids * sizeof(TransactionId));
		return;
	}

	
	for (s = CurrentTransactionState; s != NULL; s = s->parent)
	{
		if (FullTransactionIdIsValid(s->fullTransactionId))
			nxids = add_size(nxids, 1);
		nxids = add_size(nxids, s->nChildXids);
	}
	Assert(SerializedTransactionStateHeaderSize + nxids * sizeof(TransactionId)
		   <= maxsize);

	
	workspace = palloc(nxids * sizeof(TransactionId));
	for (s = CurrentTransactionState; s != NULL; s = s->parent)
	{
		if (FullTransactionIdIsValid(s->fullTransactionId))
			workspace[i++] = XidFromFullTransactionId(s->fullTransactionId);
		memcpy(&workspace[i], s->childXids, s->nChildXids * sizeof(TransactionId));
		i += s->nChildXids;
	}
	Assert(i == nxids);

	
	qsort(workspace, nxids, sizeof(TransactionId), xidComparator);

	
	result->nParallelCurrentXids = nxids;
	memcpy(&result->parallelCurrentXids[0], workspace, nxids * sizeof(TransactionId));
}


void StartParallelWorkerTransaction(char *tstatespace)
{
	SerializedTransactionState *tstate;

	Assert(CurrentTransactionState->blockState == TBLOCK_DEFAULT);
	StartTransaction();

	tstate = (SerializedTransactionState *) tstatespace;
	XactIsoLevel = tstate->xactIsoLevel;
	XactDeferrable = tstate->xactDeferrable;
	XactTopFullTransactionId = tstate->topFullTransactionId;
	CurrentTransactionState->fullTransactionId = tstate->currentFullTransactionId;
	currentCommandId = tstate->currentCommandId;
	nParallelCurrentXids = tstate->nParallelCurrentXids;
	ParallelCurrentXids = &tstate->parallelCurrentXids[0];

	CurrentTransactionState->blockState = TBLOCK_PARALLEL_INPROGRESS;
}


void EndParallelWorkerTransaction(void)
{
	Assert(CurrentTransactionState->blockState == TBLOCK_PARALLEL_INPROGRESS);
	CommitTransaction();
	CurrentTransactionState->blockState = TBLOCK_DEFAULT;
}


static void ShowTransactionState(const char *str)
{
	
	if (log_min_messages <= DEBUG5 || client_min_messages <= DEBUG5)
		ShowTransactionStateRec(str, CurrentTransactionState);
}


static void ShowTransactionStateRec(const char *str, TransactionState s)
{
	StringInfoData buf;

	initStringInfo(&buf);

	if (s->nChildXids > 0)
	{
		int			i;

		appendStringInfo(&buf, ", children: %u", s->childXids[0]);
		for (i = 1; i < s->nChildXids; i++)
			appendStringInfo(&buf, " %u", s->childXids[i]);
	}

	if (s->parent)
		ShowTransactionStateRec(str, s->parent);

	
	ereport(DEBUG5, (errmsg_internal("%s(%d) name: %s; blockState: %s; state: %s, xid/subid/cid: %u/%u/%u%s%s", str, s->nestingLevel, PointerIsValid(s->name) ? s->name : "unnamed", BlockStateAsString(s->blockState), TransStateAsString(s->state), (unsigned int) XidFromFullTransactionId(s->fullTransactionId), (unsigned int) s->subTransactionId, (unsigned int) currentCommandId, currentCommandIdUsed ? " (used)" : "", buf.data)));










	pfree(buf.data);
}


static const char * BlockStateAsString(TBlockState blockState)
{
	switch (blockState)
	{
		case TBLOCK_DEFAULT:
			return "DEFAULT";
		case TBLOCK_STARTED:
			return "STARTED";
		case TBLOCK_BEGIN:
			return "BEGIN";
		case TBLOCK_INPROGRESS:
			return "INPROGRESS";
		case TBLOCK_IMPLICIT_INPROGRESS:
			return "IMPLICIT_INPROGRESS";
		case TBLOCK_PARALLEL_INPROGRESS:
			return "PARALLEL_INPROGRESS";
		case TBLOCK_END:
			return "END";
		case TBLOCK_ABORT:
			return "ABORT";
		case TBLOCK_ABORT_END:
			return "ABORT_END";
		case TBLOCK_ABORT_PENDING:
			return "ABORT_PENDING";
		case TBLOCK_PREPARE:
			return "PREPARE";
		case TBLOCK_SUBBEGIN:
			return "SUBBEGIN";
		case TBLOCK_SUBINPROGRESS:
			return "SUBINPROGRESS";
		case TBLOCK_SUBRELEASE:
			return "SUBRELEASE";
		case TBLOCK_SUBCOMMIT:
			return "SUBCOMMIT";
		case TBLOCK_SUBABORT:
			return "SUBABORT";
		case TBLOCK_SUBABORT_END:
			return "SUBABORT_END";
		case TBLOCK_SUBABORT_PENDING:
			return "SUBABORT_PENDING";
		case TBLOCK_SUBRESTART:
			return "SUBRESTART";
		case TBLOCK_SUBABORT_RESTART:
			return "SUBABORT_RESTART";
	}
	return "UNRECOGNIZED";
}


static const char * TransStateAsString(TransState state)
{
	switch (state)
	{
		case TRANS_DEFAULT:
			return "DEFAULT";
		case TRANS_START:
			return "START";
		case TRANS_INPROGRESS:
			return "INPROGRESS";
		case TRANS_COMMIT:
			return "COMMIT";
		case TRANS_ABORT:
			return "ABORT";
		case TRANS_PREPARE:
			return "PREPARE";
	}
	return "UNRECOGNIZED";
}


static void EndLocalDistribXact(bool isCommit)
{
	if (MyProc->localDistribXactData.state == LOCALDISTRIBXACT_STATE_NONE)
		return;

	
	switch (DistributedTransactionContext)
	{
		case DTX_CONTEXT_QE_TWO_PHASE_EXPLICIT_WRITER:
		case DTX_CONTEXT_QE_TWO_PHASE_IMPLICIT_WRITER:
		case DTX_CONTEXT_QE_AUTO_COMMIT_IMPLICIT:
		case DTX_CONTEXT_QD_DISTRIBUTED_CAPABLE:
		case DTX_CONTEXT_QD_RETRY_PHASE_2:
		case DTX_CONTEXT_LOCAL_ONLY:
			AssertImply(DistributedTransactionContext == DTX_CONTEXT_LOCAL_ONLY, Gp_role == GP_ROLE_UTILITY || IsAutoVacuumWorkerProcess());
			LocalDistribXact_ChangeState(MyProc->pgprocno, isCommit ? LOCALDISTRIBXACT_STATE_COMMITTED :

										 LOCALDISTRIBXACT_STATE_ABORTED);
			break;

		case DTX_CONTEXT_QE_READER:
		case DTX_CONTEXT_QE_ENTRY_DB_SINGLETON:
			
			break;

		case DTX_CONTEXT_QE_PREPARED:
		case DTX_CONTEXT_QE_FINISH_PREPARED:
			elog(PANIC, "Unexpected distribute transaction context: '%s'", DtxContextToString(DistributedTransactionContext));
			break;

		default:
			elog(PANIC, "Unrecognized DTX transaction context: %d", (int) DistributedTransactionContext);
			break;
	}
}


const char * IsoLevelAsUpperString(int IsoLevel)
{
	switch (IsoLevel)
	{
		case XACT_READ_UNCOMMITTED:
			return "READ UNCOMMITTED";
		case XACT_READ_COMMITTED:
			return "READ COMMITTED";
		case XACT_REPEATABLE_READ:
			return "REPEATABLE READ";
		case XACT_SERIALIZABLE:
			return "SERIALIZABLE";
		default:
			return "UNKNOWN";
	}
}



int xactGetCommittedChildren(TransactionId **ptr)
{
	TransactionState s = CurrentTransactionState;

	if (s->nChildXids == 0)
		*ptr = NULL;
	else *ptr = s->childXids;

	return s->nChildXids;
}



XLogRecPtr XactLogCommitRecord(TimestampTz commit_time, Oid tablespace_oid_to_delete_on_commit, int nsubxacts, TransactionId *subxacts, int nrels, RelFileNodePendingDelete *rels, int nmsgs, SharedInvalidationMessage *msgs, int ndeldbs, DbDirNode *deldbs, bool relcacheInval, bool forceSync, int xactflags, TransactionId twophase_xid, const char *twophase_gid)








{
	xl_xact_commit xlrec;
	xl_xact_xinfo xl_xinfo;
	xl_xact_dbinfo xl_dbinfo;
	xl_xact_subxacts xl_subxacts;
	xl_xact_relfilenodes xl_relfilenodes;
	xl_xact_invals xl_invals;
	xl_xact_twophase xl_twophase;
	xl_xact_origin xl_origin;
	xl_xact_distrib xl_distrib;
	xl_xact_deldbs xl_deldbs;
	XLogRecPtr recptr;
	bool isOnePhaseQE = (Gp_role == GP_ROLE_EXECUTE && MyTmGxactLocal->isOnePhaseCommit);
	bool isDtxPrepared = isPreparedDtxTransaction();

	uint8		info;

	Assert(CritSectionCount > 0);

	xl_xinfo.xinfo = 0;

	
	if (isDtxPrepared)
		info = XLOG_XACT_DISTRIBUTED_COMMIT;
	else if (!TransactionIdIsValid(twophase_xid))
		info = XLOG_XACT_COMMIT;
	else info = XLOG_XACT_COMMIT_PREPARED;

	

	xlrec.xact_time = commit_time;
	xlrec.tablespace_oid_to_delete_on_commit = tablespace_oid_to_delete_on_commit;

	if (relcacheInval)
		xl_xinfo.xinfo |= XACT_COMPLETION_UPDATE_RELCACHE_FILE;
	if (forceSyncCommit)
		xl_xinfo.xinfo |= XACT_COMPLETION_FORCE_SYNC_COMMIT;
	if ((xactflags & XACT_FLAGS_ACQUIREDACCESSEXCLUSIVELOCK))
		xl_xinfo.xinfo |= XACT_XINFO_HAS_AE_LOCKS;

	
	if (synchronous_commit >= SYNCHRONOUS_COMMIT_REMOTE_APPLY)
		xl_xinfo.xinfo |= XACT_COMPLETION_APPLY_FEEDBACK;

	
	if (nmsgs > 0 || XLogLogicalInfoActive())
	{
		xl_xinfo.xinfo |= XACT_XINFO_HAS_DBINFO;
		xl_dbinfo.dbId = MyDatabaseId;
		xl_dbinfo.tsId = MyDatabaseTableSpace;
	}

	if (nsubxacts > 0)
	{
		xl_xinfo.xinfo |= XACT_XINFO_HAS_SUBXACTS;
		xl_subxacts.nsubxacts = nsubxacts;
	}

	if (nrels > 0)
	{
		xl_xinfo.xinfo |= XACT_XINFO_HAS_RELFILENODES;
		xl_relfilenodes.nrels = nrels;
	}

	if (nmsgs > 0)
	{
		xl_xinfo.xinfo |= XACT_XINFO_HAS_INVALS;
		xl_invals.nmsgs = nmsgs;
	}

	if (ndeldbs > 0)
	{
		xl_xinfo.xinfo |= XACT_XINFO_HAS_DELDBS;
		xl_deldbs.ndeldbs = ndeldbs;
	}

	if (TransactionIdIsValid(twophase_xid))
	{
		xl_xinfo.xinfo |= XACT_XINFO_HAS_TWOPHASE;
		xl_twophase.xid = twophase_xid;
		Assert(twophase_gid != NULL);

		if (XLogLogicalInfoActive())
			xl_xinfo.xinfo |= XACT_XINFO_HAS_GID;
	}

	
	if (replorigin_session_origin != InvalidRepOriginId)
	{
		xl_xinfo.xinfo |= XACT_XINFO_HAS_ORIGIN;

		xl_origin.origin_lsn = replorigin_session_origin_lsn;
		xl_origin.origin_timestamp = replorigin_session_origin_timestamp;
	}

	if (isDtxPrepared || isOnePhaseQE)
	{
		xl_xinfo.xinfo |= XACT_XINFO_HAS_DISTRIB;
		xl_distrib.distrib_xid = getDistributedTransactionId();
	}

	if (xl_xinfo.xinfo != 0)
		info |= XLOG_XACT_HAS_INFO;

	

	XLogBeginInsert();

	XLogRegisterData((char *) (&xlrec), sizeof(xl_xact_commit));

	if (xl_xinfo.xinfo != 0)
		XLogRegisterData((char *) (&xl_xinfo.xinfo), sizeof(xl_xinfo.xinfo));

	if (xl_xinfo.xinfo & XACT_XINFO_HAS_DBINFO)
		XLogRegisterData((char *) (&xl_dbinfo), sizeof(xl_dbinfo));

	if (xl_xinfo.xinfo & XACT_XINFO_HAS_SUBXACTS)
	{
		XLogRegisterData((char *) (&xl_subxacts), MinSizeOfXactSubxacts);
		XLogRegisterData((char *) subxacts, nsubxacts * sizeof(TransactionId));
	}

	if (xl_xinfo.xinfo & XACT_XINFO_HAS_RELFILENODES)
	{
		XLogRegisterData((char *) (&xl_relfilenodes), MinSizeOfXactRelfilenodes);
		XLogRegisterData((char *) rels, nrels * sizeof(RelFileNodePendingDelete));
	}

	if (xl_xinfo.xinfo & XACT_XINFO_HAS_INVALS)
	{
		XLogRegisterData((char *) (&xl_invals), MinSizeOfXactInvals);
		XLogRegisterData((char *) msgs, nmsgs * sizeof(SharedInvalidationMessage));
	}

	if (xl_xinfo.xinfo & XACT_XINFO_HAS_DELDBS)
	{
		XLogRegisterData((char *) (&xl_deldbs), MinSizeOfXactDelDbs);
		XLogRegisterData((char *) deldbs, ndeldbs * sizeof(DbDirNode));
	}

	if (xl_xinfo.xinfo & XACT_XINFO_HAS_TWOPHASE)
	{
		XLogRegisterData((char *) (&xl_twophase), sizeof(xl_xact_twophase));
		if (xl_xinfo.xinfo & XACT_XINFO_HAS_GID)
			XLogRegisterData(unconstify(char *, twophase_gid), strlen(twophase_gid) + 1);
	}

	if (xl_xinfo.xinfo & XACT_XINFO_HAS_ORIGIN)
		XLogRegisterData((char *) (&xl_origin), sizeof(xl_xact_origin));

	if (xl_xinfo.xinfo & XACT_XINFO_HAS_DISTRIB)
		XLogRegisterData((char *) (&xl_distrib), sizeof(xl_xact_distrib));

	
	XLogSetRecordFlags(XLOG_INCLUDE_ORIGIN);

	if (isDtxPrepared)
		insertingDistributedCommitted();

	recptr = XLogInsert(RM_XACT_ID, info);

	if (isDtxPrepared)
		insertedDistributedCommitted();

	return recptr;
}


XLogRecPtr XactLogAbortRecord(TimestampTz abort_time, Oid tablespace_oid_to_delete_on_abort, int nsubxacts, TransactionId *subxacts, int nrels, RelFileNodePendingDelete *rels, int ndeldbs, DbDirNode *deldbs, int xactflags, TransactionId twophase_xid, const char *twophase_gid)






{
	xl_xact_abort xlrec;
	xl_xact_xinfo xl_xinfo;
	xl_xact_subxacts xl_subxacts;
	xl_xact_relfilenodes xl_relfilenodes;
	xl_xact_deldbs xl_deldbs;
	xl_xact_twophase xl_twophase;
	xl_xact_dbinfo xl_dbinfo;
	xl_xact_origin xl_origin;

	uint8		info;

	Assert(CritSectionCount > 0);

	xl_xinfo.xinfo = 0;

	
	if (!TransactionIdIsValid(twophase_xid))
		info = XLOG_XACT_ABORT;
	else info = XLOG_XACT_ABORT_PREPARED;


	

	xlrec.xact_time = abort_time;
	xlrec.tablespace_oid_to_delete_on_abort = tablespace_oid_to_delete_on_abort;

	if ((xactflags & XACT_FLAGS_ACQUIREDACCESSEXCLUSIVELOCK))
		xl_xinfo.xinfo |= XACT_XINFO_HAS_AE_LOCKS;

	if (nsubxacts > 0)
	{
		xl_xinfo.xinfo |= XACT_XINFO_HAS_SUBXACTS;
		xl_subxacts.nsubxacts = nsubxacts;
	}

	if (nrels > 0)
	{
		xl_xinfo.xinfo |= XACT_XINFO_HAS_RELFILENODES;
		xl_relfilenodes.nrels = nrels;
	}

	if (ndeldbs > 0)
	{
		xl_xinfo.xinfo |= XACT_XINFO_HAS_DELDBS;
		xl_deldbs.ndeldbs = ndeldbs;
	}

	if (TransactionIdIsValid(twophase_xid))
	{
		xl_xinfo.xinfo |= XACT_XINFO_HAS_TWOPHASE;
		xl_twophase.xid = twophase_xid;
		Assert(twophase_gid != NULL);

		if (XLogLogicalInfoActive())
			xl_xinfo.xinfo |= XACT_XINFO_HAS_GID;
	}

	if (TransactionIdIsValid(twophase_xid) && XLogLogicalInfoActive())
	{
		xl_xinfo.xinfo |= XACT_XINFO_HAS_DBINFO;
		xl_dbinfo.dbId = MyDatabaseId;
		xl_dbinfo.tsId = MyDatabaseTableSpace;
	}

	
	if ((replorigin_session_origin != InvalidRepOriginId) && TransactionIdIsValid(twophase_xid) && XLogLogicalInfoActive())

	{
		xl_xinfo.xinfo |= XACT_XINFO_HAS_ORIGIN;

		xl_origin.origin_lsn = replorigin_session_origin_lsn;
		xl_origin.origin_timestamp = replorigin_session_origin_timestamp;
	}

	if (xl_xinfo.xinfo != 0)
		info |= XLOG_XACT_HAS_INFO;

	

	XLogBeginInsert();

	XLogRegisterData((char *) (&xlrec), MinSizeOfXactAbort);

	if (xl_xinfo.xinfo != 0)
		XLogRegisterData((char *) (&xl_xinfo), sizeof(xl_xinfo));

	if (xl_xinfo.xinfo & XACT_XINFO_HAS_DBINFO)
		XLogRegisterData((char *) (&xl_dbinfo), sizeof(xl_dbinfo));

	if (xl_xinfo.xinfo & XACT_XINFO_HAS_SUBXACTS)
	{
		XLogRegisterData((char *) (&xl_subxacts), MinSizeOfXactSubxacts);
		XLogRegisterData((char *) subxacts, nsubxacts * sizeof(TransactionId));
	}

	if (xl_xinfo.xinfo & XACT_XINFO_HAS_RELFILENODES)
	{
		XLogRegisterData((char *) (&xl_relfilenodes), MinSizeOfXactRelfilenodes);
		XLogRegisterData((char *) rels, nrels * sizeof(RelFileNodePendingDelete));
	}

	if (xl_xinfo.xinfo & XACT_XINFO_HAS_DELDBS)
	{
		XLogRegisterData((char *) (&xl_deldbs), MinSizeOfXactDelDbs);
		XLogRegisterData((char *) deldbs, ndeldbs * sizeof(DbDirNode));
	}


	if (xl_xinfo.xinfo & XACT_XINFO_HAS_TWOPHASE)
	{
		XLogRegisterData((char *) (&xl_twophase), sizeof(xl_xact_twophase));
		if (xl_xinfo.xinfo & XACT_XINFO_HAS_GID)
			XLogRegisterData(unconstify(char *, twophase_gid), strlen(twophase_gid) + 1);
	}

	if (xl_xinfo.xinfo & XACT_XINFO_HAS_ORIGIN)
		XLogRegisterData((char *) (&xl_origin), sizeof(xl_xact_origin));

	if (TransactionIdIsValid(twophase_xid))
		XLogSetRecordFlags(XLOG_INCLUDE_ORIGIN);

	return XLogInsert(RM_XACT_ID, info);
}


static void xact_redo_commit(xl_xact_parsed_commit *parsed, TransactionId xid, XLogRecPtr lsn, RepOriginId origin_id)



{
	TransactionId max_xid;
	TimestampTz commit_time;
	Oid tablespace_oid_to_delete = parsed->tablespace_oid_to_delete_on_commit;

	Assert(TransactionIdIsValid(xid));

	max_xid = TransactionIdLatest(xid, parsed->nsubxacts, parsed->subxacts);

	ereportif(OidIsValid(tablespace_oid_to_delete), DEBUG5, (errmsg("in xact_redo_commit_internal with tablespace oid to delete: %u", tablespace_oid_to_delete)));


	
	AdvanceNextFullTransactionIdPastXid(max_xid);

	
	if (parsed->distribXid != 0)
	{
		DistributedLog_SetCommittedTree(xid, parsed->nsubxacts, parsed->subxacts, parsed->distribXid, true);

	}

	Assert(((parsed->xinfo & XACT_XINFO_HAS_ORIGIN) == 0) == (origin_id == InvalidRepOriginId));

	if (parsed->xinfo & XACT_XINFO_HAS_ORIGIN)
		commit_time = parsed->origin_timestamp;
	else commit_time = parsed->xact_time;

	
	TransactionTreeSetCommitTsData(xid, parsed->nsubxacts, parsed->subxacts, commit_time, origin_id, false);

	if (standbyState == STANDBY_DISABLED)
	{
		
		TransactionIdCommitTree(xid, parsed->nsubxacts, parsed->subxacts);
	}
	else {
		
		RecordKnownAssignedTransactionIds(max_xid);

		
		TransactionIdAsyncCommitTree( xid, parsed->nsubxacts, parsed->subxacts, lsn);

		
		ExpireTreeKnownAssignedTransactionIds( xid, parsed->nsubxacts, parsed->subxacts, max_xid);

		
		ProcessCommittedInvalidationMessages( parsed->msgs, parsed->nmsgs, XactCompletionRelcacheInitFileInval(parsed->xinfo), parsed->dbId, parsed->tsId);



		
		if (parsed->xinfo & XACT_XINFO_HAS_AE_LOCKS)
			StandbyReleaseLockTree(xid, parsed->nsubxacts, parsed->subxacts);
	}

	if (parsed->xinfo & XACT_XINFO_HAS_ORIGIN)
	{
		
		replorigin_advance(origin_id, parsed->origin_lsn, lsn, false  , false  );
	}

	
	if (parsed->nrels > 0)
	{
		
		XLogFlush(lsn);

		
		DropRelationFiles(parsed->xnodes, parsed->nrels, true);
	}

	if (parsed->ndeldbs > 0)
	{
		XLogFlush(lsn);
		DropDatabaseDirectories(parsed->deldbs, parsed->ndeldbs, true);
	}

	DoTablespaceDeletionForRedoXlog(tablespace_oid_to_delete);

	
	if (XactCompletionForceSyncCommit(parsed->xinfo))
		XLogFlush(lsn);

	
	if (XactCompletionApplyFeedback(parsed->xinfo))
		XLogRequestWalReceiverReply();
}


static void xact_redo_distributed_commit(xl_xact_parsed_commit *parsed, TransactionId xid, XLogRecPtr lsn, RepOriginId origin_id)



{
	if (TransactionIdIsValid(xid))
		xact_redo_commit(parsed, xid, lsn, origin_id);

	redoDistributedCommitRecord(parsed->distribXid);
}

static void xact_redo_abort(xl_xact_parsed_abort *parsed, TransactionId xid)
{
	TransactionId max_xid;

	Assert(TransactionIdIsValid(xid));

	
	max_xid = TransactionIdLatest(xid, parsed->nsubxacts, parsed->subxacts);

	AdvanceNextFullTransactionIdPastXid(max_xid);

	if (standbyState == STANDBY_DISABLED)
	{
		
		TransactionIdAbortTree(xid, parsed->nsubxacts, parsed->subxacts);
	}
	else {
		
		RecordKnownAssignedTransactionIds(max_xid);

		
		TransactionIdAbortTree(xid, parsed->nsubxacts, parsed->subxacts);

		
		ExpireTreeKnownAssignedTransactionIds( xid, parsed->nsubxacts, parsed->subxacts, max_xid);

		

		
		if (parsed->xinfo & XACT_XINFO_HAS_AE_LOCKS)
			StandbyReleaseLockTree(xid, parsed->nsubxacts, parsed->subxacts);
	}

	
	DropRelationFiles(parsed->xnodes, parsed->nrels, true);
	DropDatabaseDirectories(parsed->deldbs, parsed->ndeldbs, true);
	DoTablespaceDeletionForRedoXlog(parsed->tablespace_oid_to_delete_on_abort);
}

static void xact_redo_distributed_forget(xl_xact_distributed_forget *xlrec, TransactionId xid pg_attribute_unused() )
{
	redoDistributedForgetCommitRecord(xlrec->gxid);
}


void xact_redo(XLogReaderState *record)
{
	uint8		info = XLogRecGetInfo(record) & XLOG_XACT_OPMASK;

	
	Assert(!XLogRecHasAnyBlockRefs(record));

	if (info == XLOG_XACT_COMMIT)
	{
		xl_xact_commit *xlrec = (xl_xact_commit *) XLogRecGetData(record);
		xl_xact_parsed_commit parsed;

		ParseCommitRecord(XLogRecGetInfo(record), xlrec, &parsed);
		xact_redo_commit(&parsed, XLogRecGetXid(record), record->EndRecPtr, XLogRecGetOrigin(record));
	}
	else if (info == XLOG_XACT_COMMIT_PREPARED)
	{
		xl_xact_commit *xlrec = (xl_xact_commit *) XLogRecGetData(record);
		xl_xact_parsed_commit parsed;

		ParseCommitRecord(XLogRecGetInfo(record), xlrec, &parsed);
		xact_redo_commit(&parsed, parsed.twophase_xid, record->EndRecPtr, XLogRecGetOrigin(record));

		
		LWLockAcquire(TwoPhaseStateLock, LW_EXCLUSIVE);
		PrepareRedoRemove(parsed.twophase_xid, false);
		LWLockRelease(TwoPhaseStateLock);
	}
	else if (info == XLOG_XACT_ABORT)
	{
		xl_xact_abort *xlrec = (xl_xact_abort *) XLogRecGetData(record);
		xl_xact_parsed_abort parsed;

		ParseAbortRecord(XLogRecGetInfo(record), xlrec, &parsed);
		xact_redo_abort(&parsed, XLogRecGetXid(record));
	}
	else if (info == XLOG_XACT_ABORT_PREPARED)
	{
		xl_xact_abort *xlrec = (xl_xact_abort *) XLogRecGetData(record);
		xl_xact_parsed_abort parsed;

		ParseAbortRecord(XLogRecGetInfo(record), xlrec, &parsed);
		xact_redo_abort(&parsed, parsed.twophase_xid);

		
		LWLockAcquire(TwoPhaseStateLock, LW_EXCLUSIVE);
		PrepareRedoRemove(parsed.twophase_xid, false);
		LWLockRelease(TwoPhaseStateLock);
	}
	else if (info == XLOG_XACT_PREPARE)
	{
		
		LWLockAcquire(TwoPhaseStateLock, LW_EXCLUSIVE);
		PrepareRedoAdd(XLogRecGetData(record), record->ReadRecPtr, record->EndRecPtr, XLogRecGetOrigin(record));


		LWLockRelease(TwoPhaseStateLock);
	}
	else if (info == XLOG_XACT_DISTRIBUTED_COMMIT)
	{
		xl_xact_commit *xlrec = (xl_xact_commit *) XLogRecGetData(record);
		xl_xact_parsed_commit parsed;

		ParseCommitRecord(XLogRecGetInfo(record), xlrec, &parsed);
		Assert(parsed.twophase_xid == InvalidTransactionId);
		xact_redo_distributed_commit(&parsed, XLogRecGetXid(record), record->EndRecPtr, XLogRecGetOrigin(record));
	}
	else if (info == XLOG_XACT_DISTRIBUTED_FORGET)
	{
		xl_xact_distributed_forget *xlrec = (xl_xact_distributed_forget *) XLogRecGetData(record);

		xact_redo_distributed_forget(xlrec, XLogRecGetXid(record));
	}
	else if (info == XLOG_XACT_ASSIGNMENT)
	{
		xl_xact_assignment *xlrec = (xl_xact_assignment *) XLogRecGetData(record);

		if (standbyState >= STANDBY_INITIALIZED)
			ProcArrayApplyXidAssignment(xlrec->xtop, xlrec->nsubxacts, xlrec->xsub);
	}
	else elog(PANIC, "xact_redo: unknown op code %u", info);
}
