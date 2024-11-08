
































typedef struct ExprEvalOpLookup {
	const void *opcode;
	ExprEvalOp	op;
} ExprEvalOpLookup;


static const void **dispatch_table = NULL;


static ExprEvalOpLookup reverse_dispatch_table[EEOP_LAST];


























static Datum ExecInterpExpr(ExprState *state, ExprContext *econtext, bool *isnull);
static void ExecInitInterpreter(void);


static void CheckVarSlotCompatibility(TupleTableSlot *slot, int attnum, Oid vartype);
static TupleDesc get_cached_rowtype(Oid type_id, int32 typmod, ExprEvalRowtypeCache *rowcache, bool *changed);

static void ExecEvalRowNullInt(ExprState *state, ExprEvalStep *op, ExprContext *econtext, bool checkisnull);


static Datum ExecJustInnerVar(ExprState *state, ExprContext *econtext, bool *isnull);
static Datum ExecJustOuterVar(ExprState *state, ExprContext *econtext, bool *isnull);
static Datum ExecJustScanVar(ExprState *state, ExprContext *econtext, bool *isnull);
static Datum ExecJustConst(ExprState *state, ExprContext *econtext, bool *isnull);
static Datum ExecJustAssignInnerVar(ExprState *state, ExprContext *econtext, bool *isnull);
static Datum ExecJustAssignOuterVar(ExprState *state, ExprContext *econtext, bool *isnull);
static Datum ExecJustAssignScanVar(ExprState *state, ExprContext *econtext, bool *isnull);
static Datum ExecJustApplyFuncToCase(ExprState *state, ExprContext *econtext, bool *isnull);



void ExecReadyInterpretedExpr(ExprState *state)
{
	
	ExecInitInterpreter();

	
	Assert(state->steps_len >= 1);
	Assert(state->steps[state->steps_len - 1].opcode == EEOP_DONE);

	
	if (state->flags & EEO_FLAG_INTERPRETER_INITIALIZED)
		return;

	
	state->evalfunc = ExecInterpExprStillValid;

	
	Assert((state->flags & EEO_FLAG_DIRECT_THREADED) == 0);

	
	state->flags |= EEO_FLAG_INTERPRETER_INITIALIZED;

	
	if (state->steps_len == 3)
	{
		ExprEvalOp	step0 = state->steps[0].opcode;
		ExprEvalOp	step1 = state->steps[1].opcode;

		if (step0 == EEOP_INNER_FETCHSOME && step1 == EEOP_INNER_VAR)
		{
			state->evalfunc_private = (void *) ExecJustInnerVar;
			return;
		}
		else if (step0 == EEOP_OUTER_FETCHSOME && step1 == EEOP_OUTER_VAR)
		{
			state->evalfunc_private = (void *) ExecJustOuterVar;
			return;
		}
		else if (step0 == EEOP_SCAN_FETCHSOME && step1 == EEOP_SCAN_VAR)
		{
			state->evalfunc_private = (void *) ExecJustScanVar;
			return;
		}
		else if (step0 == EEOP_INNER_FETCHSOME && step1 == EEOP_ASSIGN_INNER_VAR)
		{
			state->evalfunc_private = (void *) ExecJustAssignInnerVar;
			return;
		}
		else if (step0 == EEOP_OUTER_FETCHSOME && step1 == EEOP_ASSIGN_OUTER_VAR)
		{
			state->evalfunc_private = (void *) ExecJustAssignOuterVar;
			return;
		}
		else if (step0 == EEOP_SCAN_FETCHSOME && step1 == EEOP_ASSIGN_SCAN_VAR)
		{
			state->evalfunc_private = (void *) ExecJustAssignScanVar;
			return;
		}
		else if (step0 == EEOP_CASE_TESTVAL && step1 == EEOP_FUNCEXPR_STRICT && state->steps[0].d.casetest.value)

		{
			state->evalfunc_private = (void *) ExecJustApplyFuncToCase;
			return;
		}
	}
	else if (state->steps_len == 2 && state->steps[0].opcode == EEOP_CONST)
	{
		state->evalfunc_private = (void *) ExecJustConst;
		return;
	}



	
	{
		int			off;

		for (off = 0; off < state->steps_len; off++)
		{
			ExprEvalStep *op = &state->steps[off];

			op->opcode = EEO_OPCODE(op->opcode);
		}

		state->flags |= EEO_FLAG_DIRECT_THREADED;
	}


	state->evalfunc_private = (void *) ExecInterpExpr;
}



static Datum ExecInterpExpr(ExprState *state, ExprContext *econtext, bool *isnull)
{
	ExprEvalStep *op;
	TupleTableSlot *resultslot;
	TupleTableSlot *innerslot;
	TupleTableSlot *outerslot;
	TupleTableSlot *scanslot;

	

	static const void *const dispatch_table[] = {
		&&CASE_EEOP_DONE, &&CASE_EEOP_INNER_FETCHSOME, &&CASE_EEOP_OUTER_FETCHSOME, &&CASE_EEOP_SCAN_FETCHSOME, &&CASE_EEOP_INNER_VAR, &&CASE_EEOP_OUTER_VAR, &&CASE_EEOP_SCAN_VAR, &&CASE_EEOP_INNER_SYSVAR, &&CASE_EEOP_OUTER_SYSVAR, &&CASE_EEOP_SCAN_SYSVAR, &&CASE_EEOP_WHOLEROW, &&CASE_EEOP_ASSIGN_INNER_VAR, &&CASE_EEOP_ASSIGN_OUTER_VAR, &&CASE_EEOP_ASSIGN_SCAN_VAR, &&CASE_EEOP_ASSIGN_TMP, &&CASE_EEOP_ASSIGN_TMP_MAKE_RO, &&CASE_EEOP_CONST, &&CASE_EEOP_FUNCEXPR, &&CASE_EEOP_FUNCEXPR_STRICT, &&CASE_EEOP_FUNCEXPR_FUSAGE, &&CASE_EEOP_FUNCEXPR_STRICT_FUSAGE, &&CASE_EEOP_BOOL_AND_STEP_FIRST, &&CASE_EEOP_BOOL_AND_STEP, &&CASE_EEOP_BOOL_AND_STEP_LAST, &&CASE_EEOP_BOOL_OR_STEP_FIRST, &&CASE_EEOP_BOOL_OR_STEP, &&CASE_EEOP_BOOL_OR_STEP_LAST, &&CASE_EEOP_BOOL_NOT_STEP, &&CASE_EEOP_QUAL, &&CASE_EEOP_JUMP, &&CASE_EEOP_JUMP_IF_NULL, &&CASE_EEOP_JUMP_IF_NOT_NULL, &&CASE_EEOP_JUMP_IF_NOT_TRUE, &&CASE_EEOP_NULLTEST_ISNULL, &&CASE_EEOP_NULLTEST_ISNOTNULL, &&CASE_EEOP_NULLTEST_ROWISNULL, &&CASE_EEOP_NULLTEST_ROWISNOTNULL, &&CASE_EEOP_BOOLTEST_IS_TRUE, &&CASE_EEOP_BOOLTEST_IS_NOT_TRUE, &&CASE_EEOP_BOOLTEST_IS_FALSE, &&CASE_EEOP_BOOLTEST_IS_NOT_FALSE, &&CASE_EEOP_PARAM_EXEC, &&CASE_EEOP_PARAM_EXTERN, &&CASE_EEOP_PARAM_CALLBACK, &&CASE_EEOP_CASE_TESTVAL, &&CASE_EEOP_MAKE_READONLY, &&CASE_EEOP_IOCOERCE, &&CASE_EEOP_DISTINCT, &&CASE_EEOP_NOT_DISTINCT, &&CASE_EEOP_NULLIF, &&CASE_EEOP_SQLVALUEFUNCTION, &&CASE_EEOP_CURRENTOFEXPR, &&CASE_EEOP_NEXTVALUEEXPR, &&CASE_EEOP_ARRAYEXPR, &&CASE_EEOP_ARRAYCOERCE, &&CASE_EEOP_ROW, &&CASE_EEOP_ROWCOMPARE_STEP, &&CASE_EEOP_ROWCOMPARE_FINAL, &&CASE_EEOP_MINMAX, &&CASE_EEOP_FIELDSELECT, &&CASE_EEOP_FIELDSTORE_DEFORM, &&CASE_EEOP_FIELDSTORE_FORM, &&CASE_EEOP_ARRAYREF_SUBSCRIPT, &&CASE_EEOP_ARRAYREF_OLD, &&CASE_EEOP_ARRAYREF_ASSIGN, &&CASE_EEOP_ARRAYREF_FETCH, &&CASE_EEOP_DOMAIN_TESTVAL, &&CASE_EEOP_DOMAIN_NOTNULL, &&CASE_EEOP_DOMAIN_CHECK, &&CASE_EEOP_CONVERT_ROWTYPE, &&CASE_EEOP_SCALARARRAYOP, &&CASE_EEOP_XMLEXPR, &&CASE_EEOP_AGGREF, &&CASE_EEOP_GROUPING_FUNC, &&CASE_EEOP_WINDOW_FUNC, &&CASE_EEOP_SUBPLAN, &&CASE_EEOP_ALTERNATIVE_SUBPLAN, &&CASE_EEOP_AGG_STRICT_DESERIALIZE, &&CASE_EEOP_AGG_DESERIALIZE, &&CASE_EEOP_AGG_STRICT_INPUT_CHECK_ARGS, &&CASE_EEOP_AGG_STRICT_INPUT_CHECK_NULLS, &&CASE_EEOP_AGG_INIT_TRANS, &&CASE_EEOP_AGG_STRICT_TRANS_CHECK, &&CASE_EEOP_AGG_PLAIN_TRANS_BYVAL, &&CASE_EEOP_AGG_PLAIN_TRANS, &&CASE_EEOP_AGG_ORDERED_TRANS_DATUM, &&CASE_EEOP_AGG_ORDERED_TRANS_TUPLE, &&CASE_EEOP_LAST };
























































































	StaticAssertStmt(EEOP_LAST + 1 == lengthof(dispatch_table), "dispatch_table out of whack with ExprEvalOp");

	if (unlikely(state == NULL))
		return PointerGetDatum(dispatch_table);

	Assert(state != NULL);


	
	op = state->steps;
	resultslot = state->resultslot;
	innerslot = econtext->ecxt_innertuple;
	outerslot = econtext->ecxt_outertuple;
	scanslot = econtext->ecxt_scantuple;


	EEO_DISPATCH();


	EEO_SWITCH()
	{
		EEO_CASE(EEOP_DONE)
		{
			goto out;
		}

		EEO_CASE(EEOP_INNER_FETCHSOME)
		{
			
			slot_getsomeattrs(innerslot, op->d.fetch.last_var);

			EEO_NEXT();
		}

		EEO_CASE(EEOP_OUTER_FETCHSOME)
		{
			slot_getsomeattrs(outerslot, op->d.fetch.last_var);

			EEO_NEXT();
		}

		EEO_CASE(EEOP_SCAN_FETCHSOME)
		{
			slot_getsomeattrs(scanslot, op->d.fetch.last_var);

			EEO_NEXT();
		}

		EEO_CASE(EEOP_INNER_VAR)
		{
			int			attnum = op->d.var.attnum;

			
			Assert(attnum >= 0 && attnum < innerslot->tts_nvalid);
			*op->resvalue = innerslot->tts_values[attnum];
			*op->resnull = innerslot->tts_isnull[attnum];

			EEO_NEXT();
		}

		EEO_CASE(EEOP_OUTER_VAR)
		{
			int			attnum = op->d.var.attnum;

			

			Assert(attnum >= 0 && attnum < outerslot->tts_nvalid);
			*op->resvalue = outerslot->tts_values[attnum];
			*op->resnull = outerslot->tts_isnull[attnum];

			EEO_NEXT();
		}

		EEO_CASE(EEOP_SCAN_VAR)
		{
			int			attnum = op->d.var.attnum;

			

			Assert(attnum >= 0 && attnum < scanslot->tts_nvalid);
			*op->resvalue = scanslot->tts_values[attnum];
			*op->resnull = scanslot->tts_isnull[attnum];

			EEO_NEXT();
		}

		EEO_CASE(EEOP_INNER_SYSVAR)
		{
			int			attnum = op->d.var.attnum;
			Datum		d;

			
			Assert(innerslot->tts_tuple != NULL);
			Assert(innerslot->tts_tuple != &(innerslot->tts_minhdr));

			
			d = heap_getsysattr(innerslot->tts_tuple, attnum, innerslot->tts_tupleDescriptor, op->resnull);

			*op->resvalue = d;

			EEO_NEXT();
		}

		EEO_CASE(EEOP_OUTER_SYSVAR)
		{
			int			attnum = op->d.var.attnum;
			Datum		d;

			
			Assert(outerslot->tts_tuple != NULL);
			Assert(outerslot->tts_tuple != &(outerslot->tts_minhdr));

			
			d = heap_getsysattr(outerslot->tts_tuple, attnum, outerslot->tts_tupleDescriptor, op->resnull);

			*op->resvalue = d;

			EEO_NEXT();
		}

		EEO_CASE(EEOP_SCAN_SYSVAR)
		{
			int			attnum = op->d.var.attnum;
			Datum		d;

			
			Assert(scanslot->tts_tuple != NULL);
			Assert(scanslot->tts_tuple != &(scanslot->tts_minhdr));

			
			d = heap_getsysattr(scanslot->tts_tuple, attnum, scanslot->tts_tupleDescriptor, op->resnull);

			*op->resvalue = d;

			EEO_NEXT();
		}

		EEO_CASE(EEOP_WHOLEROW)
		{
			
			ExecEvalWholeRowVar(state, op, econtext);

			EEO_NEXT();
		}

		EEO_CASE(EEOP_ASSIGN_INNER_VAR)
		{
			int			resultnum = op->d.assign_var.resultnum;
			int			attnum = op->d.assign_var.attnum;

			
			Assert(attnum >= 0 && attnum < innerslot->tts_nvalid);
			resultslot->tts_values[resultnum] = innerslot->tts_values[attnum];
			resultslot->tts_isnull[resultnum] = innerslot->tts_isnull[attnum];

			EEO_NEXT();
		}

		EEO_CASE(EEOP_ASSIGN_OUTER_VAR)
		{
			int			resultnum = op->d.assign_var.resultnum;
			int			attnum = op->d.assign_var.attnum;

			
			Assert(attnum >= 0 && attnum < outerslot->tts_nvalid);
			resultslot->tts_values[resultnum] = outerslot->tts_values[attnum];
			resultslot->tts_isnull[resultnum] = outerslot->tts_isnull[attnum];

			EEO_NEXT();
		}

		EEO_CASE(EEOP_ASSIGN_SCAN_VAR)
		{
			int			resultnum = op->d.assign_var.resultnum;
			int			attnum = op->d.assign_var.attnum;

			
			Assert(attnum >= 0 && attnum < scanslot->tts_nvalid);
			resultslot->tts_values[resultnum] = scanslot->tts_values[attnum];
			resultslot->tts_isnull[resultnum] = scanslot->tts_isnull[attnum];

			EEO_NEXT();
		}

		EEO_CASE(EEOP_ASSIGN_TMP)
		{
			int			resultnum = op->d.assign_tmp.resultnum;

			resultslot->tts_values[resultnum] = state->resvalue;
			resultslot->tts_isnull[resultnum] = state->resnull;

			EEO_NEXT();
		}

		EEO_CASE(EEOP_ASSIGN_TMP_MAKE_RO)
		{
			int			resultnum = op->d.assign_tmp.resultnum;

			resultslot->tts_isnull[resultnum] = state->resnull;
			if (!resultslot->tts_isnull[resultnum])
				resultslot->tts_values[resultnum] = MakeExpandedObjectReadOnlyInternal(state->resvalue);
			else resultslot->tts_values[resultnum] = state->resvalue;

			EEO_NEXT();
		}

		EEO_CASE(EEOP_CONST)
		{
			*op->resnull = op->d.constval.isnull;
			*op->resvalue = op->d.constval.value;

			EEO_NEXT();
		}

		
		EEO_CASE(EEOP_FUNCEXPR)
		{
			FunctionCallInfo fcinfo = op->d.func.fcinfo_data;
			Datum		d;

			fcinfo->isnull = false;
			d = op->d.func.fn_addr(fcinfo);
			*op->resvalue = d;
			*op->resnull = fcinfo->isnull;

			EEO_NEXT();
		}

		EEO_CASE(EEOP_FUNCEXPR_STRICT)
		{
			FunctionCallInfo fcinfo = op->d.func.fcinfo_data;
			NullableDatum *args = fcinfo->args;
			int			argno;
			Datum		d;

			
			for (argno = 0; argno < op->d.func.nargs; argno++)
			{
				if (args[argno].isnull)
				{
					*op->resnull = true;
					goto strictfail;
				}
			}
			fcinfo->isnull = false;
			d = op->d.func.fn_addr(fcinfo);
			*op->resvalue = d;
			*op->resnull = fcinfo->isnull;

	strictfail:
			EEO_NEXT();
		}

		EEO_CASE(EEOP_FUNCEXPR_FUSAGE)
		{
			
			ExecEvalFuncExprFusage(state, op, econtext);

			EEO_NEXT();
		}

		EEO_CASE(EEOP_FUNCEXPR_STRICT_FUSAGE)
		{
			
			ExecEvalFuncExprStrictFusage(state, op, econtext);

			EEO_NEXT();
		}

		
		EEO_CASE(EEOP_BOOL_AND_STEP_FIRST)
		{
			*op->d.boolexpr.anynull = false;

			

			
		}

		EEO_CASE(EEOP_BOOL_AND_STEP)
		{
			if (*op->resnull)
			{
				*op->d.boolexpr.anynull = true;
			}
			else if (!DatumGetBool(*op->resvalue))
			{
				
				
				EEO_JUMP(op->d.boolexpr.jumpdone);
			}

			EEO_NEXT();
		}

		EEO_CASE(EEOP_BOOL_AND_STEP_LAST)
		{
			if (*op->resnull)
			{
				
			}
			else if (!DatumGetBool(*op->resvalue))
			{
				

				
			}
			else if (*op->d.boolexpr.anynull)
			{
				*op->resvalue = (Datum) 0;
				*op->resnull = true;
			}
			else {
				
			}

			EEO_NEXT();
		}

		
		EEO_CASE(EEOP_BOOL_OR_STEP_FIRST)
		{
			*op->d.boolexpr.anynull = false;

			

			
		}

		EEO_CASE(EEOP_BOOL_OR_STEP)
		{
			if (*op->resnull)
			{
				*op->d.boolexpr.anynull = true;
			}
			else if (DatumGetBool(*op->resvalue))
			{
				
				
				EEO_JUMP(op->d.boolexpr.jumpdone);
			}

			EEO_NEXT();
		}

		EEO_CASE(EEOP_BOOL_OR_STEP_LAST)
		{
			if (*op->resnull)
			{
				
			}
			else if (DatumGetBool(*op->resvalue))
			{
				

				
			}
			else if (*op->d.boolexpr.anynull)
			{
				*op->resvalue = (Datum) 0;
				*op->resnull = true;
			}
			else {
				
			}

			EEO_NEXT();
		}

		EEO_CASE(EEOP_BOOL_NOT_STEP)
		{
			
			*op->resvalue = BoolGetDatum(!DatumGetBool(*op->resvalue));

			EEO_NEXT();
		}

		EEO_CASE(EEOP_QUAL)
		{
			

			
			if (*op->resnull || !DatumGetBool(*op->resvalue))
			{
				
				*op->resnull = false;
				*op->resvalue = BoolGetDatum(false);
				EEO_JUMP(op->d.qualexpr.jumpdone);
			}

			

			EEO_NEXT();
		}

		EEO_CASE(EEOP_JUMP)
		{
			
			EEO_JUMP(op->d.jump.jumpdone);
		}

		EEO_CASE(EEOP_JUMP_IF_NULL)
		{
			
			if (*op->resnull)
				EEO_JUMP(op->d.jump.jumpdone);

			EEO_NEXT();
		}

		EEO_CASE(EEOP_JUMP_IF_NOT_NULL)
		{
			
			if (!*op->resnull)
				EEO_JUMP(op->d.jump.jumpdone);

			EEO_NEXT();
		}

		EEO_CASE(EEOP_JUMP_IF_NOT_TRUE)
		{
			
			if (*op->resnull || !DatumGetBool(*op->resvalue))
				EEO_JUMP(op->d.jump.jumpdone);

			EEO_NEXT();
		}

		EEO_CASE(EEOP_NULLTEST_ISNULL)
		{
			*op->resvalue = BoolGetDatum(*op->resnull);
			*op->resnull = false;

			EEO_NEXT();
		}

		EEO_CASE(EEOP_NULLTEST_ISNOTNULL)
		{
			*op->resvalue = BoolGetDatum(!*op->resnull);
			*op->resnull = false;

			EEO_NEXT();
		}

		EEO_CASE(EEOP_NULLTEST_ROWISNULL)
		{
			
			ExecEvalRowNull(state, op, econtext);

			EEO_NEXT();
		}

		EEO_CASE(EEOP_NULLTEST_ROWISNOTNULL)
		{
			
			ExecEvalRowNotNull(state, op, econtext);

			EEO_NEXT();
		}

		

		EEO_CASE(EEOP_BOOLTEST_IS_TRUE)
		{
			if (*op->resnull)
			{
				*op->resvalue = BoolGetDatum(false);
				*op->resnull = false;
			}
			

			EEO_NEXT();
		}

		EEO_CASE(EEOP_BOOLTEST_IS_NOT_TRUE)
		{
			if (*op->resnull)
			{
				*op->resvalue = BoolGetDatum(true);
				*op->resnull = false;
			}
			else *op->resvalue = BoolGetDatum(!DatumGetBool(*op->resvalue));

			EEO_NEXT();
		}

		EEO_CASE(EEOP_BOOLTEST_IS_FALSE)
		{
			if (*op->resnull)
			{
				*op->resvalue = BoolGetDatum(false);
				*op->resnull = false;
			}
			else *op->resvalue = BoolGetDatum(!DatumGetBool(*op->resvalue));

			EEO_NEXT();
		}

		EEO_CASE(EEOP_BOOLTEST_IS_NOT_FALSE)
		{
			if (*op->resnull)
			{
				*op->resvalue = BoolGetDatum(true);
				*op->resnull = false;
			}
			

			EEO_NEXT();
		}

		EEO_CASE(EEOP_PARAM_EXEC)
		{
			
			ExecEvalParamExec(state, op, econtext);

			EEO_NEXT();
		}

		EEO_CASE(EEOP_PARAM_EXTERN)
		{
			
			ExecEvalParamExtern(state, op, econtext);
			EEO_NEXT();
		}

		EEO_CASE(EEOP_PARAM_CALLBACK)
		{
			
			op->d.cparam.paramfunc(state, op, econtext);
			EEO_NEXT();
		}

		EEO_CASE(EEOP_CASE_TESTVAL)
		{
			
			if (op->d.casetest.value)
			{
				*op->resvalue = *op->d.casetest.value;
				*op->resnull = *op->d.casetest.isnull;
			}
			else {
				*op->resvalue = econtext->caseValue_datum;
				*op->resnull = econtext->caseValue_isNull;
			}

			EEO_NEXT();
		}

		EEO_CASE(EEOP_DOMAIN_TESTVAL)
		{
			
			if (op->d.casetest.value)
			{
				*op->resvalue = *op->d.casetest.value;
				*op->resnull = *op->d.casetest.isnull;
			}
			else {
				*op->resvalue = econtext->domainValue_datum;
				*op->resnull = econtext->domainValue_isNull;
			}

			EEO_NEXT();
		}

		EEO_CASE(EEOP_MAKE_READONLY)
		{
			
			if (!*op->d.make_readonly.isnull)
				*op->resvalue = MakeExpandedObjectReadOnlyInternal(*op->d.make_readonly.value);
			*op->resnull = *op->d.make_readonly.isnull;

			EEO_NEXT();
		}

		EEO_CASE(EEOP_IOCOERCE)
		{
			
			char	   *str;

			
			if (*op->resnull)
			{
				
				str = NULL;
			}
			else {
				FunctionCallInfo fcinfo_out;

				fcinfo_out = op->d.iocoerce.fcinfo_data_out;
				fcinfo_out->args[0].value = *op->resvalue;
				fcinfo_out->args[0].isnull = false;

				fcinfo_out->isnull = false;
				str = DatumGetCString(FunctionCallInvoke(fcinfo_out));

				
				Assert(!fcinfo_out->isnull);
			}

			
			if (!op->d.iocoerce.finfo_in->fn_strict || str != NULL)
			{
				FunctionCallInfo fcinfo_in;
				Datum		d;

				fcinfo_in = op->d.iocoerce.fcinfo_data_in;
				fcinfo_in->args[0].value = PointerGetDatum(str);
				fcinfo_in->args[0].isnull = *op->resnull;
				

				fcinfo_in->isnull = false;
				d = FunctionCallInvoke(fcinfo_in);
				*op->resvalue = d;

				
				if (str == NULL)
				{
					Assert(*op->resnull);
					Assert(fcinfo_in->isnull);
				}
				else {
					Assert(!*op->resnull);
					Assert(!fcinfo_in->isnull);
				}
			}

			EEO_NEXT();
		}

		EEO_CASE(EEOP_DISTINCT)
		{
			
			FunctionCallInfo fcinfo = op->d.func.fcinfo_data;

			
			if (fcinfo->args[0].isnull && fcinfo->args[1].isnull)
			{
				
				*op->resvalue = BoolGetDatum(false);
				*op->resnull = false;
			}
			else if (fcinfo->args[0].isnull || fcinfo->args[1].isnull)
			{
				
				*op->resvalue = BoolGetDatum(true);
				*op->resnull = false;
			}
			else {
				
				Datum		eqresult;

				fcinfo->isnull = false;
				eqresult = op->d.func.fn_addr(fcinfo);
				
				*op->resvalue = BoolGetDatum(!DatumGetBool(eqresult));
				*op->resnull = fcinfo->isnull;
			}

			EEO_NEXT();
		}

		
		EEO_CASE(EEOP_NOT_DISTINCT)
		{
			FunctionCallInfo fcinfo = op->d.func.fcinfo_data;

			if (fcinfo->args[0].isnull && fcinfo->args[1].isnull)
			{
				*op->resvalue = BoolGetDatum(true);
				*op->resnull = false;
			}
			else if (fcinfo->args[0].isnull || fcinfo->args[1].isnull)
			{
				*op->resvalue = BoolGetDatum(false);
				*op->resnull = false;
			}
			else {
				Datum		eqresult;

				fcinfo->isnull = false;
				eqresult = op->d.func.fn_addr(fcinfo);
				*op->resvalue = eqresult;
				*op->resnull = fcinfo->isnull;
			}

			EEO_NEXT();
		}

		EEO_CASE(EEOP_NULLIF)
		{
			
			FunctionCallInfo fcinfo = op->d.func.fcinfo_data;

			
			if (!fcinfo->args[0].isnull && !fcinfo->args[1].isnull)
			{
				Datum		result;

				fcinfo->isnull = false;
				result = op->d.func.fn_addr(fcinfo);

				
				if (!fcinfo->isnull && DatumGetBool(result))
				{
					*op->resvalue = (Datum) 0;
					*op->resnull = true;

					EEO_NEXT();
				}
			}

			
			*op->resvalue = fcinfo->args[0].value;
			*op->resnull = fcinfo->args[0].isnull;

			EEO_NEXT();
		}

		EEO_CASE(EEOP_SQLVALUEFUNCTION)
		{
			
			ExecEvalSQLValueFunction(state, op);

			EEO_NEXT();
		}

		EEO_CASE(EEOP_CURRENTOFEXPR)
		{
			
			ExecEvalCurrentOfExpr(state, op);

			EEO_NEXT();
		}

		EEO_CASE(EEOP_NEXTVALUEEXPR)
		{
			
			ExecEvalNextValueExpr(state, op);

			EEO_NEXT();
		}

		EEO_CASE(EEOP_ARRAYEXPR)
		{
			
			ExecEvalArrayExpr(state, op);

			EEO_NEXT();
		}

		EEO_CASE(EEOP_ARRAYCOERCE)
		{
			
			ExecEvalArrayCoerce(state, op, econtext);

			EEO_NEXT();
		}

		EEO_CASE(EEOP_ROW)
		{
			
			ExecEvalRow(state, op);

			EEO_NEXT();
		}

		EEO_CASE(EEOP_ROWCOMPARE_STEP)
		{
			FunctionCallInfo fcinfo = op->d.rowcompare_step.fcinfo_data;
			Datum		d;

			
			if (op->d.rowcompare_step.finfo->fn_strict && (fcinfo->args[0].isnull || fcinfo->args[1].isnull))
			{
				*op->resnull = true;
				EEO_JUMP(op->d.rowcompare_step.jumpnull);
			}

			
			fcinfo->isnull = false;
			d = op->d.rowcompare_step.fn_addr(fcinfo);
			*op->resvalue = d;

			
			if (fcinfo->isnull)
			{
				*op->resnull = true;
				EEO_JUMP(op->d.rowcompare_step.jumpnull);
			}
			*op->resnull = false;

			
			if (DatumGetInt32(*op->resvalue) != 0)
			{
				EEO_JUMP(op->d.rowcompare_step.jumpdone);
			}

			EEO_NEXT();
		}

		EEO_CASE(EEOP_ROWCOMPARE_FINAL)
		{
			int32		cmpresult = DatumGetInt32(*op->resvalue);
			RowCompareType rctype = op->d.rowcompare_final.rctype;

			*op->resnull = false;
			switch (rctype)
			{
					
				case ROWCOMPARE_LT:
					*op->resvalue = BoolGetDatum(cmpresult < 0);
					break;
				case ROWCOMPARE_LE:
					*op->resvalue = BoolGetDatum(cmpresult <= 0);
					break;
				case ROWCOMPARE_GE:
					*op->resvalue = BoolGetDatum(cmpresult >= 0);
					break;
				case ROWCOMPARE_GT:
					*op->resvalue = BoolGetDatum(cmpresult > 0);
					break;
				default:
					Assert(false);
					break;
			}

			EEO_NEXT();
		}

		EEO_CASE(EEOP_MINMAX)
		{
			
			ExecEvalMinMax(state, op);

			EEO_NEXT();
		}

		EEO_CASE(EEOP_FIELDSELECT)
		{
			
			ExecEvalFieldSelect(state, op, econtext);

			EEO_NEXT();
		}

		EEO_CASE(EEOP_FIELDSTORE_DEFORM)
		{
			
			ExecEvalFieldStoreDeForm(state, op, econtext);

			EEO_NEXT();
		}

		EEO_CASE(EEOP_FIELDSTORE_FORM)
		{
			
			ExecEvalFieldStoreForm(state, op, econtext);

			EEO_NEXT();
		}

		EEO_CASE(EEOP_ARRAYREF_SUBSCRIPT)
		{
			

			
			if (ExecEvalArrayRefSubscript(state, op))
			{
				EEO_NEXT();
			}
			else {
				
				EEO_JUMP(op->d.arrayref_subscript.jumpdone);
			}
		}

		EEO_CASE(EEOP_ARRAYREF_OLD)
		{
			

			
			ExecEvalArrayRefOld(state, op);

			EEO_NEXT();
		}

		
		EEO_CASE(EEOP_ARRAYREF_ASSIGN)
		{
			
			ExecEvalArrayRefAssign(state, op);

			EEO_NEXT();
		}

		
		EEO_CASE(EEOP_ARRAYREF_FETCH)
		{
			
			ExecEvalArrayRefFetch(state, op);

			EEO_NEXT();
		}

		EEO_CASE(EEOP_CONVERT_ROWTYPE)
		{
			
			ExecEvalConvertRowtype(state, op, econtext);

			EEO_NEXT();
		}

		EEO_CASE(EEOP_SCALARARRAYOP)
		{
			
			ExecEvalScalarArrayOp(state, op);

			EEO_NEXT();
		}

		EEO_CASE(EEOP_DOMAIN_NOTNULL)
		{
			
			ExecEvalConstraintNotNull(state, op);

			EEO_NEXT();
		}

		EEO_CASE(EEOP_DOMAIN_CHECK)
		{
			
			ExecEvalConstraintCheck(state, op);

			EEO_NEXT();
		}

		EEO_CASE(EEOP_XMLEXPR)
		{
			
			ExecEvalXmlExpr(state, op);

			EEO_NEXT();
		}

		EEO_CASE(EEOP_AGGREF)
		{
			
			AggrefExprState *aggref = op->d.aggref.astate;

			Assert(econtext->ecxt_aggvalues != NULL);

			*op->resvalue = econtext->ecxt_aggvalues[aggref->aggno];
			*op->resnull = econtext->ecxt_aggnulls[aggref->aggno];

			EEO_NEXT();
		}

		EEO_CASE(EEOP_GROUPING_FUNC)
		{
			
			ExecEvalGroupingFunc(state, op);

			EEO_NEXT();
		}

		EEO_CASE(EEOP_WINDOW_FUNC)
		{
			
			WindowFuncExprState *wfunc = op->d.window_func.wfstate;

			Assert(econtext->ecxt_aggvalues != NULL);

			*op->resvalue = econtext->ecxt_aggvalues[wfunc->wfuncno];
			*op->resnull = econtext->ecxt_aggnulls[wfunc->wfuncno];

			EEO_NEXT();
		}

		EEO_CASE(EEOP_SUBPLAN)
		{
			
			ExecEvalSubPlan(state, op, econtext);

			EEO_NEXT();
		}

		EEO_CASE(EEOP_ALTERNATIVE_SUBPLAN)
		{
			
			ExecEvalAlternativeSubPlan(state, op, econtext);

			EEO_NEXT();
		}

		
		EEO_CASE(EEOP_AGG_STRICT_DESERIALIZE)
		{
			
			if (op->d.agg_deserialize.fcinfo_data->args[0].isnull)
				EEO_JUMP(op->d.agg_deserialize.jumpnull);

			
		}

		
		EEO_CASE(EEOP_AGG_DESERIALIZE)
		{
			FunctionCallInfo fcinfo = op->d.agg_deserialize.fcinfo_data;
			AggState   *aggstate = op->d.agg_deserialize.aggstate;
			MemoryContext oldContext;

			
			oldContext = MemoryContextSwitchTo(aggstate->tmpcontext->ecxt_per_tuple_memory);
			fcinfo->isnull = false;
			*op->resvalue = FunctionCallInvoke(fcinfo);
			*op->resnull = fcinfo->isnull;
			MemoryContextSwitchTo(oldContext);

			EEO_NEXT();
		}

		
		EEO_CASE(EEOP_AGG_STRICT_INPUT_CHECK_NULLS)
		{
			int			argno;
			bool	   *nulls = op->d.agg_strict_input_check.nulls;
			int			nargs = op->d.agg_strict_input_check.nargs;

			for (argno = 0; argno < nargs; argno++)
			{
				if (nulls[argno])
					EEO_JUMP(op->d.agg_strict_input_check.jumpnull);
			}
			EEO_NEXT();
		}

		EEO_CASE(EEOP_AGG_STRICT_INPUT_CHECK_ARGS)
		{
			int			argno;
			NullableDatum *args = op->d.agg_strict_input_check.args;
			int			nargs = op->d.agg_strict_input_check.nargs;

			for (argno = 0; argno < nargs; argno++)
			{
				if (args[argno].isnull)
					EEO_JUMP(op->d.agg_strict_input_check.jumpnull);
			}
			EEO_NEXT();
		}

		
		EEO_CASE(EEOP_AGG_INIT_TRANS)
		{
			AggState   *aggstate;
			AggStatePerGroup pergroup;

			aggstate = op->d.agg_init_trans.aggstate;
			pergroup = &aggstate->all_pergroups [op->d.agg_init_trans.setoff] [op->d.agg_init_trans.transno];


			
			if (pergroup->noTransValue)
			{
				AggStatePerTrans pertrans = op->d.agg_init_trans.pertrans;

				aggstate->curaggcontext = op->d.agg_init_trans.aggcontext;
				aggstate->current_set = op->d.agg_init_trans.setno;

				ExecAggInitGroup(aggstate, pertrans, pergroup);

				
				EEO_JUMP(op->d.agg_init_trans.jumpnull);
			}

			EEO_NEXT();
		}

		
		EEO_CASE(EEOP_AGG_STRICT_TRANS_CHECK)
		{
			AggState   *aggstate;
			AggStatePerGroup pergroup;

			aggstate = op->d.agg_strict_trans_check.aggstate;
			pergroup = &aggstate->all_pergroups [op->d.agg_strict_trans_check.setoff] [op->d.agg_strict_trans_check.transno];


			if (unlikely(pergroup->transValueIsNull))
				EEO_JUMP(op->d.agg_strict_trans_check.jumpnull);

			EEO_NEXT();
		}

		
		EEO_CASE(EEOP_AGG_PLAIN_TRANS_BYVAL)
		{
			AggState   *aggstate;
			AggStatePerTrans pertrans;
			AggStatePerGroup pergroup;
			FunctionCallInfo fcinfo;
			MemoryContext oldContext;
			Datum		newVal;

			aggstate = op->d.agg_trans.aggstate;
			pertrans = op->d.agg_trans.pertrans;

			pergroup = &aggstate->all_pergroups [op->d.agg_trans.setoff] [op->d.agg_trans.transno];


			Assert(pertrans->transtypeByVal);

			fcinfo = pertrans->transfn_fcinfo;

			
			aggstate->curaggcontext = op->d.agg_trans.aggcontext;
			aggstate->current_set = op->d.agg_trans.setno;

			
			aggstate->curpertrans = pertrans;

			
			oldContext = MemoryContextSwitchTo(aggstate->tmpcontext->ecxt_per_tuple_memory);

			fcinfo->args[0].value = pergroup->transValue;
			fcinfo->args[0].isnull = pergroup->transValueIsNull;
			fcinfo->isnull = false; 

			newVal = FunctionCallInvoke(fcinfo);

			pergroup->transValue = newVal;
			pergroup->transValueIsNull = fcinfo->isnull;

			MemoryContextSwitchTo(oldContext);

			EEO_NEXT();
		}

		
		EEO_CASE(EEOP_AGG_PLAIN_TRANS)
		{
			AggState   *aggstate;
			AggStatePerTrans pertrans;
			AggStatePerGroup pergroup;
			FunctionCallInfo fcinfo;
			MemoryContext oldContext;
			Datum		newVal;

			aggstate = op->d.agg_trans.aggstate;
			pertrans = op->d.agg_trans.pertrans;

			pergroup = &aggstate->all_pergroups [op->d.agg_trans.setoff] [op->d.agg_trans.transno];


			Assert(!pertrans->transtypeByVal);

			fcinfo = pertrans->transfn_fcinfo;

			
			aggstate->curaggcontext = op->d.agg_trans.aggcontext;
			aggstate->current_set = op->d.agg_trans.setno;

			
			aggstate->curpertrans = pertrans;

			
			oldContext = MemoryContextSwitchTo(aggstate->tmpcontext->ecxt_per_tuple_memory);

			fcinfo->args[0].value = pergroup->transValue;
			fcinfo->args[0].isnull = pergroup->transValueIsNull;
			fcinfo->isnull = false; 

			newVal = FunctionCallInvoke(fcinfo);

			
			if (DatumGetPointer(newVal) != DatumGetPointer(pergroup->transValue))
				newVal = ExecAggTransReparent(aggstate, pertrans, newVal, fcinfo->isnull, pergroup->transValue, pergroup->transValueIsNull);



			pergroup->transValue = newVal;
			pergroup->transValueIsNull = fcinfo->isnull;

			MemoryContextSwitchTo(oldContext);

			EEO_NEXT();
		}

		
		EEO_CASE(EEOP_AGG_ORDERED_TRANS_DATUM)
		{
			
			ExecEvalAggOrderedTransDatum(state, op, econtext);

			EEO_NEXT();
		}

		
		EEO_CASE(EEOP_AGG_ORDERED_TRANS_TUPLE)
		{
			
			ExecEvalAggOrderedTransTuple(state, op, econtext);

			EEO_NEXT();
		}

		EEO_CASE(EEOP_LAST)
		{
			
			Assert(false);
			goto out;
		}
	}

out:
	*isnull = state->resnull;
	return state->resvalue;
}


Datum ExecInterpExprStillValid(ExprState *state, ExprContext *econtext, bool *isNull)
{
	
	CheckExprStillValid(state, econtext);

	
	state->evalfunc = (ExprStateEvalFunc) state->evalfunc_private;

	
	return state->evalfunc(state, econtext, isNull);
}


void CheckExprStillValid(ExprState *state, ExprContext *econtext)
{
	int			i = 0;
	TupleTableSlot *innerslot;
	TupleTableSlot *outerslot;
	TupleTableSlot *scanslot;

	innerslot = econtext->ecxt_innertuple;
	outerslot = econtext->ecxt_outertuple;
	scanslot = econtext->ecxt_scantuple;

	for (i = 0; i < state->steps_len; i++)
	{
		ExprEvalStep *op = &state->steps[i];

		switch (ExecEvalStepOp(state, op))
		{
			case EEOP_INNER_VAR:
				{
					int			attnum = op->d.var.attnum;

					CheckVarSlotCompatibility(innerslot, attnum + 1, op->d.var.vartype);
					break;
				}

			case EEOP_OUTER_VAR:
				{
					int			attnum = op->d.var.attnum;

					CheckVarSlotCompatibility(outerslot, attnum + 1, op->d.var.vartype);
					break;
				}

			case EEOP_SCAN_VAR:
				{
					int			attnum = op->d.var.attnum;

					CheckVarSlotCompatibility(scanslot, attnum + 1, op->d.var.vartype);
					break;
				}
			default:
				break;
		}
	}
}


static void CheckVarSlotCompatibility(TupleTableSlot *slot, int attnum, Oid vartype)
{
	
	if (attnum > 0)
	{
		TupleDesc	slot_tupdesc = slot->tts_tupleDescriptor;
		Form_pg_attribute attr;

		if (attnum > slot_tupdesc->natts)	
			elog(ERROR, "attribute number %d exceeds number of columns %d", attnum, slot_tupdesc->natts);

		attr = TupleDescAttr(slot_tupdesc, attnum - 1);

		if (attr->attisdropped)
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_COLUMN), errmsg("attribute %d of type %s has been dropped", attnum, format_type_be(slot_tupdesc->tdtypeid))));



		if (vartype != attr->atttypid)
			ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("attribute %d of type %s has wrong type", attnum, format_type_be(slot_tupdesc->tdtypeid)), errdetail("Table has type %s, but query expects %s.", format_type_be(attr->atttypid), format_type_be(vartype))));





	}
}


static TupleDesc get_cached_rowtype(Oid type_id, int32 typmod, ExprEvalRowtypeCache *rowcache, bool *changed)


{
	if (type_id != RECORDOID)
	{
		
		TypeCacheEntry *typentry = (TypeCacheEntry *) rowcache->cacheptr;

		if (unlikely(typentry == NULL || rowcache->tupdesc_id == 0 || typentry->tupDesc_identifier != rowcache->tupdesc_id))

		{
			typentry = lookup_type_cache(type_id, TYPECACHE_TUPDESC);
			if (typentry->tupDesc == NULL)
				ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("type %s is not composite", format_type_be(type_id))));


			rowcache->cacheptr = (void *) typentry;
			rowcache->tupdesc_id = typentry->tupDesc_identifier;
			if (changed)
				*changed = true;
		}
		return typentry->tupDesc;
	}
	else {
		
		TupleDesc	tupDesc = (TupleDesc) rowcache->cacheptr;

		if (unlikely(tupDesc == NULL || rowcache->tupdesc_id != 0 || type_id != tupDesc->tdtypeid || typmod != tupDesc->tdtypmod))


		{
			tupDesc = lookup_rowtype_tupdesc(type_id, typmod);
			
			ReleaseTupleDesc(tupDesc);
			rowcache->cacheptr = (void *) tupDesc;
			rowcache->tupdesc_id = 0;	
			if (changed)
				*changed = true;
		}
		return tupDesc;
	}
}





static Datum ExecJustInnerVar(ExprState *state, ExprContext *econtext, bool *isnull)
{
	ExprEvalStep *op = &state->steps[1];
	int			attnum = op->d.var.attnum + 1;
	TupleTableSlot *slot = econtext->ecxt_innertuple;

	
	return slot_getattr(slot, attnum, isnull);
}


static Datum ExecJustOuterVar(ExprState *state, ExprContext *econtext, bool *isnull)
{
	ExprEvalStep *op = &state->steps[1];
	int			attnum = op->d.var.attnum + 1;
	TupleTableSlot *slot = econtext->ecxt_outertuple;

	
	return slot_getattr(slot, attnum, isnull);
}


static Datum ExecJustScanVar(ExprState *state, ExprContext *econtext, bool *isnull)
{
	ExprEvalStep *op = &state->steps[1];
	int			attnum = op->d.var.attnum + 1;
	TupleTableSlot *slot = econtext->ecxt_scantuple;

	
	return slot_getattr(slot, attnum, isnull);
}


static Datum ExecJustConst(ExprState *state, ExprContext *econtext, bool *isnull)
{
	ExprEvalStep *op = &state->steps[0];

	*isnull = op->d.constval.isnull;
	return op->d.constval.value;
}


static Datum ExecJustAssignInnerVar(ExprState *state, ExprContext *econtext, bool *isnull)
{
	ExprEvalStep *op = &state->steps[1];
	int			attnum = op->d.assign_var.attnum + 1;
	int			resultnum = op->d.assign_var.resultnum;
	TupleTableSlot *inslot = econtext->ecxt_innertuple;
	TupleTableSlot *outslot = state->resultslot;

	
	outslot->tts_values[resultnum] = slot_getattr(inslot, attnum, &outslot->tts_isnull[resultnum]);
	return 0;
}


static Datum ExecJustAssignOuterVar(ExprState *state, ExprContext *econtext, bool *isnull)
{
	ExprEvalStep *op = &state->steps[1];
	int			attnum = op->d.assign_var.attnum + 1;
	int			resultnum = op->d.assign_var.resultnum;
	TupleTableSlot *inslot = econtext->ecxt_outertuple;
	TupleTableSlot *outslot = state->resultslot;

	
	outslot->tts_values[resultnum] = slot_getattr(inslot, attnum, &outslot->tts_isnull[resultnum]);
	return 0;
}


static Datum ExecJustAssignScanVar(ExprState *state, ExprContext *econtext, bool *isnull)
{
	ExprEvalStep *op = &state->steps[1];
	int			attnum = op->d.assign_var.attnum + 1;
	int			resultnum = op->d.assign_var.resultnum;
	TupleTableSlot *inslot = econtext->ecxt_scantuple;
	TupleTableSlot *outslot = state->resultslot;

	
	outslot->tts_values[resultnum] = slot_getattr(inslot, attnum, &outslot->tts_isnull[resultnum]);
	return 0;
}


static Datum ExecJustApplyFuncToCase(ExprState *state, ExprContext *econtext, bool *isnull)
{
	ExprEvalStep *op = &state->steps[0];
	FunctionCallInfo fcinfo;
	NullableDatum *args;
	int			argno;
	Datum		d;

	
	*op->resvalue = *op->d.casetest.value;
	*op->resnull = *op->d.casetest.isnull;

	op++;

	fcinfo = op->d.func.fcinfo_data;
	args = fcinfo->args;

	
	for (argno = 0; argno < op->d.func.nargs; argno++)
	{
		if (args[argno].isnull)
		{
			*isnull = true;
			return (Datum) 0;
		}
	}
	fcinfo->isnull = false;
	d = op->d.func.fn_addr(fcinfo);
	*isnull = fcinfo->isnull;
	return d;
}



static int dispatch_compare_ptr(const void *a, const void *b)
{
	const ExprEvalOpLookup *la = (const ExprEvalOpLookup *) a;
	const ExprEvalOpLookup *lb = (const ExprEvalOpLookup *) b;

	if (la->opcode < lb->opcode)
		return -1;
	else if (la->opcode > lb->opcode)
		return 1;
	return 0;
}



static void ExecInitInterpreter(void)
{

	
	if (dispatch_table == NULL)
	{
		int			i;

		dispatch_table = (const void **)
			DatumGetPointer(ExecInterpExpr(NULL, NULL, NULL));

		
		for (i = 0; i < EEOP_LAST; i++)
		{
			reverse_dispatch_table[i].opcode = dispatch_table[i];
			reverse_dispatch_table[i].op = (ExprEvalOp) i;
		}

		
		qsort(reverse_dispatch_table, EEOP_LAST  , sizeof(ExprEvalOpLookup), dispatch_compare_ptr);


	}

}


ExprEvalOp ExecEvalStepOp(ExprState *state, ExprEvalStep *op)
{

	if (state->flags & EEO_FLAG_DIRECT_THREADED)
	{
		ExprEvalOpLookup key;
		ExprEvalOpLookup *res;

		key.opcode = (void *) op->opcode;
		res = bsearch(&key, reverse_dispatch_table, EEOP_LAST  , sizeof(ExprEvalOpLookup), dispatch_compare_ptr);



		Assert(res);			
		return res->op;
	}

	return (ExprEvalOp) op->opcode;
}





void ExecEvalFuncExprFusage(ExprState *state, ExprEvalStep *op, ExprContext *econtext)

{
	FunctionCallInfo fcinfo = op->d.func.fcinfo_data;
	PgStat_FunctionCallUsage fcusage;
	Datum		d;

	pgstat_init_function_usage(fcinfo, &fcusage);

	fcinfo->isnull = false;
	d = op->d.func.fn_addr(fcinfo);
	*op->resvalue = d;
	*op->resnull = fcinfo->isnull;

	pgstat_end_function_usage(&fcusage, true);
}


void ExecEvalFuncExprStrictFusage(ExprState *state, ExprEvalStep *op, ExprContext *econtext)

{

	FunctionCallInfo fcinfo = op->d.func.fcinfo_data;
	PgStat_FunctionCallUsage fcusage;
	NullableDatum *args = fcinfo->args;
	int			argno;
	Datum		d;

	
	for (argno = 0; argno < op->d.func.nargs; argno++)
	{
		if (args[argno].isnull)
		{
			*op->resnull = true;
			return;
		}
	}

	pgstat_init_function_usage(fcinfo, &fcusage);

	fcinfo->isnull = false;
	d = op->d.func.fn_addr(fcinfo);
	*op->resvalue = d;
	*op->resnull = fcinfo->isnull;

	pgstat_end_function_usage(&fcusage, true);
}


void ExecEvalParamExec(ExprState *state, ExprEvalStep *op, ExprContext *econtext)
{
	ParamExecData *prm;

	prm = &(econtext->ecxt_param_exec_vals[op->d.param.paramid]);
	if (unlikely(prm->execPlan != NULL))
	{
		
		ExecSetParamPlan(prm->execPlan, econtext);
		
		Assert(prm->execPlan == NULL);
	}
	*op->resvalue = prm->value;
	*op->resnull = prm->isnull;
}


void ExecEvalParamExtern(ExprState *state, ExprEvalStep *op, ExprContext *econtext)
{
	ParamListInfo paramInfo = econtext->ecxt_param_list_info;
	int			paramId = op->d.param.paramid;

	if (likely(paramInfo && paramId > 0 && paramId <= paramInfo->numParams))
	{
		ParamExternData *prm;
		ParamExternData prmdata;

		
		if (paramInfo->paramFetch != NULL)
			prm = paramInfo->paramFetch(paramInfo, paramId, false, &prmdata);
		else prm = &paramInfo->params[paramId - 1];

		if (likely(OidIsValid(prm->ptype)))
		{
			
			if (unlikely(prm->ptype != op->d.param.paramtype))
				ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("type of parameter %d (%s) does not match that when preparing the plan (%s)", paramId, format_type_be(prm->ptype), format_type_be(op->d.param.paramtype))));




			*op->resvalue = prm->value;
			*op->resnull = prm->isnull;
			return;
		}
	}

	ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("no value found for parameter %d", paramId)));

}


void ExecEvalSQLValueFunction(ExprState *state, ExprEvalStep *op)
{
	LOCAL_FCINFO(fcinfo, 0);
	SQLValueFunction *svf = op->d.sqlvaluefunction.svf;

	*op->resnull = false;

	
	switch (svf->op)
	{
		case SVFOP_CURRENT_DATE:
			*op->resvalue = DateADTGetDatum(GetSQLCurrentDate());
			break;
		case SVFOP_CURRENT_TIME:
		case SVFOP_CURRENT_TIME_N:
			*op->resvalue = TimeTzADTPGetDatum(GetSQLCurrentTime(svf->typmod));
			break;
		case SVFOP_CURRENT_TIMESTAMP:
		case SVFOP_CURRENT_TIMESTAMP_N:
			*op->resvalue = TimestampTzGetDatum(GetSQLCurrentTimestamp(svf->typmod));
			break;
		case SVFOP_LOCALTIME:
		case SVFOP_LOCALTIME_N:
			*op->resvalue = TimeADTGetDatum(GetSQLLocalTime(svf->typmod));
			break;
		case SVFOP_LOCALTIMESTAMP:
		case SVFOP_LOCALTIMESTAMP_N:
			*op->resvalue = TimestampGetDatum(GetSQLLocalTimestamp(svf->typmod));
			break;
		case SVFOP_CURRENT_ROLE:
		case SVFOP_CURRENT_USER:
		case SVFOP_USER:
			InitFunctionCallInfoData(*fcinfo, NULL, 0, InvalidOid, NULL, NULL);
			*op->resvalue = current_user(fcinfo);
			*op->resnull = fcinfo->isnull;
			break;
		case SVFOP_SESSION_USER:
			InitFunctionCallInfoData(*fcinfo, NULL, 0, InvalidOid, NULL, NULL);
			*op->resvalue = session_user(fcinfo);
			*op->resnull = fcinfo->isnull;
			break;
		case SVFOP_CURRENT_CATALOG:
			InitFunctionCallInfoData(*fcinfo, NULL, 0, InvalidOid, NULL, NULL);
			*op->resvalue = current_database(fcinfo);
			*op->resnull = fcinfo->isnull;
			break;
		case SVFOP_CURRENT_SCHEMA:
			InitFunctionCallInfoData(*fcinfo, NULL, 0, InvalidOid, NULL, NULL);
			*op->resvalue = current_schema(fcinfo);
			*op->resnull = fcinfo->isnull;
			break;
	}
}


void ExecEvalCurrentOfExpr(ExprState *state, ExprEvalStep *op)
{
	ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("WHERE CURRENT OF is not supported for this table type")));

}


void ExecEvalNextValueExpr(ExprState *state, ExprEvalStep *op)
{
	int64		newval = nextval_internal(op->d.nextvalueexpr.seqid, false);

	switch (op->d.nextvalueexpr.seqtypid)
	{
		case INT2OID:
			*op->resvalue = Int16GetDatum((int16) newval);
			break;
		case INT4OID:
			*op->resvalue = Int32GetDatum((int32) newval);
			break;
		case INT8OID:
			*op->resvalue = Int64GetDatum((int64) newval);
			break;
		default:
			elog(ERROR, "unsupported sequence type %u", op->d.nextvalueexpr.seqtypid);
	}
	*op->resnull = false;
}


void ExecEvalRowNull(ExprState *state, ExprEvalStep *op, ExprContext *econtext)
{
	ExecEvalRowNullInt(state, op, econtext, true);
}


void ExecEvalRowNotNull(ExprState *state, ExprEvalStep *op, ExprContext *econtext)
{
	ExecEvalRowNullInt(state, op, econtext, false);
}


static void ExecEvalRowNullInt(ExprState *state, ExprEvalStep *op, ExprContext *econtext, bool checkisnull)

{
	Datum		value = *op->resvalue;
	bool		isnull = *op->resnull;
	HeapTupleHeader tuple;
	Oid			tupType;
	int32		tupTypmod;
	TupleDesc	tupDesc;
	HeapTupleData tmptup;
	int			att;

	*op->resnull = false;

	
	if (isnull)
	{
		*op->resvalue = BoolGetDatum(checkisnull);
		return;
	}

	

	tuple = DatumGetHeapTupleHeader(value);

	tupType = HeapTupleHeaderGetTypeId(tuple);
	tupTypmod = HeapTupleHeaderGetTypMod(tuple);

	
	tupDesc = get_cached_rowtype(tupType, tupTypmod, &op->d.nulltest_row.rowcache, NULL);

	
	tmptup.t_len = HeapTupleHeaderGetDatumLength(tuple);
	tmptup.t_data = tuple;

	for (att = 1; att <= tupDesc->natts; att++)
	{
		
		if (TupleDescAttr(tupDesc, att - 1)->attisdropped)
			continue;
		if (heap_attisnull(&tmptup, att, tupDesc))
		{
			
			if (!checkisnull)
			{
				*op->resvalue = BoolGetDatum(false);
				return;
			}
		}
		else {
			
			if (checkisnull)
			{
				*op->resvalue = BoolGetDatum(false);
				return;
			}
		}
	}

	*op->resvalue = BoolGetDatum(true);
}


void ExecEvalArrayExpr(ExprState *state, ExprEvalStep *op)
{
	ArrayType  *result;
	Oid			element_type = op->d.arrayexpr.elemtype;
	int			nelems = op->d.arrayexpr.nelems;
	int			ndims = 0;
	int			dims[MAXDIM];
	int			lbs[MAXDIM];

	
	*op->resnull = false;

	if (!op->d.arrayexpr.multidims)
	{
		
		Datum	   *dvalues = op->d.arrayexpr.elemvalues;
		bool	   *dnulls = op->d.arrayexpr.elemnulls;

		
		ndims = 1;
		dims[0] = nelems;
		lbs[0] = 1;

		result = construct_md_array(dvalues, dnulls, ndims, dims, lbs, element_type, op->d.arrayexpr.elemlength, op->d.arrayexpr.elembyval, op->d.arrayexpr.elemalign);



	}
	else {
		
		int			nbytes = 0;
		int			nitems = 0;
		int			outer_nelems = 0;
		int			elem_ndims = 0;
		int		   *elem_dims = NULL;
		int		   *elem_lbs = NULL;
		bool		firstone = true;
		bool		havenulls = false;
		bool		haveempty = false;
		char	  **subdata;
		bits8	  **subbitmaps;
		int		   *subbytes;
		int		   *subnitems;
		int32		dataoffset;
		char	   *dat;
		int			iitem;
		int			elemoff;
		int			i;

		subdata = (char **) palloc(nelems * sizeof(char *));
		subbitmaps = (bits8 **) palloc(nelems * sizeof(bits8 *));
		subbytes = (int *) palloc(nelems * sizeof(int));
		subnitems = (int *) palloc(nelems * sizeof(int));

		
		for (elemoff = 0; elemoff < nelems; elemoff++)
		{
			Datum		arraydatum;
			bool		eisnull;
			ArrayType  *array;
			int			this_ndims;

			arraydatum = op->d.arrayexpr.elemvalues[elemoff];
			eisnull = op->d.arrayexpr.elemnulls[elemoff];

			
			if (eisnull)
			{
				haveempty = true;
				continue;
			}

			array = DatumGetArrayTypeP(arraydatum);

			
			if (element_type != ARR_ELEMTYPE(array))
				ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("cannot merge incompatible arrays"), errdetail("Array with element type %s cannot be " "included in ARRAY construct with element type %s.", format_type_be(ARR_ELEMTYPE(array)), format_type_be(element_type))));






			this_ndims = ARR_NDIM(array);
			
			if (this_ndims <= 0)
			{
				haveempty = true;
				continue;
			}

			if (firstone)
			{
				
				elem_ndims = this_ndims;
				ndims = elem_ndims + 1;
				if (ndims <= 0 || ndims > MAXDIM)
					ereport(ERROR, (errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED), errmsg("number of array dimensions (%d) exceeds "  "the maximum allowed (%d)", ndims, MAXDIM)))


				elem_dims = (int *) palloc(elem_ndims * sizeof(int));
				memcpy(elem_dims, ARR_DIMS(array), elem_ndims * sizeof(int));
				elem_lbs = (int *) palloc(elem_ndims * sizeof(int));
				memcpy(elem_lbs, ARR_LBOUND(array), elem_ndims * sizeof(int));

				firstone = false;
			}
			else {
				
				if (elem_ndims != this_ndims || memcmp(elem_dims, ARR_DIMS(array), elem_ndims * sizeof(int)) != 0 || memcmp(elem_lbs, ARR_LBOUND(array), elem_ndims * sizeof(int)) != 0)



					ereport(ERROR, (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR), errmsg("multidimensional arrays must have array " "expressions with matching dimensions")));


			}

			subdata[outer_nelems] = ARR_DATA_PTR(array);
			subbitmaps[outer_nelems] = ARR_NULLBITMAP(array);
			subbytes[outer_nelems] = ARR_SIZE(array) - ARR_DATA_OFFSET(array);
			nbytes += subbytes[outer_nelems];
			subnitems[outer_nelems] = ArrayGetNItems(this_ndims, ARR_DIMS(array));
			nitems += subnitems[outer_nelems];
			havenulls |= ARR_HASNULL(array);
			outer_nelems++;
		}

		
		if (haveempty)
		{
			if (ndims == 0)		
			{
				*op->resvalue = PointerGetDatum(construct_empty_array(element_type));
				return;
			}
			ereport(ERROR, (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR), errmsg("multidimensional arrays must have array " "expressions with matching dimensions")));


		}

		
		dims[0] = outer_nelems;
		lbs[0] = 1;
		for (i = 1; i < ndims; i++)
		{
			dims[i] = elem_dims[i - 1];
			lbs[i] = elem_lbs[i - 1];
		}

		if (havenulls)
		{
			dataoffset = ARR_OVERHEAD_WITHNULLS(ndims, nitems);
			nbytes += dataoffset;
		}
		else {
			dataoffset = 0;		
			nbytes += ARR_OVERHEAD_NONULLS(ndims);
		}

		result = (ArrayType *) palloc(nbytes);
		SET_VARSIZE(result, nbytes);
		result->ndim = ndims;
		result->dataoffset = dataoffset;
		result->elemtype = element_type;
		memcpy(ARR_DIMS(result), dims, ndims * sizeof(int));
		memcpy(ARR_LBOUND(result), lbs, ndims * sizeof(int));

		dat = ARR_DATA_PTR(result);
		iitem = 0;
		for (i = 0; i < outer_nelems; i++)
		{
			memcpy(dat, subdata[i], subbytes[i]);
			dat += subbytes[i];
			if (havenulls)
				array_bitmap_copy(ARR_NULLBITMAP(result), iitem, subbitmaps[i], 0, subnitems[i]);

			iitem += subnitems[i];
		}
	}

	*op->resvalue = PointerGetDatum(result);
}


void ExecEvalArrayCoerce(ExprState *state, ExprEvalStep *op, ExprContext *econtext)
{
	Datum		arraydatum;

	
	if (*op->resnull)
		return;

	arraydatum = *op->resvalue;

	
	if (op->d.arraycoerce.elemexprstate == NULL)
	{
		
		ArrayType  *array = DatumGetArrayTypePCopy(arraydatum);

		ARR_ELEMTYPE(array) = op->d.arraycoerce.resultelemtype;
		*op->resvalue = PointerGetDatum(array);
		return;
	}

	
	*op->resvalue = array_map(arraydatum, op->d.arraycoerce.elemexprstate, econtext, op->d.arraycoerce.resultelemtype, op->d.arraycoerce.amstate);



}


void ExecEvalRow(ExprState *state, ExprEvalStep *op)
{
	HeapTuple	tuple;

	
	tuple = heap_form_tuple(op->d.row.tupdesc, op->d.row.elemvalues, op->d.row.elemnulls);


	*op->resvalue = HeapTupleGetDatum(tuple);
	*op->resnull = false;
}


void ExecEvalMinMax(ExprState *state, ExprEvalStep *op)
{
	Datum	   *values = op->d.minmax.values;
	bool	   *nulls = op->d.minmax.nulls;
	FunctionCallInfo fcinfo = op->d.minmax.fcinfo_data;
	MinMaxOp	operator = op->d.minmax.op;
	int			off;

	
	Assert(fcinfo->args[0].isnull == false);
	Assert(fcinfo->args[1].isnull == false);

	
	*op->resnull = true;

	for (off = 0; off < op->d.minmax.nelems; off++)
	{
		
		if (nulls[off])
			continue;

		if (*op->resnull)
		{
			
			*op->resvalue = values[off];
			*op->resnull = false;
		}
		else {
			int			cmpresult;

			
			fcinfo->args[0].value = *op->resvalue;
			fcinfo->args[1].value = values[off];

			fcinfo->isnull = false;
			cmpresult = DatumGetInt32(FunctionCallInvoke(fcinfo));
			if (fcinfo->isnull) 
				continue;

			if (cmpresult > 0 && operator == IS_LEAST)
				*op->resvalue = values[off];
			else if (cmpresult < 0 && operator == IS_GREATEST)
				*op->resvalue = values[off];
		}
	}
}


void ExecEvalFieldSelect(ExprState *state, ExprEvalStep *op, ExprContext *econtext)
{
	AttrNumber	fieldnum = op->d.fieldselect.fieldnum;
	Datum		tupDatum;
	HeapTupleHeader tuple;
	Oid			tupType;
	int32		tupTypmod;
	TupleDesc	tupDesc;
	Form_pg_attribute attr;
	HeapTupleData tmptup;

	
	if (*op->resnull)
		return;

	tupDatum = *op->resvalue;

	
	if (VARATT_IS_EXTERNAL_EXPANDED(DatumGetPointer(tupDatum)))
	{
		ExpandedRecordHeader *erh = (ExpandedRecordHeader *) DatumGetEOHP(tupDatum);

		Assert(erh->er_magic == ER_MAGIC);

		
		tupDesc = expanded_record_get_tupdesc(erh);

		
		if (fieldnum <= 0)		
			elog(ERROR, "unsupported reference to system column %d in FieldSelect", fieldnum);
		if (fieldnum > tupDesc->natts)	
			elog(ERROR, "attribute number %d exceeds number of columns %d", fieldnum, tupDesc->natts);
		attr = TupleDescAttr(tupDesc, fieldnum - 1);

		
		if (attr->attisdropped)
		{
			*op->resnull = true;
			return;
		}

		
		
		if (op->d.fieldselect.resulttype != attr->atttypid)
			ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("attribute %d has wrong type", fieldnum), errdetail("Table has type %s, but query expects %s.", format_type_be(attr->atttypid), format_type_be(op->d.fieldselect.resulttype))));





		
		*op->resvalue = expanded_record_get_field(erh, fieldnum, op->resnull);
	}
	else {
		
		tuple = DatumGetHeapTupleHeader(tupDatum);

		tupType = HeapTupleHeaderGetTypeId(tuple);
		tupTypmod = HeapTupleHeaderGetTypMod(tuple);

		
		tupDesc = get_cached_rowtype(tupType, tupTypmod, &op->d.fieldselect.rowcache, NULL);

		
		if (fieldnum <= 0)		
			elog(ERROR, "unsupported reference to system column %d in FieldSelect", fieldnum);
		if (fieldnum > tupDesc->natts)	
			elog(ERROR, "attribute number %d exceeds number of columns %d", fieldnum, tupDesc->natts);
		attr = TupleDescAttr(tupDesc, fieldnum - 1);

		
		if (attr->attisdropped)
		{
			*op->resnull = true;
			return;
		}

		
		
		if (op->d.fieldselect.resulttype != attr->atttypid)
			ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("attribute %d has wrong type", fieldnum), errdetail("Table has type %s, but query expects %s.", format_type_be(attr->atttypid), format_type_be(op->d.fieldselect.resulttype))));





		
		tmptup.t_len = HeapTupleHeaderGetDatumLength(tuple);
		tmptup.t_data = tuple;

		
		*op->resvalue = heap_getattr(&tmptup, fieldnum, tupDesc, op->resnull);


	}
}


void ExecEvalFieldStoreDeForm(ExprState *state, ExprEvalStep *op, ExprContext *econtext)
{
	TupleDesc	tupDesc;

	
	tupDesc = get_cached_rowtype(op->d.fieldstore.fstore->resulttype, -1, op->d.fieldstore.rowcache, NULL);

	
	if (unlikely(tupDesc->natts > op->d.fieldstore.ncolumns))
		elog(ERROR, "too many columns in composite type %u", op->d.fieldstore.fstore->resulttype);

	if (*op->resnull)
	{
		
		memset(op->d.fieldstore.nulls, true, op->d.fieldstore.ncolumns * sizeof(bool));
	}
	else {
		
		Datum		tupDatum = *op->resvalue;
		HeapTupleHeader tuphdr;
		HeapTupleData tmptup;

		tuphdr = DatumGetHeapTupleHeader(tupDatum);
		tmptup.t_len = HeapTupleHeaderGetDatumLength(tuphdr);
		ItemPointerSetInvalid(&(tmptup.t_self));
		tmptup.t_tableOid = InvalidOid;
		tmptup.t_data = tuphdr;

		heap_deform_tuple(&tmptup, tupDesc, op->d.fieldstore.values, op->d.fieldstore.nulls);

	}
}


void ExecEvalFieldStoreForm(ExprState *state, ExprEvalStep *op, ExprContext *econtext)
{
	TupleDesc	tupDesc;
	HeapTuple	tuple;

	
	tupDesc = get_cached_rowtype(op->d.fieldstore.fstore->resulttype, -1, op->d.fieldstore.rowcache, NULL);

	tuple = heap_form_tuple(tupDesc, op->d.fieldstore.values, op->d.fieldstore.nulls);


	*op->resvalue = HeapTupleGetDatum(tuple);
	*op->resnull = false;
}


bool ExecEvalArrayRefSubscript(ExprState *state, ExprEvalStep *op)
{
	ArrayRefState *arefstate = op->d.arrayref_subscript.state;
	int		   *indexes;
	int			off;

	
	if (arefstate->subscriptnull)
	{
		if (arefstate->isassignment)
			ereport(ERROR, (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED), errmsg("array subscript in assignment must not be null")));

		*op->resnull = true;
		return false;
	}

	
	if (op->d.arrayref_subscript.isupper)
		indexes = arefstate->upperindex;
	else indexes = arefstate->lowerindex;
	off = op->d.arrayref_subscript.off;

	indexes[off] = DatumGetInt32(arefstate->subscriptvalue);

	return true;
}


void ExecEvalArrayRefFetch(ExprState *state, ExprEvalStep *op)
{
	ArrayRefState *arefstate = op->d.arrayref.state;

	
	Assert(!(*op->resnull));

	if (arefstate->numlower == 0)
	{
		
		*op->resvalue = array_get_element(*op->resvalue, arefstate->numupper, arefstate->upperindex, arefstate->refattrlength, arefstate->refelemlength, arefstate->refelembyval, arefstate->refelemalign, op->resnull);






	}
	else {
		
		*op->resvalue = array_get_slice(*op->resvalue, arefstate->numupper, arefstate->upperindex, arefstate->lowerindex, arefstate->upperprovided, arefstate->lowerprovided, arefstate->refattrlength, arefstate->refelemlength, arefstate->refelembyval, arefstate->refelemalign);








	}
}


void ExecEvalArrayRefOld(ExprState *state, ExprEvalStep *op)
{
	ArrayRefState *arefstate = op->d.arrayref.state;

	if (*op->resnull)
	{
		
		arefstate->prevvalue = (Datum) 0;
		arefstate->prevnull = true;
	}
	else if (arefstate->numlower == 0)
	{
		
		arefstate->prevvalue = array_get_element(*op->resvalue, arefstate->numupper, arefstate->upperindex, arefstate->refattrlength, arefstate->refelemlength, arefstate->refelembyval, arefstate->refelemalign, &arefstate->prevnull);






	}
	else {
		
		
		arefstate->prevvalue = array_get_slice(*op->resvalue, arefstate->numupper, arefstate->upperindex, arefstate->lowerindex, arefstate->upperprovided, arefstate->lowerprovided, arefstate->refattrlength, arefstate->refelemlength, arefstate->refelembyval, arefstate->refelemalign);








		arefstate->prevnull = false;
	}
}


void ExecEvalArrayRefAssign(ExprState *state, ExprEvalStep *op)
{
	ArrayRefState *arefstate = op->d.arrayref.state;

	
	if (arefstate->refattrlength > 0)	
	{
		if (*op->resnull || arefstate->replacenull)
			return;
	}

	
	if (*op->resnull)
	{
		*op->resvalue = PointerGetDatum(construct_empty_array(arefstate->refelemtype));
		*op->resnull = false;
	}

	if (arefstate->numlower == 0)
	{
		
		*op->resvalue = array_set_element(*op->resvalue, arefstate->numupper, arefstate->upperindex, arefstate->replacevalue, arefstate->replacenull, arefstate->refattrlength, arefstate->refelemlength, arefstate->refelembyval, arefstate->refelemalign);







	}
	else {
		
		*op->resvalue = array_set_slice(*op->resvalue, arefstate->numupper, arefstate->upperindex, arefstate->lowerindex, arefstate->upperprovided, arefstate->lowerprovided, arefstate->replacevalue, arefstate->replacenull, arefstate->refattrlength, arefstate->refelemlength, arefstate->refelembyval, arefstate->refelemalign);










	}
}


void ExecEvalConvertRowtype(ExprState *state, ExprEvalStep *op, ExprContext *econtext)
{
	HeapTuple	result;
	Datum		tupDatum;
	HeapTupleHeader tuple;
	HeapTupleData tmptup;
	TupleDesc	indesc, outdesc;
	bool		changed = false;

	
	if (*op->resnull)
		return;

	tupDatum = *op->resvalue;
	tuple = DatumGetHeapTupleHeader(tupDatum);

	
	indesc = get_cached_rowtype(op->d.convert_rowtype.inputtype, -1, op->d.convert_rowtype.incache, &changed);

	IncrTupleDescRefCount(indesc);
	outdesc = get_cached_rowtype(op->d.convert_rowtype.outputtype, -1, op->d.convert_rowtype.outcache, &changed);

	IncrTupleDescRefCount(outdesc);

	
	Assert(HeapTupleHeaderGetTypeId(tuple) == indesc->tdtypeid || HeapTupleHeaderGetTypeId(tuple) == RECORDOID);

	
	if (changed)
	{
		MemoryContext old_cxt;

		
		old_cxt = MemoryContextSwitchTo(econtext->ecxt_per_query_memory);

		
		op->d.convert_rowtype.map = convert_tuples_by_name(indesc, outdesc, gettext_noop("could not convert row type"));


		MemoryContextSwitchTo(old_cxt);
	}

	
	tmptup.t_len = HeapTupleHeaderGetDatumLength(tuple);
	tmptup.t_data = tuple;

	if (op->d.convert_rowtype.map != NULL)
	{
		
		result = execute_attr_map_tuple(&tmptup, op->d.convert_rowtype.map);
		
		*op->resvalue = HeapTupleGetDatum(result);
	}
	else {
		
		*op->resvalue = heap_copy_tuple_as_datum(&tmptup, outdesc);
	}

	DecrTupleDescRefCount(indesc);
	DecrTupleDescRefCount(outdesc);
}


void ExecEvalScalarArrayOp(ExprState *state, ExprEvalStep *op)
{
	FunctionCallInfo fcinfo = op->d.scalararrayop.fcinfo_data;
	bool		useOr = op->d.scalararrayop.useOr;
	bool		strictfunc = op->d.scalararrayop.finfo->fn_strict;
	ArrayType  *arr;
	int			nitems;
	Datum		result;
	bool		resultnull;
	int			i;
	int16		typlen;
	bool		typbyval;
	char		typalign;
	char	   *s;
	bits8	   *bitmap;
	int			bitmask;

	
	if (*op->resnull)
		return;

	
	arr = DatumGetArrayTypeP(*op->resvalue);

	
	nitems = ArrayGetNItems(ARR_NDIM(arr), ARR_DIMS(arr));
	if (nitems <= 0)
	{
		*op->resvalue = BoolGetDatum(!useOr);
		*op->resnull = false;
		return;
	}

	
	if (fcinfo->args[0].isnull && strictfunc)
	{
		*op->resnull = true;
		return;
	}

	
	if (op->d.scalararrayop.element_type != ARR_ELEMTYPE(arr))
	{
		get_typlenbyvalalign(ARR_ELEMTYPE(arr), &op->d.scalararrayop.typlen, &op->d.scalararrayop.typbyval, &op->d.scalararrayop.typalign);


		op->d.scalararrayop.element_type = ARR_ELEMTYPE(arr);
	}

	typlen = op->d.scalararrayop.typlen;
	typbyval = op->d.scalararrayop.typbyval;
	typalign = op->d.scalararrayop.typalign;

	
	result = BoolGetDatum(!useOr);
	resultnull = false;

	
	s = (char *) ARR_DATA_PTR(arr);
	bitmap = ARR_NULLBITMAP(arr);
	bitmask = 1;

	for (i = 0; i < nitems; i++)
	{
		Datum		elt;
		Datum		thisresult;

		
		if (bitmap && (*bitmap & bitmask) == 0)
		{
			fcinfo->args[1].value = (Datum) 0;
			fcinfo->args[1].isnull = true;
		}
		else {
			elt = fetch_att(s, typbyval, typlen);
			s = att_addlength_pointer(s, typlen, s);
			s = (char *) att_align_nominal(s, typalign);
			fcinfo->args[1].value = elt;
			fcinfo->args[1].isnull = false;
		}

		
		if (fcinfo->args[1].isnull && strictfunc)
		{
			fcinfo->isnull = true;
			thisresult = (Datum) 0;
		}
		else {
			fcinfo->isnull = false;
			thisresult = op->d.scalararrayop.fn_addr(fcinfo);
		}

		
		if (fcinfo->isnull)
			resultnull = true;
		else if (useOr)
		{
			if (DatumGetBool(thisresult))
			{
				result = BoolGetDatum(true);
				resultnull = false;
				break;			
			}
		}
		else {
			if (!DatumGetBool(thisresult))
			{
				result = BoolGetDatum(false);
				resultnull = false;
				break;			
			}
		}

		
		if (bitmap)
		{
			bitmask <<= 1;
			if (bitmask == 0x100)
			{
				bitmap++;
				bitmask = 1;
			}
		}
	}

	*op->resvalue = result;
	*op->resnull = resultnull;
}


void ExecEvalConstraintNotNull(ExprState *state, ExprEvalStep *op)
{
	if (*op->resnull)
		ereport(ERROR, (errcode(ERRCODE_NOT_NULL_VIOLATION), errmsg("domain %s does not allow null values", format_type_be(op->d.domaincheck.resulttype)), errdatatype(op->d.domaincheck.resulttype)));



}


void ExecEvalConstraintCheck(ExprState *state, ExprEvalStep *op)
{
	if (!*op->d.domaincheck.checknull && !DatumGetBool(*op->d.domaincheck.checkvalue))
		ereport(ERROR, (errcode(ERRCODE_CHECK_VIOLATION), errmsg("value for domain %s violates check constraint \"%s\"", format_type_be(op->d.domaincheck.resulttype), op->d.domaincheck.constraintname), errdomainconstraint(op->d.domaincheck.resulttype, op->d.domaincheck.constraintname)));





}


void ExecEvalXmlExpr(ExprState *state, ExprEvalStep *op)
{
	XmlExpr    *xexpr = op->d.xmlexpr.xexpr;
	Datum		value;
	int			i;

	*op->resnull = true;		
	*op->resvalue = (Datum) 0;

	switch (xexpr->op)
	{
		case IS_XMLCONCAT:
			{
				Datum	   *argvalue = op->d.xmlexpr.argvalue;
				bool	   *argnull = op->d.xmlexpr.argnull;
				List	   *values = NIL;

				for (i = 0; i < list_length(xexpr->args); i++)
				{
					if (!argnull[i])
						values = lappend(values, DatumGetPointer(argvalue[i]));
				}

				if (values != NIL)
				{
					*op->resvalue = PointerGetDatum(xmlconcat(values));
					*op->resnull = false;
				}
			}
			break;

		case IS_XMLFOREST:
			{
				Datum	   *argvalue = op->d.xmlexpr.named_argvalue;
				bool	   *argnull = op->d.xmlexpr.named_argnull;
				StringInfoData buf;
				ListCell   *lc;
				ListCell   *lc2;

				initStringInfo(&buf);

				i = 0;
				forboth(lc, xexpr->named_args, lc2, xexpr->arg_names)
				{
					Expr	   *e = (Expr *) lfirst(lc);
					char	   *argname = strVal(lfirst(lc2));

					if (!argnull[i])
					{
						value = argvalue[i];
						appendStringInfo(&buf, "<%s>%s</%s>", argname, map_sql_value_to_xml_value(value, exprType((Node *) e), true), argname);



						*op->resnull = false;
					}
					i++;
				}

				if (!*op->resnull)
				{
					text	   *result;

					result = cstring_to_text_with_len(buf.data, buf.len);
					*op->resvalue = PointerGetDatum(result);
				}

				pfree(buf.data);
			}
			break;

		case IS_XMLELEMENT:
			*op->resvalue = PointerGetDatum(xmlelement(xexpr, op->d.xmlexpr.named_argvalue, op->d.xmlexpr.named_argnull, op->d.xmlexpr.argvalue, op->d.xmlexpr.argnull));



			*op->resnull = false;
			break;

		case IS_XMLPARSE:
			{
				Datum	   *argvalue = op->d.xmlexpr.argvalue;
				bool	   *argnull = op->d.xmlexpr.argnull;
				text	   *data;
				bool		preserve_whitespace;

				
				Assert(list_length(xexpr->args) == 2);

				if (argnull[0])
					return;
				value = argvalue[0];
				data = DatumGetTextPP(value);

				if (argnull[1]) 
					return;
				value = argvalue[1];
				preserve_whitespace = DatumGetBool(value);

				*op->resvalue = PointerGetDatum(xmlparse(data, xexpr->xmloption, preserve_whitespace));

				*op->resnull = false;
			}
			break;

		case IS_XMLPI:
			{
				text	   *arg;
				bool		isnull;

				
				Assert(list_length(xexpr->args) <= 1);

				if (xexpr->args)
				{
					isnull = op->d.xmlexpr.argnull[0];
					if (isnull)
						arg = NULL;
					else arg = DatumGetTextPP(op->d.xmlexpr.argvalue[0]);
				}
				else {
					arg = NULL;
					isnull = false;
				}

				*op->resvalue = PointerGetDatum(xmlpi(xexpr->name, arg, isnull, op->resnull));


			}
			break;

		case IS_XMLROOT:
			{
				Datum	   *argvalue = op->d.xmlexpr.argvalue;
				bool	   *argnull = op->d.xmlexpr.argnull;
				xmltype    *data;
				text	   *version;
				int			standalone;

				
				Assert(list_length(xexpr->args) == 3);

				if (argnull[0])
					return;
				data = DatumGetXmlP(argvalue[0]);

				if (argnull[1])
					version = NULL;
				else version = DatumGetTextPP(argvalue[1]);

				Assert(!argnull[2]);	
				standalone = DatumGetInt32(argvalue[2]);

				*op->resvalue = PointerGetDatum(xmlroot(data, version, standalone));

				*op->resnull = false;
			}
			break;

		case IS_XMLSERIALIZE:
			{
				Datum	   *argvalue = op->d.xmlexpr.argvalue;
				bool	   *argnull = op->d.xmlexpr.argnull;

				
				Assert(list_length(xexpr->args) == 1);

				if (argnull[0])
					return;
				value = argvalue[0];

				*op->resvalue = PointerGetDatum( xmltotext_with_xmloption(DatumGetXmlP(value), xexpr->xmloption));

				*op->resnull = false;
			}
			break;

		case IS_DOCUMENT:
			{
				Datum	   *argvalue = op->d.xmlexpr.argvalue;
				bool	   *argnull = op->d.xmlexpr.argnull;

				
				Assert(list_length(xexpr->args) == 1);

				if (argnull[0])
					return;
				value = argvalue[0];

				*op->resvalue = BoolGetDatum(xml_is_document(DatumGetXmlP(value)));
				*op->resnull = false;
			}
			break;

		default:
			elog(ERROR, "unrecognized XML operation");
			break;
	}
}


void ExecEvalGroupingFunc(ExprState *state, ExprEvalStep *op)
{
	int			result = 0;
	Bitmapset  *grouped_cols = op->d.grouping_func.parent->grouped_cols;
	ListCell   *lc;

	foreach(lc, op->d.grouping_func.clauses)
	{
		int			attnum = lfirst_int(lc);

		result <<= 1;

		if (!bms_is_member(attnum, grouped_cols))
			result |= 1;
	}

	*op->resvalue = Int32GetDatum(result);
	*op->resnull = false;
}


void ExecEvalSubPlan(ExprState *state, ExprEvalStep *op, ExprContext *econtext)
{
	SubPlanState *sstate = op->d.subplan.sstate;

	
	check_stack_depth();

	*op->resvalue = ExecSubPlan(sstate, econtext, op->resnull);
}


void ExecEvalAlternativeSubPlan(ExprState *state, ExprEvalStep *op, ExprContext *econtext)
{
	AlternativeSubPlanState *asstate = op->d.alternative_subplan.asstate;

	
	check_stack_depth();

	*op->resvalue = ExecAlternativeSubPlan(asstate, econtext, op->resnull);
}


void ExecEvalWholeRowVar(ExprState *state, ExprEvalStep *op, ExprContext *econtext)
{
	Var		   *variable = op->d.wholerow.var;
	TupleTableSlot *slot;
	TupleDesc	output_tupdesc;
	MemoryContext oldcontext;
	HeapTupleHeader dtuple;
	HeapTuple	tuple;

	
	Assert(variable->varattno == InvalidAttrNumber);

	
	switch (variable->varno)
	{
		case INNER_VAR:
			
			slot = econtext->ecxt_innertuple;
			break;

		case OUTER_VAR:
			
			slot = econtext->ecxt_outertuple;
			break;

			

		default:
			
			slot = econtext->ecxt_scantuple;
			break;
	}

	
	if (op->d.wholerow.junkFilter != NULL)
		slot = ExecFilterJunk(op->d.wholerow.junkFilter, slot);

	
	if (op->d.wholerow.first)
	{
		
		op->d.wholerow.slow = false;

		
		if (variable->vartype != RECORDOID)
		{
			TupleDesc	var_tupdesc;
			TupleDesc	slot_tupdesc;
			int			i;

			
			var_tupdesc = lookup_rowtype_tupdesc_domain(variable->vartype, -1, false);

			slot_tupdesc = slot->tts_tupleDescriptor;

			if (var_tupdesc->natts != slot_tupdesc->natts)
				ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("table row type and query-specified row type do not match"), errdetail_plural("Table row contains %d attribute, but query expects %d.", "Table row contains %d attributes, but query expects %d.", slot_tupdesc->natts, slot_tupdesc->natts, var_tupdesc->natts)));







			for (i = 0; i < var_tupdesc->natts; i++)
			{
				Form_pg_attribute vattr = TupleDescAttr(var_tupdesc, i);
				Form_pg_attribute sattr = TupleDescAttr(slot_tupdesc, i);

				if (vattr->atttypid == sattr->atttypid)
					continue;	
				if (!vattr->attisdropped)
					ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("table row type and query-specified row type do not match"), errdetail("Table has type %s at ordinal position %d, but query expects %s.", format_type_be(sattr->atttypid), i + 1, format_type_be(vattr->atttypid))));






				if (vattr->attlen != sattr->attlen || vattr->attalign != sattr->attalign)
					op->d.wholerow.slow = true; 
			}

			
			oldcontext = MemoryContextSwitchTo(econtext->ecxt_per_query_memory);
			output_tupdesc = CreateTupleDescCopy(var_tupdesc);
			MemoryContextSwitchTo(oldcontext);

			ReleaseTupleDesc(var_tupdesc);
		}
		else {
			
			oldcontext = MemoryContextSwitchTo(econtext->ecxt_per_query_memory);
			output_tupdesc = CreateTupleDescCopy(slot->tts_tupleDescriptor);
			MemoryContextSwitchTo(oldcontext);
		}

		
		if (econtext->ecxt_estate && variable->varno <= list_length(econtext->ecxt_estate->es_range_table))
		{
			RangeTblEntry *rte = rt_fetch(variable->varno, econtext->ecxt_estate->es_range_table);

			if (rte->eref)
				ExecTypeSetColNames(output_tupdesc, rte->eref->colnames);
		}

		
		op->d.wholerow.tupdesc = BlessTupleDesc(output_tupdesc);

		op->d.wholerow.first = false;
	}

	
	slot_getallattrs(slot);

	if (op->d.wholerow.slow)
	{
		
		TupleDesc	tupleDesc = slot->tts_tupleDescriptor;
		TupleDesc	var_tupdesc = op->d.wholerow.tupdesc;
		int			i;

		Assert(var_tupdesc->natts == tupleDesc->natts);

		for (i = 0; i < var_tupdesc->natts; i++)
		{
			Form_pg_attribute vattr = TupleDescAttr(var_tupdesc, i);
			Form_pg_attribute sattr = TupleDescAttr(tupleDesc, i);

			if (!vattr->attisdropped)
				continue;		
			if (slot->tts_isnull[i])
				continue;		
			if (vattr->attlen != sattr->attlen || vattr->attalign != sattr->attalign)
				ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("table row type and query-specified row type do not match"), errdetail("Physical storage mismatch on dropped attribute at ordinal position %d.", i + 1)));



		}
	}

	
	tuple = toast_build_flattened_tuple(slot->tts_tupleDescriptor, slot->tts_values, slot->tts_isnull);

	dtuple = tuple->t_data;

	
	HeapTupleHeaderSetTypeId(dtuple, op->d.wholerow.tupdesc->tdtypeid);
	HeapTupleHeaderSetTypMod(dtuple, op->d.wholerow.tupdesc->tdtypmod);

	*op->resvalue = PointerGetDatum(dtuple);
	*op->resnull = false;
}


void ExecAggInitGroup(AggState *aggstate, AggStatePerTrans pertrans, AggStatePerGroup pergroup)
{
	FunctionCallInfo fcinfo = pertrans->transfn_fcinfo;
	MemoryContext oldContext;

	
	oldContext = MemoryContextSwitchTo( aggstate->curaggcontext->ecxt_per_tuple_memory);
	pergroup->transValue = datumCopy(fcinfo->args[1].value, pertrans->transtypeByVal, pertrans->transtypeLen);

	pergroup->transValueIsNull = false;
	pergroup->noTransValue = false;
	MemoryContextSwitchTo(oldContext);
}


Datum ExecAggTransReparent(AggState *aggstate, AggStatePerTrans pertrans, Datum newValue, bool newValueIsNull, Datum oldValue, bool oldValueIsNull)


{
	if (!newValueIsNull)
	{
		MemoryContextSwitchTo(aggstate->curaggcontext->ecxt_per_tuple_memory);
		if (DatumIsReadWriteExpandedObject(newValue, false, pertrans->transtypeLen) && MemoryContextGetParent(DatumGetEOHP(newValue)->eoh_context) == GetCurrentMemoryContext())


			  ;
		else newValue = datumCopy(newValue, pertrans->transtypeByVal, pertrans->transtypeLen);


	}
	if (!oldValueIsNull)
	{
		if (DatumIsReadWriteExpandedObject(oldValue, false, pertrans->transtypeLen))

			DeleteExpandedObject(oldValue);
		else pfree(DatumGetPointer(oldValue));
	}

	return newValue;
}


void ExecEvalAggOrderedTransDatum(ExprState *state, ExprEvalStep *op, ExprContext *econtext)

{
	AggStatePerTrans pertrans = op->d.agg_trans.pertrans;
	int			setno = op->d.agg_trans.setno;

	tuplesort_putdatum(pertrans->sortstates[setno], *op->resvalue, *op->resnull);
}


void ExecEvalAggOrderedTransTuple(ExprState *state, ExprEvalStep *op, ExprContext *econtext)

{
	AggStatePerTrans pertrans = op->d.agg_trans.pertrans;
	int			setno = op->d.agg_trans.setno;

	ExecClearTuple(pertrans->sortslot);
	pertrans->sortslot->tts_nvalid = pertrans->numInputs;
	ExecStoreVirtualTuple(pertrans->sortslot);
	tuplesort_puttupleslot(pertrans->sortstates[setno], pertrans->sortslot);
}
