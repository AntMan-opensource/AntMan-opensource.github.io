





















































































































































extern int errno;
























typedef unsigned long trio_flags_t;















int read(int handle, char* buffer, unsigned int length);
int write(int handle, const char* buffer, unsigned int length);











typedef wchar_t trio_wchar_t;
typedef wint_t trio_wint_t;

typedef char trio_wchar_t;
typedef int trio_wint_t;









































typedef signed long long int trio_longlong_t;
typedef unsigned long long int trio_ulonglong_t;


typedef signed __int64 trio_longlong_t;
typedef unsigned __int64 trio_ulonglong_t;

typedef TRIO_SIGNED long int trio_longlong_t;
typedef unsigned long int trio_ulonglong_t;






typedef intmax_t trio_intmax_t;
typedef uintmax_t trio_uintmax_t;
typedef int8_t trio_int8_t;
typedef int16_t trio_int16_t;
typedef int32_t trio_int32_t;
typedef int64_t trio_int64_t;



typedef intmax_t trio_intmax_t;
typedef uintmax_t trio_uintmax_t;
typedef int8_t trio_int8_t;
typedef int16_t trio_int16_t;
typedef int32_t trio_int32_t;
typedef int64_t trio_int64_t;


typedef trio_longlong_t trio_intmax_t;
typedef trio_ulonglong_t trio_uintmax_t;
typedef __int8 trio_int8_t;
typedef __int16 trio_int16_t;
typedef __int32 trio_int32_t;
typedef __int64 trio_int64_t;

typedef trio_longlong_t trio_intmax_t;
typedef trio_ulonglong_t trio_uintmax_t;

typedef TRIO_INT8_T trio_int8_t;

typedef TRIO_SIGNED char trio_int8_t;


typedef TRIO_INT16_T trio_int16_t;

typedef TRIO_SIGNED short trio_int16_t;


typedef TRIO_INT32_T trio_int32_t;

typedef TRIO_SIGNED int trio_int32_t;


typedef TRIO_INT64_T trio_int64_t;

typedef trio_longlong_t trio_int64_t;


























































































enum {
	TYPE_PRINT = 1,  TYPE_SCAN = 2,    FLAGS_NEW = 0, FLAGS_STICKY = 1, FLAGS_SPACE = 2 * FLAGS_STICKY, FLAGS_SHOWSIGN = 2 * FLAGS_SPACE, FLAGS_LEFTADJUST = 2 * FLAGS_SHOWSIGN, FLAGS_ALTERNATIVE = 2 * FLAGS_LEFTADJUST, FLAGS_SHORT = 2 * FLAGS_ALTERNATIVE, FLAGS_SHORTSHORT = 2 * FLAGS_SHORT, FLAGS_LONG = 2 * FLAGS_SHORTSHORT, FLAGS_QUAD = 2 * FLAGS_LONG, FLAGS_LONGDOUBLE = 2 * FLAGS_QUAD, FLAGS_SIZE_T = 2 * FLAGS_LONGDOUBLE, FLAGS_PTRDIFF_T = 2 * FLAGS_SIZE_T, FLAGS_INTMAX_T = 2 * FLAGS_PTRDIFF_T, FLAGS_NILPADDING = 2 * FLAGS_INTMAX_T, FLAGS_UNSIGNED = 2 * FLAGS_NILPADDING, FLAGS_UPPER = 2 * FLAGS_UNSIGNED, FLAGS_WIDTH = 2 * FLAGS_UPPER, FLAGS_WIDTH_PARAMETER = 2 * FLAGS_WIDTH, FLAGS_PRECISION = 2 * FLAGS_WIDTH_PARAMETER, FLAGS_PRECISION_PARAMETER = 2 * FLAGS_PRECISION, FLAGS_BASE = 2 * FLAGS_PRECISION_PARAMETER, FLAGS_BASE_PARAMETER = 2 * FLAGS_BASE, FLAGS_FLOAT_E = 2 * FLAGS_BASE_PARAMETER, FLAGS_FLOAT_G = 2 * FLAGS_FLOAT_E, FLAGS_QUOTE = 2 * FLAGS_FLOAT_G, FLAGS_WIDECHAR = 2 * FLAGS_QUOTE, FLAGS_IGNORE = 2 * FLAGS_WIDECHAR, FLAGS_IGNORE_PARAMETER = 2 * FLAGS_IGNORE, FLAGS_VARSIZE_PARAMETER = 2 * FLAGS_IGNORE_PARAMETER, FLAGS_FIXED_SIZE = 2 * FLAGS_VARSIZE_PARAMETER, FLAGS_LAST = FLAGS_FIXED_SIZE,  FLAGS_EXCLUDE = FLAGS_SHORT, FLAGS_USER_DEFINED = FLAGS_IGNORE, FLAGS_USER_DEFINED_PARAMETER = FLAGS_IGNORE_PARAMETER, FLAGS_ROUNDING = FLAGS_INTMAX_T,  FLAGS_ALL_VARSIZES = FLAGS_LONG | FLAGS_QUAD | FLAGS_INTMAX_T | FLAGS_PTRDIFF_T | FLAGS_SIZE_T, FLAGS_ALL_SIZES = FLAGS_ALL_VARSIZES | FLAGS_SHORTSHORT | FLAGS_SHORT,  NO_POSITION = -1, NO_WIDTH = 0, NO_PRECISION = -1, NO_SIZE = -1,   NO_BASE = -1, MIN_BASE = 2, MAX_BASE = 36, BASE_BINARY = 2, BASE_OCTAL = 8, BASE_DECIMAL = 10, BASE_HEX = 16,   MAX_PARAMETERS = 64,  MAX_CHARACTER_CLASS = UCHAR_MAX + 1,    MAX_USER_NAME = 64, MAX_USER_DATA = 256,    MAX_LOCALE_SEPARATOR_LENGTH = MB_LEN_MAX,  MAX_LOCALE_GROUPS = 64 };






























































































































































































typedef struct {
	
	int type;
	
	trio_flags_t flags;
	
	int width;
	
	int precision;
	
	int base;
	
	int baseSpecifier;
	
	int varsize;
	
	int beginOffset;
	
	int endOffset;
	
	int position;
	
	union {
		char* string;

		trio_wchar_t* wstring;

		trio_pointer_t pointer;
		union {
			trio_intmax_t as_signed;
			trio_uintmax_t as_unsigned;
		} number;

		double doubleNumber;
		double* doublePointer;
		trio_long_double_t longdoubleNumber;
		trio_long_double_t* longdoublePointer;

		int errorNumber;
	} data;

	
	union {
		char namespace[MAX_USER_NAME];
		int handler; 
	} user_defined;
	char user_data[MAX_USER_DATA];

} trio_parameter_t;


typedef struct {
	union {
		trio_outstream_t out;
		trio_instream_t in;
	} stream;
	trio_pointer_t closure;
} trio_custom_t;


typedef struct _trio_class_t {
	
	void(*OutStream) TRIO_PROTO((struct _trio_class_t*, int));
	
	void(*InStream) TRIO_PROTO((struct _trio_class_t*, int*));
	
	void(*UndoStream) TRIO_PROTO((struct _trio_class_t*));
	
	trio_pointer_t location;
	
	int current;
	
	int processed;
	union {
		
		int committed;
		
		int cached;
	} actually;
	
	int max;
	
	int error;
} trio_class_t;


typedef struct _trio_reference_t {
	trio_class_t* data;
	trio_parameter_t* parameter;
} trio_reference_t;



typedef struct _trio_userdef_t {
	struct _trio_userdef_t* next;
	trio_callback_t callback;
	char* name;
} trio_userdef_t;









static TRIO_CONST trio_long_double_t ___dummy_long_double = 0;



static TRIO_CONST char internalNullString[] = "(nil)";


static struct lconv* internalLocaleValues = NULL;




static int internalDecimalPointLength = 1;
static char internalDecimalPoint = '.';
static char internalDecimalPointString[MAX_LOCALE_SEPARATOR_LENGTH + 1] = ".";


static int internalThousandSeparatorLength = 1;
static char internalThousandSeparator[MAX_LOCALE_SEPARATOR_LENGTH + 1] = ",";
static char internalGrouping[MAX_LOCALE_GROUPS] = { (char)NO_GROUPING };


static TRIO_CONST char internalDigitsLower[] = "0123456789abcdefghijklmnopqrstuvwxyz";
static TRIO_CONST char internalDigitsUpper[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

static BOOLEAN_T internalDigitsUnconverted = TRUE;
static int internalDigitArray[128];

static BOOLEAN_T internalCollationUnconverted = TRUE;
static char internalCollationArray[MAX_CHARACTER_CLASS][MAX_CHARACTER_CLASS];




static TRIO_VOLATILE trio_callback_t internalEnterCriticalRegion = NULL;
static TRIO_VOLATILE trio_callback_t internalLeaveCriticalRegion = NULL;
static trio_userdef_t* internalUserDef = NULL;













TRIO_PRIVATE void TrioInitializeParameter TRIO_ARGS1((parameter), trio_parameter_t* parameter)
{
	parameter->type = FORMAT_UNKNOWN;
	parameter->flags = 0;
	parameter->width = 0;
	parameter->precision = 0;
	parameter->base = 0;
	parameter->baseSpecifier = 0;
	parameter->varsize = 0;
	parameter->beginOffset = 0;
	parameter->endOffset = 0;
	parameter->position = 0;
	parameter->data.pointer = 0;

	parameter->user_defined.handler = 0;
	parameter->user_data[0] = 0;

}


TRIO_PRIVATE void TrioCopyParameter TRIO_ARGS2((target, source), trio_parameter_t* target, TRIO_CONST trio_parameter_t* source)
{

	size_t i;


	target->type = source->type;
	target->flags = source->flags;
	target->width = source->width;
	target->precision = source->precision;
	target->base = source->base;
	target->baseSpecifier = source->baseSpecifier;
	target->varsize = source->varsize;
	target->beginOffset = source->beginOffset;
	target->endOffset = source->endOffset;
	target->position = source->position;
	target->data = source->data;


	target->user_defined = source->user_defined;

	for (i = 0U; i < sizeof(target->user_data); ++i)
	{
		if ((target->user_data[i] = source->user_data[i]) == NIL)
			break;
	}

}


TRIO_PRIVATE BOOLEAN_T TrioIsQualifier TRIO_ARGS1((character), TRIO_CONST char character)
{
	
	switch (character)
	{
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case QUALIFIER_PLUS:
		case QUALIFIER_MINUS:
		case QUALIFIER_SPACE:
		case QUALIFIER_DOT:
		case QUALIFIER_STAR:
		case QUALIFIER_ALTERNATIVE:
		case QUALIFIER_SHORT:
		case QUALIFIER_LONG:
		case QUALIFIER_CIRCUMFLEX:
		case QUALIFIER_LONG_UPPER:
		case QUALIFIER_SIZE_T:
		case QUALIFIER_PTRDIFF_T:
		case QUALIFIER_INTMAX_T:
		case QUALIFIER_QUAD:
		case QUALIFIER_SIZE_T_UPPER:

		case QUALIFIER_WIDECHAR:

		case QUALIFIER_QUOTE:
		case QUALIFIER_STICKY:
		case QUALIFIER_VARSIZE:

		case QUALIFIER_PARAM:

		case QUALIFIER_FIXED_SIZE:
		case QUALIFIER_ROUNDING_UPPER:
			return TRUE;
		default:
			return FALSE;
	}
}



TRIO_PRIVATE void TrioSetLocale(TRIO_NOARGS)
{
	internalLocaleValues = (struct lconv*)localeconv();
	if (internalLocaleValues)
	{
		if ((internalLocaleValues->decimal_point) && (internalLocaleValues->decimal_point[0] != NIL))
		{
			internalDecimalPointLength = trio_length(internalLocaleValues->decimal_point);
			if (internalDecimalPointLength == 1)
			{
				internalDecimalPoint = internalLocaleValues->decimal_point[0];
			}
			else {
				internalDecimalPoint = NIL;
				trio_copy_max(internalDecimalPointString, sizeof(internalDecimalPointString), internalLocaleValues->decimal_point);
			}
		}

		if ((internalLocaleValues->thousands_sep) && (internalLocaleValues->thousands_sep[0] != NIL))
		{
			trio_copy_max(internalThousandSeparator, sizeof(internalThousandSeparator), internalLocaleValues->thousands_sep);
			internalThousandSeparatorLength = trio_length(internalThousandSeparator);
		}


		if ((internalLocaleValues->grouping) && (internalLocaleValues->grouping[0] != NIL))
		{
			trio_copy_max(internalGrouping, sizeof(internalGrouping), internalLocaleValues->grouping);
		}

	}
}



TRIO_PRIVATE int TrioCalcThousandSeparatorLength TRIO_ARGS1((digits), int digits)
{
	int count = 0;
	int step = NO_GROUPING;
	char* groupingPointer = internalGrouping;

	while (digits > 0)
	{
		if (*groupingPointer == CHAR_MAX)
		{
			
			break; 
		}
		else if (*groupingPointer == 0)
		{
			
			if (step == NO_GROUPING)
			{
				
				break; 
			}
		}
		else {
			step = *groupingPointer++;
		}
		if (digits > step)
			count += internalThousandSeparatorLength;
		digits -= step;
	}
	return count;
}



TRIO_PRIVATE BOOLEAN_T TrioFollowedBySeparator TRIO_ARGS1((position), int position)
{
	int step = 0;
	char* groupingPointer = internalGrouping;

	position--;
	if (position == 0)
		return FALSE;
	while (position > 0)
	{
		if (*groupingPointer == CHAR_MAX)
		{
			
			break; 
		}
		else if (*groupingPointer != 0)
		{
			step = *groupingPointer++;
		}
		if (step == 0)
			break;
		position -= step;
	}
	return (position == 0);
}



TRIO_PRIVATE int TrioGetPosition TRIO_ARGS2((format, offsetPointer), TRIO_CONST char* format, int* offsetPointer)
{

	char* tmpformat;
	int number = 0;
	int offset = *offsetPointer;

	number = (int)trio_to_long(&format[offset], &tmpformat, BASE_DECIMAL);
	offset = (int)(tmpformat - format);
	if ((number != 0) && (QUALIFIER_POSITION == format[offset++]))
	{
		*offsetPointer = offset;
		
		return number - 1;
	}

	return NO_POSITION;
}



TRIO_PRIVATE trio_userdef_t* TrioFindNamespace TRIO_ARGS2((name, prev), TRIO_CONST char* name, trio_userdef_t** prev)
{
	trio_userdef_t* def;

	if (internalEnterCriticalRegion)
		(void)internalEnterCriticalRegion(NULL);

	for (def = internalUserDef; def; def = def->next)
	{
		
		if (trio_equal_case(def->name, name))
			break;

		if (prev)
			*prev = def;
	}

	if (internalLeaveCriticalRegion)
		(void)internalLeaveCriticalRegion(NULL);

	return def;
}




TRIO_PRIVATE trio_long_double_t TrioPower TRIO_ARGS2((number, exponent), int number, int exponent)
{
	trio_long_double_t result;

	if (number == 10)
	{
		switch (exponent)
		{
				
			case 0:
				result = (trio_long_double_t)number * TRIO_SUFFIX_LONG(1E-1);
				break;
			case 1:
				result = (trio_long_double_t)number * TRIO_SUFFIX_LONG(1E+0);
				break;
			case 2:
				result = (trio_long_double_t)number * TRIO_SUFFIX_LONG(1E+1);
				break;
			case 3:
				result = (trio_long_double_t)number * TRIO_SUFFIX_LONG(1E+2);
				break;
			case 4:
				result = (trio_long_double_t)number * TRIO_SUFFIX_LONG(1E+3);
				break;
			case 5:
				result = (trio_long_double_t)number * TRIO_SUFFIX_LONG(1E+4);
				break;
			case 6:
				result = (trio_long_double_t)number * TRIO_SUFFIX_LONG(1E+5);
				break;
			case 7:
				result = (trio_long_double_t)number * TRIO_SUFFIX_LONG(1E+6);
				break;
			case 8:
				result = (trio_long_double_t)number * TRIO_SUFFIX_LONG(1E+7);
				break;
			case 9:
				result = (trio_long_double_t)number * TRIO_SUFFIX_LONG(1E+8);
				break;
			default:
				result = trio_pow((trio_long_double_t)number, (trio_long_double_t)exponent);
				break;
		}
	}
	else {
		return trio_pow((trio_long_double_t)number, (trio_long_double_t)exponent);
	}
	return result;
}




TRIO_PRIVATE trio_long_double_t TrioLogarithm TRIO_ARGS2((number, base), trio_long_double_t number, int base)
{
	trio_long_double_t result;

	if (number <= 0.0)
	{
		
		result = (number == 0.0) ? trio_ninf() : trio_nan();
	}
	else {
		if (base == 10)
		{
			result = trio_log10(number);
		}
		else {
			result = trio_log10(number) / trio_log10((double)base);
		}
	}
	return result;
}




TRIO_PRIVATE double TrioLogarithmBase TRIO_ARGS1((base), int base)
{
	switch (base)
	{
		case BASE_BINARY:
			return 1.0;
		case BASE_OCTAL:
			return 3.0;
		case BASE_DECIMAL:
			return 3.321928094887362345;
		case BASE_HEX:
			return 4.0;
		default:
			return TrioLogarithm((double)base, 2);
	}
}





TRIO_PRIVATE int TrioParseQualifiers TRIO_ARGS4((type, format, offset, parameter), int type, TRIO_CONST char* format, int offset, trio_parameter_t* parameter)

{
	char ch;
	int dots = 0; 
	char* tmpformat;

	parameter->beginOffset = offset - 1;
	parameter->flags = FLAGS_NEW;
	parameter->position = TrioGetPosition(format, &offset);

	
	parameter->width = NO_WIDTH;
	parameter->precision = NO_PRECISION;
	parameter->base = NO_BASE;
	parameter->varsize = NO_SIZE;

	while (TrioIsQualifier(format[offset]))
	{
		ch = format[offset++];

		switch (ch)
		{
			case QUALIFIER_SPACE:
				parameter->flags |= FLAGS_SPACE;
				break;

			case QUALIFIER_PLUS:
				parameter->flags |= FLAGS_SHOWSIGN;
				break;

			case QUALIFIER_MINUS:
				parameter->flags |= FLAGS_LEFTADJUST;
				parameter->flags &= ~FLAGS_NILPADDING;
				break;

			case QUALIFIER_ALTERNATIVE:
				parameter->flags |= FLAGS_ALTERNATIVE;
				break;

			case QUALIFIER_DOT:
				if (dots == 0) 
				{
					dots++;

					
					if (QUALIFIER_DOT == format[offset])
						break;

					
					parameter->flags |= FLAGS_PRECISION;
					if ((QUALIFIER_STAR == format[offset])

					    || (QUALIFIER_PARAM == format[offset])

					)
					{
						offset++;
						parameter->flags |= FLAGS_PRECISION_PARAMETER;
						parameter->precision = TrioGetPosition(format, &offset);
					}
					else {
						parameter->precision = trio_to_long(&format[offset], &tmpformat, BASE_DECIMAL);
						offset = (int)(tmpformat - format);
					}
				}
				else if (dots == 1) 
				{
					dots++;

					
					parameter->flags |= FLAGS_BASE;
					if ((QUALIFIER_STAR == format[offset])

					    || (QUALIFIER_PARAM == format[offset])

					)
					{
						offset++;
						parameter->flags |= FLAGS_BASE_PARAMETER;
						parameter->base = TrioGetPosition(format, &offset);
					}
					else {
						parameter->base = trio_to_long(&format[offset], &tmpformat, BASE_DECIMAL);
						if (parameter->base > MAX_BASE)
							return TRIO_ERROR_RETURN(TRIO_EINVAL, offset);
						offset = (int)(tmpformat - format);
					}
				}
				else {
					return TRIO_ERROR_RETURN(TRIO_EINVAL, offset);
				}
				break; 


			case QUALIFIER_PARAM:
				parameter->type = TYPE_PRINT;
				

			case QUALIFIER_STAR:
				
				if (TYPE_PRINT == type)
				{
					
					int width = TrioGetPosition(format, &offset);
					parameter->flags |= (FLAGS_WIDTH | FLAGS_WIDTH_PARAMETER);
					if (NO_POSITION != width)
						parameter->width = width;
					
				}

				else {
					
					parameter->flags |= FLAGS_IGNORE;
				}

				break; 

			case '0':
				if (!(parameter->flags & FLAGS_LEFTADJUST))
					parameter->flags |= FLAGS_NILPADDING;
				
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
				parameter->flags |= FLAGS_WIDTH;
				
				parameter->width = trio_to_long(&format[offset - 1], &tmpformat, BASE_DECIMAL);
				offset = (int)(tmpformat - format);
				break;

			case QUALIFIER_SHORT:
				if (parameter->flags & FLAGS_SHORTSHORT)
					return TRIO_ERROR_RETURN(TRIO_EINVAL, offset);
				else if (parameter->flags & FLAGS_SHORT)
					parameter->flags |= FLAGS_SHORTSHORT;
				else parameter->flags |= FLAGS_SHORT;
				break;

			case QUALIFIER_LONG:
				if (parameter->flags & FLAGS_QUAD)
					return TRIO_ERROR_RETURN(TRIO_EINVAL, offset);
				else if (parameter->flags & FLAGS_LONG)
					parameter->flags |= FLAGS_QUAD;
				else parameter->flags |= FLAGS_LONG;
				break;


			case QUALIFIER_LONG_UPPER:
				parameter->flags |= FLAGS_LONGDOUBLE;
				break;



			case QUALIFIER_SIZE_T:
				parameter->flags |= FLAGS_SIZE_T;
				
				if (sizeof(size_t) == sizeof(trio_ulonglong_t))
					parameter->flags |= FLAGS_QUAD;
				else if (sizeof(size_t) == sizeof(long))
					parameter->flags |= FLAGS_LONG;
				break;



			case QUALIFIER_PTRDIFF_T:
				parameter->flags |= FLAGS_PTRDIFF_T;
				if (sizeof(ptrdiff_t) == sizeof(trio_ulonglong_t))
					parameter->flags |= FLAGS_QUAD;
				else if (sizeof(ptrdiff_t) == sizeof(long))
					parameter->flags |= FLAGS_LONG;
				break;



			case QUALIFIER_INTMAX_T:
				parameter->flags |= FLAGS_INTMAX_T;
				if (sizeof(trio_intmax_t) == sizeof(trio_ulonglong_t))
					parameter->flags |= FLAGS_QUAD;
				else if (sizeof(trio_intmax_t) == sizeof(long))
					parameter->flags |= FLAGS_LONG;
				break;



			case QUALIFIER_QUAD:
				parameter->flags |= FLAGS_QUAD;
				break;



			case QUALIFIER_FIXED_SIZE:
				if (parameter->flags & FLAGS_FIXED_SIZE)
					return TRIO_ERROR_RETURN(TRIO_EINVAL, offset);

				if (parameter->flags & (FLAGS_ALL_SIZES | FLAGS_LONGDOUBLE | FLAGS_WIDECHAR | FLAGS_VARSIZE_PARAMETER))
					return TRIO_ERROR_RETURN(TRIO_EINVAL, offset);

				if ((format[offset] == '6') && (format[offset + 1] == '4'))
				{
					parameter->varsize = sizeof(trio_int64_t);
					offset += 2;
				}
				else if ((format[offset] == '3') && (format[offset + 1] == '2'))
				{
					parameter->varsize = sizeof(trio_int32_t);
					offset += 2;
				}
				else if ((format[offset] == '1') && (format[offset + 1] == '6'))
				{
					parameter->varsize = sizeof(trio_int16_t);
					offset += 2;
				}
				else if (format[offset] == '8')
				{
					parameter->varsize = sizeof(trio_int8_t);
					offset++;
				}
				else return TRIO_ERROR_RETURN(TRIO_EINVAL, offset);

				parameter->flags |= FLAGS_FIXED_SIZE;
				break;



			case QUALIFIER_WIDECHAR:
				parameter->flags |= FLAGS_WIDECHAR;
				break;



			case QUALIFIER_SIZE_T_UPPER:
				break;



			case QUALIFIER_QUOTE:
				parameter->flags |= FLAGS_QUOTE;
				break;



			case QUALIFIER_STICKY:
				parameter->flags |= FLAGS_STICKY;
				break;



			case QUALIFIER_VARSIZE:
				parameter->flags |= FLAGS_VARSIZE_PARAMETER;
				break;



			case QUALIFIER_ROUNDING_UPPER:
				parameter->flags |= FLAGS_ROUNDING;
				break;


			default:
				
				return TRIO_ERROR_RETURN(TRIO_EINVAL, offset);
		}

	} 

	parameter->endOffset = offset;

	return 0;
}





TRIO_PRIVATE int TrioParseSpecifier TRIO_ARGS4((type, format, offset, parameter), int type, TRIO_CONST char* format, int offset, trio_parameter_t* parameter)

{
	parameter->baseSpecifier = NO_BASE;

	switch (format[offset++])
	{

		case SPECIFIER_CHAR_UPPER:
			parameter->flags |= FLAGS_WIDECHAR;
			

		case SPECIFIER_CHAR:
			if (parameter->flags & FLAGS_LONG)
				parameter->flags |= FLAGS_WIDECHAR;
			else if (parameter->flags & FLAGS_SHORT)
				parameter->flags &= ~FLAGS_WIDECHAR;
			parameter->type = FORMAT_CHAR;
			break;


		case SPECIFIER_STRING_UPPER:
			parameter->flags |= FLAGS_WIDECHAR;
			

		case SPECIFIER_STRING:
			if (parameter->flags & FLAGS_LONG)
				parameter->flags |= FLAGS_WIDECHAR;
			else if (parameter->flags & FLAGS_SHORT)
				parameter->flags &= ~FLAGS_WIDECHAR;
			parameter->type = FORMAT_STRING;
			break;


		case SPECIFIER_GROUP:
			if (TYPE_SCAN == type)
			{
				int depth = 1;
				parameter->type = FORMAT_GROUP;
				if (format[offset] == QUALIFIER_CIRCUMFLEX)
					offset++;
				if (format[offset] == SPECIFIER_UNGROUP)
					offset++;
				if (format[offset] == QUALIFIER_MINUS)
					offset++;
				
				while (format[offset] != NIL)
				{
					if (format[offset] == SPECIFIER_GROUP)
					{
						depth++;
					}
					else if (format[offset] == SPECIFIER_UNGROUP)
					{
						if (--depth <= 0)
						{
							offset++;
							break;
						}
					}
					offset++;
				}
			}
			break;


		case SPECIFIER_INTEGER:
			parameter->type = FORMAT_INT;
			break;

		case SPECIFIER_UNSIGNED:
			parameter->flags |= FLAGS_UNSIGNED;
			parameter->type = FORMAT_INT;
			break;

		case SPECIFIER_DECIMAL:
			parameter->baseSpecifier = BASE_DECIMAL;
			parameter->type = FORMAT_INT;
			break;

		case SPECIFIER_OCTAL:
			parameter->flags |= FLAGS_UNSIGNED;
			parameter->baseSpecifier = BASE_OCTAL;
			parameter->type = FORMAT_INT;
			break;


		case SPECIFIER_BINARY_UPPER:
			parameter->flags |= FLAGS_UPPER;
			
		case SPECIFIER_BINARY:
			parameter->flags |= FLAGS_NILPADDING;
			parameter->baseSpecifier = BASE_BINARY;
			parameter->type = FORMAT_INT;
			break;


		case SPECIFIER_HEX_UPPER:
			parameter->flags |= FLAGS_UPPER;
			
		case SPECIFIER_HEX:
			parameter->flags |= FLAGS_UNSIGNED;
			parameter->baseSpecifier = BASE_HEX;
			parameter->type = FORMAT_INT;
			break;



		case SPECIFIER_FLOAT_E_UPPER:
			parameter->flags |= FLAGS_UPPER;
			

		case SPECIFIER_FLOAT_E:
			parameter->flags |= FLAGS_FLOAT_E;
			parameter->type = FORMAT_DOUBLE;
			break;




		case SPECIFIER_FLOAT_G_UPPER:
			parameter->flags |= FLAGS_UPPER;
			

		case SPECIFIER_FLOAT_G:
			parameter->flags |= FLAGS_FLOAT_G;
			parameter->type = FORMAT_DOUBLE;
			break;




		case SPECIFIER_FLOAT_F_UPPER:
			parameter->flags |= FLAGS_UPPER;
			

		case SPECIFIER_FLOAT_F:
			parameter->type = FORMAT_DOUBLE;
			break;






		case SPECIFIER_POINTER:
			if (sizeof(trio_pointer_t) == sizeof(trio_ulonglong_t))
				parameter->flags |= FLAGS_QUAD;
			else if (sizeof(trio_pointer_t) == sizeof(long))
				parameter->flags |= FLAGS_LONG;
			parameter->type = FORMAT_POINTER;
			break;




		case SPECIFIER_COUNT:
			parameter->type = FORMAT_COUNT;
			break;


		case SPECIFIER_HEXFLOAT_UPPER:
			parameter->flags |= FLAGS_UPPER;
			
		case SPECIFIER_HEXFLOAT:
			parameter->baseSpecifier = BASE_HEX;
			parameter->type = FORMAT_DOUBLE;
			break;



		case SPECIFIER_ERRNO:
			parameter->type = FORMAT_ERRNO;
			break;



		case SPECIFIER_USER_DEFINED_BEGIN:
		{
			unsigned int max;
			int without_namespace = TRUE;
			char* tmpformat = (char*)&format[offset];
			int ch;

			parameter->type = FORMAT_USER_DEFINED;
			parameter->user_defined.namespace[0] = NIL;

			while ((ch = format[offset]) != NIL)
			{
				offset++;
				if ((ch == SPECIFIER_USER_DEFINED_END) || (ch == SPECIFIER_USER_DEFINED_EXTRA))
				{
					if (without_namespace)
						
						parameter->flags |= FLAGS_USER_DEFINED_PARAMETER;

					
					max = (unsigned int)(&format[offset] - tmpformat);
					if (max > MAX_USER_DATA)
						max = MAX_USER_DATA;
					trio_copy_max(parameter->user_data, max, tmpformat);

					
					while ((ch != NIL) && (ch != SPECIFIER_USER_DEFINED_END))
						ch = format[offset++];

					break; 
				}

				if (ch == SPECIFIER_USER_DEFINED_SEPARATOR)
				{
					without_namespace = FALSE;
					
					max = (int)(&format[offset] - tmpformat);
					if (max > MAX_USER_NAME)
						max = MAX_USER_NAME;
					trio_copy_max(parameter->user_defined.namespace, max, tmpformat);
					tmpformat = (char*)&format[offset];
				}
			}

			if (ch != SPECIFIER_USER_DEFINED_END)
				return TRIO_ERROR_RETURN(TRIO_EINVAL, offset);
		}
		break;


		default:
			
			return TRIO_ERROR_RETURN(TRIO_EINVAL, offset);
	}

	parameter->endOffset = offset;

	return 0;
}



TRIO_PRIVATE int TrioParse TRIO_ARGS6((type, format, parameters, arglist, argfunc, argarray), int type, TRIO_CONST char* format, trio_parameter_t* parameters, va_list arglist, trio_argfunc_t argfunc, trio_pointer_t* argarray)


{
	
	unsigned short usedEntries[MAX_PARAMETERS];
	
	int parameterPosition;
	int maxParam = -1;
	
	int offset;           
	BOOLEAN_T positional; 

	BOOLEAN_T gotSticky = FALSE; 

	
	int indices[MAX_PARAMETERS];
	int pos = 0;
	

	int charlen;

	int save_errno;
	int i = -1;
	int num;
	trio_parameter_t workParameter;
	int status;

	
	assert(((argfunc == NULL) && (argarray == NULL)) || ((argfunc != NULL) && (argarray != NULL)));

	
	memset(usedEntries, 0, sizeof(usedEntries));

	save_errno = errno;
	offset = 0;
	parameterPosition = 0;

	(void)mblen(NULL, 0);


	while (format[offset])
	{
		TrioInitializeParameter(&workParameter);


		if (!isascii(format[offset]))
		{
			
			charlen = mblen(&format[offset], MB_LEN_MAX);
			offset += (charlen > 0) ? charlen : 1;
			continue; 
		}


		switch (format[offset++])
		{

			case CHAR_IDENTIFIER:
			{
				if (CHAR_IDENTIFIER == format[offset])
				{
					
					offset++;
					continue; 
				}

				status = TrioParseQualifiers(type, format, offset, &workParameter);
				if (status < 0)
					return status; 

				status = TrioParseSpecifier(type, format, workParameter.endOffset, &workParameter);
				if (status < 0)
					return status; 
			}
			break;


			case CHAR_ALT_IDENTIFIER:
			{
				status = TrioParseQualifiers(type, format, offset, &workParameter);
				if (status < 0)
					continue; 

				status = TrioParseSpecifier(type, format, workParameter.endOffset, &workParameter);
				if ((status < 0) || (FORMAT_USER_DEFINED != workParameter.type))
					continue; 
			}
			break;


			default:
				continue; 
		}

		
		positional = (NO_POSITION != workParameter.position);

		
		if (workParameter.flags & FLAGS_WIDTH_PARAMETER)
		{
			if (workParameter.width == NO_WIDTH)
			{
				workParameter.width = parameterPosition++;
			}
			else {
				if (!positional)
					workParameter.position = workParameter.width + 1;
			}

			usedEntries[workParameter.width] += 1;
			if (workParameter.width > maxParam)
				maxParam = workParameter.width;
			parameters[pos].type = FORMAT_PARAMETER;
			parameters[pos].flags = 0;
			indices[workParameter.width] = pos;
			workParameter.width = pos++;
		}
		if (workParameter.flags & FLAGS_PRECISION_PARAMETER)
		{
			if (workParameter.precision == NO_PRECISION)
			{
				workParameter.precision = parameterPosition++;
			}
			else {
				if (!positional)
					workParameter.position = workParameter.precision + 1;
			}

			usedEntries[workParameter.precision] += 1;
			if (workParameter.precision > maxParam)
				maxParam = workParameter.precision;
			parameters[pos].type = FORMAT_PARAMETER;
			parameters[pos].flags = 0;
			indices[workParameter.precision] = pos;
			workParameter.precision = pos++;
		}
		if (workParameter.flags & FLAGS_BASE_PARAMETER)
		{
			if (workParameter.base == NO_BASE)
			{
				workParameter.base = parameterPosition++;
			}
			else {
				if (!positional)
					workParameter.position = workParameter.base + 1;
			}

			usedEntries[workParameter.base] += 1;
			if (workParameter.base > maxParam)
				maxParam = workParameter.base;
			parameters[pos].type = FORMAT_PARAMETER;
			parameters[pos].flags = 0;
			indices[workParameter.base] = pos;
			workParameter.base = pos++;
		}

		if (workParameter.flags & FLAGS_VARSIZE_PARAMETER)
		{
			workParameter.varsize = parameterPosition++;

			usedEntries[workParameter.varsize] += 1;
			if (workParameter.varsize > maxParam)
				maxParam = workParameter.varsize;
			parameters[pos].type = FORMAT_PARAMETER;
			parameters[pos].flags = 0;
			indices[workParameter.varsize] = pos;
			workParameter.varsize = pos++;
		}


		if (workParameter.flags & FLAGS_USER_DEFINED_PARAMETER)
		{
			workParameter.user_defined.handler = parameterPosition++;

			usedEntries[workParameter.user_defined.handler] += 1;
			if (workParameter.user_defined.handler > maxParam)
				maxParam = workParameter.user_defined.handler;
			parameters[pos].type = FORMAT_PARAMETER;
			parameters[pos].flags = FLAGS_USER_DEFINED;
			indices[workParameter.user_defined.handler] = pos;
			workParameter.user_defined.handler = pos++;
		}


		if (NO_POSITION == workParameter.position)
		{
			workParameter.position = parameterPosition++;
		}

		if (workParameter.position > maxParam)
			maxParam = workParameter.position;

		if (workParameter.position >= MAX_PARAMETERS)
		{
			
			return TRIO_ERROR_RETURN(TRIO_ETOOMANY, offset);
		}

		indices[workParameter.position] = pos;

		
		usedEntries[workParameter.position] += 1;

		

		if (workParameter.flags & FLAGS_STICKY)
		{
			gotSticky = TRUE;
		}
		else if (gotSticky)
		{
			for (i = pos - 1; i >= 0; i--)
			{
				if (parameters[i].type == FORMAT_PARAMETER)
					continue;
				if ((parameters[i].flags & FLAGS_STICKY) && (parameters[i].type == workParameter.type))
				{
					
					workParameter.flags |= (parameters[i].flags & (unsigned long)~FLAGS_STICKY);
					if (workParameter.width == NO_WIDTH)
						workParameter.width = parameters[i].width;
					if (workParameter.precision == NO_PRECISION)
						workParameter.precision = parameters[i].precision;
					if (workParameter.base == NO_BASE)
						workParameter.base = parameters[i].base;
					break;
				}
			}
		}


		if (workParameter.base == NO_BASE)
			workParameter.base = BASE_DECIMAL;

		offset = workParameter.endOffset;

		TrioCopyParameter(&parameters[pos++], &workParameter);
	} 

	parameters[pos].type = FORMAT_SENTINEL; 
	parameters[pos].beginOffset = offset;

	for (num = 0; num <= maxParam; num++)
	{
		if (usedEntries[num] != 1)
		{
			if (usedEntries[num] == 0) 
				return TRIO_ERROR_RETURN(TRIO_EGAP, num);
			else  return TRIO_ERROR_RETURN(TRIO_EDBLREF, num);
		}

		i = indices[num];

		
		if ((parameters[i].type != FORMAT_PARAMETER) && (parameters[i].flags & FLAGS_IGNORE))
			continue; 

		
		switch (parameters[i].type)
		{
			case FORMAT_GROUP:
			case FORMAT_STRING:

				if (parameters[i].flags & FLAGS_WIDECHAR)
				{
					parameters[i].data.wstring = (argfunc == NULL)
					        ? va_arg(arglist, trio_wchar_t*)
					        : (trio_wchar_t*)(argfunc(argarray, num, TRIO_TYPE_PWCHAR));
				}
				else  {

					parameters[i].data.string = (argfunc == NULL) ? va_arg(arglist, char*)
					                      : (char*)(argfunc(argarray, num, TRIO_TYPE_PCHAR));
				}
				break;


			case FORMAT_USER_DEFINED:

			case FORMAT_POINTER:
			case FORMAT_COUNT:
			case FORMAT_UNKNOWN:
				parameters[i].data.pointer = (argfunc == NULL)
				                                 ? va_arg(arglist, trio_pointer_t)
				                                 : argfunc(argarray, num, TRIO_TYPE_POINTER);
				break;

			case FORMAT_CHAR:
			case FORMAT_INT:

				if (TYPE_SCAN == type)
				{
					if (argfunc == NULL)
						parameters[i].data.pointer = (trio_pointer_t)va_arg(arglist, trio_pointer_t);
					else {
						if (parameters[i].type == FORMAT_CHAR)
							parameters[i].data.pointer = (trio_pointer_t)((char*)argfunc(argarray, num, TRIO_TYPE_CHAR));
						else if (parameters[i].flags & FLAGS_SHORT)
							parameters[i].data.pointer = (trio_pointer_t)((short*)argfunc(argarray, num, TRIO_TYPE_SHORT));
						else parameters[i].data.pointer = (trio_pointer_t)((int*)argfunc(argarray, num, TRIO_TYPE_INT));

					}
				}
				else  {


					if (parameters[i].flags & (FLAGS_VARSIZE_PARAMETER | FLAGS_FIXED_SIZE))
					{
						int varsize;
						if (parameters[i].flags & FLAGS_VARSIZE_PARAMETER)
						{
							
							varsize = (int)parameters[parameters[i].varsize].data.number.as_unsigned;
						}
						else {
							
							varsize = parameters[i].varsize;
						}
						parameters[i].flags &= ~FLAGS_ALL_VARSIZES;

						if (varsize <= (int)sizeof(int))
							;
						else if (varsize <= (int)sizeof(long))
							parameters[i].flags |= FLAGS_LONG;

						else if (varsize <= (int)sizeof(trio_longlong_t))
							parameters[i].flags |= FLAGS_QUAD;
						else parameters[i].flags |= FLAGS_INTMAX_T;

						else parameters[i].flags |= FLAGS_QUAD;

					}


					if (parameters[i].flags & FLAGS_SIZE_T)
						parameters[i].data.number.as_unsigned = (argfunc == NULL)
						        ? (trio_uintmax_t)va_arg(arglist, size_t)
						        : (trio_uintmax_t)( *((size_t*)argfunc(argarray, num, TRIO_TYPE_SIZE)));
					else   if (parameters[i].flags & FLAGS_PTRDIFF_T)


						parameters[i].data.number.as_unsigned = (argfunc == NULL)
						        ? (trio_uintmax_t)va_arg(arglist, ptrdiff_t)
						        : (trio_uintmax_t)( *((ptrdiff_t*)argfunc(argarray, num, TRIO_TYPE_PTRDIFF)));
					else   if (parameters[i].flags & FLAGS_INTMAX_T)


						parameters[i].data.number.as_unsigned = (argfunc == NULL)
						        ? (trio_uintmax_t)va_arg(arglist, trio_intmax_t)
						        : (trio_uintmax_t)( *((trio_intmax_t*)argfunc(argarray, num, TRIO_TYPE_UINTMAX)));
					else  if (parameters[i].flags & FLAGS_QUAD)

						parameters[i].data.number.as_unsigned = (argfunc == NULL) ? (trio_uintmax_t)va_arg(arglist, trio_ulonglong_t)
						                      : (trio_uintmax_t)(*((trio_ulonglong_t*)argfunc( argarray, num, TRIO_TYPE_ULONGLONG)));
					else if (parameters[i].flags & FLAGS_LONG)
						parameters[i].data.number.as_unsigned = (argfunc == NULL) ? (trio_uintmax_t)va_arg(arglist, long)
						                      : (trio_uintmax_t)(*( (long*)argfunc(argarray, num, TRIO_TYPE_LONG)));
					else {
						if (argfunc == NULL)
							parameters[i].data.number.as_unsigned = (trio_uintmax_t)va_arg(arglist, int);
						else {
							if (parameters[i].type == FORMAT_CHAR)
								parameters[i].data.number.as_unsigned = (trio_uintmax_t)( *((char*)argfunc(argarray, num, TRIO_TYPE_CHAR)));
							else if (parameters[i].flags & FLAGS_SHORT)
								parameters[i].data.number.as_unsigned = (trio_uintmax_t)( *((short*)argfunc(argarray, num, TRIO_TYPE_SHORT)));
							else parameters[i].data.number.as_unsigned = (trio_uintmax_t)( *((int*)argfunc(argarray, num, TRIO_TYPE_INT)));

						}
					}
				}
				break;

			case FORMAT_PARAMETER:
				
				if (parameters[i].flags & FLAGS_USER_DEFINED)
					parameters[i].data.pointer = (argfunc == NULL)
					                                 ? va_arg(arglist, trio_pointer_t)
					                                 : argfunc(argarray, num, TRIO_TYPE_POINTER);
				else parameters[i].data.number.as_unsigned = (argfunc == NULL)

					        ? (trio_uintmax_t)va_arg(arglist, int)
					        : (trio_uintmax_t)(*((int*)argfunc(argarray, num, TRIO_TYPE_INT)));
				break;


			case FORMAT_DOUBLE:

				if (TYPE_SCAN == type)
				{
					if (parameters[i].flags & FLAGS_LONGDOUBLE)
						parameters[i].data.longdoublePointer = (argfunc == NULL)
						        ? va_arg(arglist, trio_long_double_t*)
						        : (trio_long_double_t*)argfunc(argarray, num, TRIO_TYPE_LONGDOUBLE);
					else {
						if (parameters[i].flags & FLAGS_LONG)
							parameters[i].data.doublePointer = (argfunc == NULL)
							        ? va_arg(arglist, double*)
							        : (double*)argfunc(argarray, num, TRIO_TYPE_DOUBLE);
						else parameters[i].data.doublePointer = (argfunc == NULL)

							        ? (double*)va_arg(arglist, float*)
							        : (double*)argfunc(argarray, num, TRIO_TYPE_DOUBLE);
					}
				}
				else  {

					if (parameters[i].flags & FLAGS_LONGDOUBLE)
						parameters[i].data.longdoubleNumber = (argfunc == NULL) ? va_arg(arglist, trio_long_double_t)
						                      : (trio_long_double_t)(*((trio_long_double_t*)argfunc( argarray, num, TRIO_TYPE_LONGDOUBLE)));
					else {
						if (argfunc == NULL)
							parameters[i].data.longdoubleNumber = (trio_long_double_t)va_arg(arglist, double);
						else {
							if (parameters[i].flags & FLAGS_SHORT)
								parameters[i].data.longdoubleNumber = (trio_long_double_t)( *((float*)argfunc(argarray, num, TRIO_TYPE_FLOAT)));
							else parameters[i].data.longdoubleNumber = (trio_long_double_t)( *((double*)argfunc(argarray, num, TRIO_TYPE_DOUBLE)));

						}
					}
				}
				break;



			case FORMAT_ERRNO:
				parameters[i].data.errorNumber = save_errno;
				break;


			default:
				break;
		}
	} 
	return num;
}




TRIO_PRIVATE void TrioWriteNumber TRIO_ARGS6((self, number, flags, width, precision, base), trio_class_t* self, trio_uintmax_t number, trio_flags_t flags, int width, int precision, int base)

{
	BOOLEAN_T isNegative;
	BOOLEAN_T isNumberZero;
	BOOLEAN_T isPrecisionZero;
	BOOLEAN_T ignoreNumber;
	char buffer[MAX_CHARS_IN(trio_uintmax_t) * (1 + MAX_LOCALE_SEPARATOR_LENGTH) + 1];
	char* bufferend;
	char* pointer;
	TRIO_CONST char* digits;
	int i;

	int length;
	char* p;

	int count;
	int digitOffset;

	assert(VALID(self));
	assert(VALID(self->OutStream));
	assert(((base >= MIN_BASE) && (base <= MAX_BASE)) || (base == NO_BASE));

	digits = (flags & FLAGS_UPPER) ? internalDigitsUpper : internalDigitsLower;
	if (base == NO_BASE)
		base = BASE_DECIMAL;

	isNumberZero = (number == 0);
	isPrecisionZero = (precision == 0);
	ignoreNumber = (isNumberZero && isPrecisionZero && !((flags & FLAGS_ALTERNATIVE) && (base == BASE_OCTAL)));

	if (flags & FLAGS_UNSIGNED)
	{
		isNegative = FALSE;
		flags &= ~FLAGS_SHOWSIGN;
	}
	else {
		isNegative = ((trio_intmax_t)number < 0);
		if (isNegative)
			number = -((trio_intmax_t)number);
	}

	if (flags & FLAGS_QUAD)
		number &= (trio_ulonglong_t)-1;
	else if (flags & FLAGS_LONG)
		number &= (unsigned long)-1;
	else number &= (unsigned int)-1;

	
	pointer = bufferend = &buffer[sizeof(buffer) - 1];
	*pointer-- = NIL;
	for (i = 1; i < (int)sizeof(buffer); i++)
	{
		digitOffset = number % base;
		*pointer-- = digits[digitOffset];
		number /= base;
		if (number == 0)
			break;


		if ((flags & FLAGS_QUOTE) && TrioFollowedBySeparator(i + 1))
		{
			
			length = internalThousandSeparatorLength;
			if (((int)(pointer - buffer) - length) > 0)
			{
				p = &internalThousandSeparator[length - 1];
				while (length-- > 0)
					*pointer-- = *p--;
			}
		}

	}

	if (!ignoreNumber)
	{
		
		width -= (bufferend - pointer) - 1;
	}

	
	if (NO_PRECISION != precision)
	{
		precision -= (bufferend - pointer) - 1;
		if (precision < 0)
			precision = 0;
		flags |= FLAGS_NILPADDING;
	}

	
	count = (!((flags & FLAGS_LEFTADJUST) || (precision == NO_PRECISION))) ? precision : 0;

	
	if (isNegative || (flags & FLAGS_SHOWSIGN) || (flags & FLAGS_SPACE))
		width--;
	if ((flags & FLAGS_ALTERNATIVE) && !isNumberZero)
	{
		switch (base)
		{
			case BASE_BINARY:
			case BASE_HEX:
				width -= 2;
				break;
			case BASE_OCTAL:
				if (!(flags & FLAGS_NILPADDING) || (count == 0))
					width--;
				break;
			default:
				break;
		}
	}

	
	if (!((flags & FLAGS_LEFTADJUST) || ((flags & FLAGS_NILPADDING) && (precision == NO_PRECISION))))
	{
		while (width-- > count)
			self->OutStream(self, CHAR_ADJUST);
	}

	
	if (isNegative)
		self->OutStream(self, '-');
	else if (flags & FLAGS_SHOWSIGN)
		self->OutStream(self, '+');
	else if (flags & FLAGS_SPACE)
		self->OutStream(self, ' ');

	
	if ((flags & FLAGS_ALTERNATIVE) && !isNumberZero)
	{
		switch (base)
		{
			case BASE_BINARY:
				self->OutStream(self, '0');
				self->OutStream(self, (flags & FLAGS_UPPER) ? 'B' : 'b');
				break;

			case BASE_OCTAL:
				if (!(flags & FLAGS_NILPADDING) || (count == 0))
					self->OutStream(self, '0');
				break;

			case BASE_HEX:
				self->OutStream(self, '0');
				self->OutStream(self, (flags & FLAGS_UPPER) ? 'X' : 'x');
				break;

			default:
				break;
		} 
	}

	
	if (flags & FLAGS_NILPADDING)
	{
		if (precision == NO_PRECISION)
			precision = width;
		while (precision-- > 0)
		{
			self->OutStream(self, '0');
			width--;
		}
	}

	if (!ignoreNumber)
	{
		
		while (*(++pointer))
		{
			self->OutStream(self, *pointer);
		}
	}

	
	if (flags & FLAGS_LEFTADJUST)
	{
		while (width-- > 0)
			self->OutStream(self, CHAR_ADJUST);
	}
}


TRIO_PRIVATE void TrioWriteStringCharacter TRIO_ARGS3((self, ch, flags), trio_class_t* self, int ch, trio_flags_t flags)
{
	if (flags & FLAGS_ALTERNATIVE)
	{
		if (!isprint(ch))
		{
			
			self->OutStream(self, CHAR_BACKSLASH);
			switch (ch)
			{
				case '\007':
					self->OutStream(self, 'a');
					break;
				case '\b':
					self->OutStream(self, 'b');
					break;
				case '\f':
					self->OutStream(self, 'f');
					break;
				case '\n':
					self->OutStream(self, 'n');
					break;
				case '\r':
					self->OutStream(self, 'r');
					break;
				case '\t':
					self->OutStream(self, 't');
					break;
				case '\v':
					self->OutStream(self, 'v');
					break;
				case '\\':
					self->OutStream(self, '\\');
					break;
				default:
					self->OutStream(self, 'x');
					TrioWriteNumber(self, (trio_uintmax_t)ch, FLAGS_UNSIGNED | FLAGS_NILPADDING, 2, 2, BASE_HEX);
					break;
			}
		}
		else if (ch == CHAR_BACKSLASH)
		{
			self->OutStream(self, CHAR_BACKSLASH);
			self->OutStream(self, CHAR_BACKSLASH);
		}
		else {
			self->OutStream(self, ch);
		}
	}
	else {
		self->OutStream(self, ch);
	}
}


TRIO_PRIVATE void TrioWriteString TRIO_ARGS5((self, string, flags, width, precision), trio_class_t* self, TRIO_CONST char* string, trio_flags_t flags, int width, int precision)

{
	int length;
	int ch;

	assert(VALID(self));
	assert(VALID(self->OutStream));

	if (string == NULL)
	{
		string = internalNullString;
		length = sizeof(internalNullString) - 1;

		
		flags &= (~FLAGS_QUOTE);

		width = 0;
	}
	else {
		if (precision == 0)
		{
			length = trio_length(string);
		}
		else {
			length = trio_length_max(string, precision);
		}
	}
	if ((NO_PRECISION != precision) && (precision < length))
	{
		length = precision;
	}
	width -= length;


	if (flags & FLAGS_QUOTE)
		self->OutStream(self, CHAR_QUOTE);


	if (!(flags & FLAGS_LEFTADJUST))
	{
		while (width-- > 0)
			self->OutStream(self, CHAR_ADJUST);
	}

	while (length-- > 0)
	{
		
		ch = (int)((unsigned char)(*string++));
		TrioWriteStringCharacter(self, ch, flags);
	}

	if (flags & FLAGS_LEFTADJUST)
	{
		while (width-- > 0)
			self->OutStream(self, CHAR_ADJUST);
	}

	if (flags & FLAGS_QUOTE)
		self->OutStream(self, CHAR_QUOTE);

}



TRIO_PRIVATE int TrioWriteWideStringCharacter TRIO_ARGS4((self, wch, flags, width), trio_class_t* self, trio_wchar_t wch, trio_flags_t flags, int width)

{
	int size;
	int i;
	int ch;
	char* string;
	char buffer[MB_LEN_MAX + 1];

	if (width == NO_WIDTH)
		width = sizeof(buffer);

	size = wctomb(buffer, wch);
	if ((size <= 0) || (size > width) || (buffer[0] == NIL))
		return 0;

	string = buffer;
	i = size;
	while ((width >= i) && (width-- > 0) && (i-- > 0))
	{
		
		ch = (int)((unsigned char)(*string++));
		TrioWriteStringCharacter(self, ch, flags);
	}
	return size;
}




TRIO_PRIVATE void TrioWriteWideString TRIO_ARGS5((self, wstring, flags, width, precision), trio_class_t* self, TRIO_CONST trio_wchar_t* wstring, trio_flags_t flags, int width, int precision)


{
	int length;
	int size;

	assert(VALID(self));
	assert(VALID(self->OutStream));


	
	(void)mblen(NULL, 0);


	if (wstring == NULL)
	{
		TrioWriteString(self, NULL, flags, width, precision);
		return;
	}

	if (NO_PRECISION == precision)
	{
		length = INT_MAX;
	}
	else {
		length = precision;
		width -= length;
	}


	if (flags & FLAGS_QUOTE)
		self->OutStream(self, CHAR_QUOTE);


	if (!(flags & FLAGS_LEFTADJUST))
	{
		while (width-- > 0)
			self->OutStream(self, CHAR_ADJUST);
	}

	while (length > 0)
	{
		size = TrioWriteWideStringCharacter(self, *wstring++, flags, length);
		if (size == 0)
			break; 
		length -= size;
	}

	if (flags & FLAGS_LEFTADJUST)
	{
		while (width-- > 0)
			self->OutStream(self, CHAR_ADJUST);
	}

	if (flags & FLAGS_QUOTE)
		self->OutStream(self, CHAR_QUOTE);

}





TRIO_PRIVATE void TrioWriteDouble TRIO_ARGS6((self, number, flags, width, precision, base), trio_class_t* self, trio_long_double_t number, trio_flags_t flags, int width, int precision, int base)

{
	trio_long_double_t integerNumber;
	trio_long_double_t fractionNumber;
	trio_long_double_t workNumber;
	int integerDigits;
	int fractionDigits;
	int exponentDigits;
	int workDigits;
	int baseDigits;
	int integerThreshold;
	int fractionThreshold;
	int expectedWidth;
	int exponent = 0;
	unsigned int uExponent = 0;
	int exponentBase;
	trio_long_double_t dblBase;
	trio_long_double_t dblFractionBase;
	trio_long_double_t integerAdjust;
	trio_long_double_t fractionAdjust;
	trio_long_double_t workFractionNumber;
	trio_long_double_t workFractionAdjust;
	int fractionDigitsInspect;
	BOOLEAN_T isNegative;
	BOOLEAN_T isExponentNegative = FALSE;
	BOOLEAN_T requireTwoDigitExponent;
	BOOLEAN_T isHex;
	TRIO_CONST char* digits;

	char* groupingPointer;

	int i;
	int offset;
	BOOLEAN_T hasOnlyZeroes;
	int leadingFractionZeroes = -1;
	register int trailingZeroes;
	BOOLEAN_T keepTrailingZeroes;
	BOOLEAN_T keepDecimalPoint;
	trio_long_double_t epsilon;
	BOOLEAN_T adjustNumber = FALSE;

	assert(VALID(self));
	assert(VALID(self->OutStream));
	assert(((base >= MIN_BASE) && (base <= MAX_BASE)) || (base == NO_BASE));

	
	switch (trio_fpclassify_and_signbit(number, &isNegative))
	{
		case TRIO_FP_NAN:
			TrioWriteString(self, (flags & FLAGS_UPPER) ? NAN_UPPER : NAN_LOWER, flags, width, precision);
			return;

		case TRIO_FP_INFINITE:
			if (isNegative)
			{
				
				TrioWriteString(self, (flags & FLAGS_UPPER) ? "-" INFINITE_UPPER : "-" INFINITE_LOWER, flags, width, precision);

				return;
			}
			else {
				
				TrioWriteString(self, (flags & FLAGS_UPPER) ? INFINITE_UPPER : INFINITE_LOWER, flags, width, precision);
				return;
			}

		default:
			
			break;
	}

	
	if (flags & FLAGS_LONGDOUBLE)
	{
		baseDigits = (base == 10) ? LDBL_DIG : (int)trio_floor(LDBL_MANT_DIG / TrioLogarithmBase(base));
		epsilon = LDBL_EPSILON;
	}
	else if (flags & FLAGS_SHORT)
	{
		baseDigits = (base == BASE_DECIMAL)
		                 ? FLT_DIG : (int)trio_floor(FLT_MANT_DIG / TrioLogarithmBase(base));
		epsilon = FLT_EPSILON;
	}
	else {
		baseDigits = (base == BASE_DECIMAL)
		                 ? DBL_DIG : (int)trio_floor(DBL_MANT_DIG / TrioLogarithmBase(base));
		epsilon = DBL_EPSILON;
	}

	digits = (flags & FLAGS_UPPER) ? internalDigitsUpper : internalDigitsLower;
	isHex = (base == BASE_HEX);
	if (base == NO_BASE)
		base = BASE_DECIMAL;
	dblBase = (trio_long_double_t)base;
	keepTrailingZeroes = !((flags & FLAGS_ROUNDING) || ((flags & FLAGS_FLOAT_G) && !(flags & FLAGS_ALTERNATIVE)));


	if (flags & FLAGS_ROUNDING)
	{
		precision = baseDigits;
	}


	if (precision == NO_PRECISION)
	{
		if (isHex)
		{
			keepTrailingZeroes = FALSE;
			precision = FLT_MANT_DIG;
		}
		else {
			precision = FLT_DIG;
		}
	}

	if (isNegative)
	{
		number = -number;
	}

	if (isHex)
	{
		flags |= FLAGS_FLOAT_E;
	}

reprocess:

	if (flags & FLAGS_FLOAT_G)
	{
		if (precision == 0)
			precision = 1;

		if ((number < TRIO_SUFFIX_LONG(1.0E-4)) || (number >= TrioPower(base, (trio_long_double_t)precision)))
		{
			
			flags |= FLAGS_FLOAT_E;
		}
		else if (number < 1.0)
		{
			
			workNumber = TrioLogarithm(number, base);
			workNumber = TRIO_FABS(workNumber);
			if (workNumber - trio_floor(workNumber) < epsilon)
				workNumber--;
			leadingFractionZeroes = (int)trio_floor(workNumber);
		}
	}

	if (flags & FLAGS_FLOAT_E)
	{
		
		workNumber = TrioLogarithm(number, base);
		if (trio_isinf(workNumber) == -1)
		{
			exponent = 0;
			
			if (flags & FLAGS_FLOAT_G)
				flags &= ~FLAGS_FLOAT_E;
		}
		else {
			exponent = (int)trio_floor(workNumber);
			workNumber = number;
			
			workNumber *= TrioPower(dblBase, (trio_long_double_t)-exponent);
			if (trio_isinf(workNumber))
			{
				
				workNumber /= TrioPower(dblBase, (trio_long_double_t)(exponent / 2));
				workNumber /= TrioPower(dblBase, (trio_long_double_t)(exponent - (exponent / 2)));
			}
			number = workNumber;
			isExponentNegative = (exponent < 0);
			uExponent = (isExponentNegative) ? -exponent : exponent;
			if (isHex)
				uExponent *= 4; 

			
			flags &= ~FLAGS_QUOTE;

		}
	}

	integerNumber = trio_floor(number);
	fractionNumber = number - integerNumber;

	
	integerDigits = 1;
	if (integerNumber > epsilon)
	{
		integerDigits += (int)TrioLogarithm(integerNumber, base);
	}

	fractionDigits = precision;
	if (flags & FLAGS_FLOAT_G)
	{
		if (leadingFractionZeroes > 0)
		{
			fractionDigits += leadingFractionZeroes;
		}
		if ((integerNumber > epsilon) || (number <= epsilon))
		{
			fractionDigits -= integerDigits;
		}
	}

	dblFractionBase = TrioPower(base, fractionDigits);

	if (integerNumber < 1.0)
	{
		workNumber = number * dblFractionBase + TRIO_SUFFIX_LONG(0.5);
		if (trio_floor(number * dblFractionBase) != trio_floor(workNumber))
		{
			adjustNumber = TRUE;
			
			if ((int)TrioLogarithm(number * dblFractionBase, base) != (int)TrioLogarithm(workNumber, base))
			{
				--leadingFractionZeroes;
			}
		}
		workNumber /= dblFractionBase;
	}
	else {
		workNumber = number + TRIO_SUFFIX_LONG(0.5) / dblFractionBase;
		adjustNumber = (trio_floor(number) != trio_floor(workNumber));
	}
	if (adjustNumber)
	{
		if ((flags & FLAGS_FLOAT_G) && !(flags & FLAGS_FLOAT_E))
		{
			
			if ((workNumber < TRIO_SUFFIX_LONG(1.0E-4)) || (workNumber >= TrioPower(base, (trio_long_double_t)precision)))
			{
				
				flags |= FLAGS_FLOAT_E;
				goto reprocess;
			}
		}

		if (flags & FLAGS_FLOAT_E)
		{
			workDigits = 1 + TrioLogarithm(trio_floor(workNumber), base);
			if (integerDigits == workDigits)
			{
				
				number += TRIO_SUFFIX_LONG(0.5) / dblFractionBase;
				integerNumber = trio_floor(number);
				fractionNumber = number - integerNumber;
			}
			else {
				
				exponent++;
				isExponentNegative = (exponent < 0);
				uExponent = (isExponentNegative) ? -exponent : exponent;
				if (isHex)
					uExponent *= 4; 
				workNumber = (number + TRIO_SUFFIX_LONG(0.5) / dblFractionBase) / dblBase;
				integerNumber = trio_floor(workNumber);
				fractionNumber = workNumber - integerNumber;
			}
		}
		else {
			if (workNumber > 1.0)
			{
				
				integerNumber = trio_floor(workNumber);
				fractionNumber = 0.0;
				integerDigits = (integerNumber > epsilon) ? 1 + (int)TrioLogarithm(integerNumber, base) : 1;
				if (flags & FLAGS_FLOAT_G)
				{
					if (flags & FLAGS_ALTERNATIVE)
					{
						fractionDigits = precision;
						if ((integerNumber > epsilon) || (number <= epsilon))
						{
							fractionDigits -= integerDigits;
						}
					}
					else {
						fractionDigits = 0;
					}
				}
			}
			else {
				integerNumber = trio_floor(workNumber);
				fractionNumber = workNumber - integerNumber;
				if (flags & FLAGS_FLOAT_G)
				{
					if (flags & FLAGS_ALTERNATIVE)
					{
						fractionDigits = precision;
						if (leadingFractionZeroes > 0)
						{
							fractionDigits += leadingFractionZeroes;
						}
						if ((integerNumber > epsilon) || (number <= epsilon))
						{
							fractionDigits -= integerDigits;
						}
					}
				}
			}
		}
	}

	
	integerAdjust = fractionAdjust = TRIO_SUFFIX_LONG(0.5);

	if (flags & FLAGS_ROUNDING)
	{
		if (integerDigits > baseDigits)
		{
			integerThreshold = baseDigits;
			fractionDigits = 0;
			dblFractionBase = 1.0;
			fractionThreshold = 0;
			precision = 0; 
			integerAdjust = TrioPower(base, integerDigits - integerThreshold - 1);
			fractionAdjust = 0.0;
		}
		else {
			integerThreshold = integerDigits;
			fractionThreshold = fractionDigits - integerThreshold;
			fractionAdjust = 1.0;
		}
	}
	else  {

		integerThreshold = INT_MAX;
		fractionThreshold = INT_MAX;
	}

	
	fractionAdjust /= dblFractionBase;
	hasOnlyZeroes = (trio_floor((fractionNumber + fractionAdjust) * dblFractionBase) < epsilon);
	keepDecimalPoint = ((flags & FLAGS_ALTERNATIVE) || !((precision == 0) || (!keepTrailingZeroes && hasOnlyZeroes)));

	expectedWidth = integerDigits + fractionDigits;

	if (!keepTrailingZeroes)
	{
		trailingZeroes = 0;
		workFractionNumber = fractionNumber;
		workFractionAdjust = fractionAdjust;
		fractionDigitsInspect = fractionDigits;

		if (integerDigits > integerThreshold)
		{
			fractionDigitsInspect = 0;
		}
		else if (fractionThreshold <= fractionDigits)
		{
			fractionDigitsInspect = fractionThreshold + 1;
		}

		trailingZeroes = fractionDigits - fractionDigitsInspect;
		for (i = 0; i < fractionDigitsInspect; i++)
		{
			workFractionNumber *= dblBase;
			workFractionAdjust *= dblBase;
			workNumber = trio_floor(workFractionNumber + workFractionAdjust);
			workFractionNumber -= workNumber;
			offset = (int)trio_fmod(workNumber, dblBase);
			if (offset == 0)
			{
				trailingZeroes++;
			}
			else {
				trailingZeroes = 0;
			}
		}
		expectedWidth -= trailingZeroes;
	}

	if (keepDecimalPoint)
	{
		expectedWidth += internalDecimalPointLength;
	}


	if (flags & FLAGS_QUOTE)
	{
		expectedWidth += TrioCalcThousandSeparatorLength(integerDigits);
	}


	if (isNegative || (flags & FLAGS_SHOWSIGN) || (flags & FLAGS_SPACE))
	{
		expectedWidth += sizeof("-") - 1;
	}

	exponentDigits = 0;
	if (flags & FLAGS_FLOAT_E)
	{
		exponentDigits = (uExponent == 0)
		        ? 1 : (int)trio_ceil(TrioLogarithm((double)(uExponent + 1), (isHex) ? 10 : base));
	}
	requireTwoDigitExponent = ((base == BASE_DECIMAL) && (exponentDigits == 1));
	if (exponentDigits > 0)
	{
		expectedWidth += exponentDigits;
		expectedWidth += (requireTwoDigitExponent ? sizeof("E+0") - 1 : sizeof("E+") - 1);
	}

	if (isHex)
	{
		expectedWidth += sizeof("0X") - 1;
	}

	
	if (flags & FLAGS_NILPADDING)
	{
		
		if (isNegative)
			self->OutStream(self, '-');
		else if (flags & FLAGS_SHOWSIGN)
			self->OutStream(self, '+');
		else if (flags & FLAGS_SPACE)
			self->OutStream(self, ' ');
		if (isHex)
		{
			self->OutStream(self, '0');
			self->OutStream(self, (flags & FLAGS_UPPER) ? 'X' : 'x');
		}
		if (!(flags & FLAGS_LEFTADJUST))
		{
			for (i = expectedWidth; i < width; i++)
			{
				self->OutStream(self, '0');
			}
		}
	}
	else {
		
		if (!(flags & FLAGS_LEFTADJUST))
		{
			for (i = expectedWidth; i < width; i++)
			{
				self->OutStream(self, CHAR_ADJUST);
			}
		}
		if (isNegative)
			self->OutStream(self, '-');
		else if (flags & FLAGS_SHOWSIGN)
			self->OutStream(self, '+');
		else if (flags & FLAGS_SPACE)
			self->OutStream(self, ' ');
		if (isHex)
		{
			self->OutStream(self, '0');
			self->OutStream(self, (flags & FLAGS_UPPER) ? 'X' : 'x');
		}
	}

	
	for (i = 0; i < integerDigits; i++)
	{
		workNumber = trio_floor(((integerNumber + integerAdjust) / TrioPower(base, integerDigits - i - 1)));
		if (i > integerThreshold)
		{
			
			self->OutStream(self, digits[0]);
		}
		else {
			self->OutStream(self, digits[(int)trio_fmod(workNumber, dblBase)]);
		}


		if (((flags & (FLAGS_FLOAT_E | FLAGS_QUOTE)) == FLAGS_QUOTE) && TrioFollowedBySeparator(integerDigits - i))
		{
			for (groupingPointer = internalThousandSeparator; *groupingPointer != NIL;
			     groupingPointer++)
			{
				self->OutStream(self, *groupingPointer);
			}
		}

	}

	
	trailingZeroes = 0;

	if (keepDecimalPoint)
	{
		if (internalDecimalPoint)
		{
			self->OutStream(self, internalDecimalPoint);
		}
		else {
			for (i = 0; i < internalDecimalPointLength; i++)
			{
				self->OutStream(self, internalDecimalPointString[i]);
			}
		}
	}

	for (i = 0; i < fractionDigits; i++)
	{
		if ((integerDigits > integerThreshold) || (i > fractionThreshold))
		{
			
			trailingZeroes++;
		}
		else {
			fractionNumber *= dblBase;
			fractionAdjust *= dblBase;
			workNumber = trio_floor(fractionNumber + fractionAdjust);
			if (workNumber > fractionNumber)
			{
				
				fractionNumber = 0.0;
				fractionAdjust = 0.0;
			}
			else {
				fractionNumber -= workNumber;
			}
			offset = (int)trio_fmod(workNumber, dblBase);
			if (offset == 0)
			{
				trailingZeroes++;
			}
			else {
				while (trailingZeroes > 0)
				{
					
					self->OutStream(self, digits[0]);
					trailingZeroes--;
				}
				self->OutStream(self, digits[offset]);
			}
		}
	}

	if (keepTrailingZeroes)
	{
		while (trailingZeroes > 0)
		{
			self->OutStream(self, digits[0]);
			trailingZeroes--;
		}
	}

	
	if (exponentDigits > 0)
	{
		self->OutStream(self, isHex ? ((flags & FLAGS_UPPER) ? 'P' : 'p')
		                            : ((flags & FLAGS_UPPER) ? 'E' : 'e'));
		self->OutStream(self, (isExponentNegative) ? '-' : '+');

		
		if (requireTwoDigitExponent)
			self->OutStream(self, '0');

		if (isHex)
			base = 10;
		exponentBase = (int)TrioPower(base, exponentDigits - 1);
		for (i = 0; i < exponentDigits; i++)
		{
			self->OutStream(self, digits[(uExponent / exponentBase) % base]);
			exponentBase /= base;
		}
	}
	
	if (flags & FLAGS_LEFTADJUST)
	{
		for (i = expectedWidth; i < width; i++)
		{
			self->OutStream(self, CHAR_ADJUST);
		}
	}
}



TRIO_PRIVATE int TrioFormatProcess TRIO_ARGS3((data, format, parameters), trio_class_t* data, TRIO_CONST char* format, trio_parameter_t* parameters)
{
	int i;

	TRIO_CONST char* string;

	trio_pointer_t pointer;
	trio_flags_t flags;
	int width;
	int precision;
	int base;
	int offset;

	offset = 0;
	i = 0;

	for (;;)
	{
		
		while (parameters[i].type == FORMAT_PARAMETER)
			i++;

		
		while (offset < parameters[i].beginOffset)
		{
			if (CHAR_IDENTIFIER == format[offset] && CHAR_IDENTIFIER == format[offset + 1])
			{
				data->OutStream(data, CHAR_IDENTIFIER);
				offset += 2;
			}
			else {
				data->OutStream(data, format[offset++]);
			}
		}

		
		if (parameters[i].type == FORMAT_SENTINEL)
			break;

		
		flags = parameters[i].flags;

		
		width = parameters[i].width;
		if (flags & FLAGS_WIDTH_PARAMETER)
		{
			
			width = (int)parameters[width].data.number.as_signed;
			if (width < 0)
			{
				
				flags |= FLAGS_LEFTADJUST;
				flags &= ~FLAGS_NILPADDING;
				width = -width;
			}
		}

		
		if (flags & FLAGS_PRECISION)
		{
			precision = parameters[i].precision;
			if (flags & FLAGS_PRECISION_PARAMETER)
			{
				
				precision = (int)parameters[precision].data.number.as_signed;
				if (precision < 0)
				{
					
					precision = NO_PRECISION;
				}
			}
		}
		else {
			precision = NO_PRECISION;
		}

		
		if (NO_BASE != parameters[i].baseSpecifier)
		{
			
			base = parameters[i].baseSpecifier;
		}
		else if (flags & FLAGS_BASE_PARAMETER)
		{
			
			base = parameters[i].base;
			base = (int)parameters[base].data.number.as_signed;
		}
		else {
			
			base = parameters[i].base;
		}

		switch (parameters[i].type)
		{
			case FORMAT_CHAR:

				if (flags & FLAGS_QUOTE)
					data->OutStream(data, CHAR_QUOTE);

				if (!(flags & FLAGS_LEFTADJUST))
				{
					while (--width > 0)
						data->OutStream(data, CHAR_ADJUST);
				}

				if (flags & FLAGS_WIDECHAR)
				{
					TrioWriteWideStringCharacter( data, (trio_wchar_t)parameters[i].data.number.as_signed, flags, NO_WIDTH);
				}
				else  {

					TrioWriteStringCharacter(data, (int)parameters[i].data.number.as_signed, flags);
				}

				if (flags & FLAGS_LEFTADJUST)
				{
					while (--width > 0)
						data->OutStream(data, CHAR_ADJUST);
				}

				if (flags & FLAGS_QUOTE)
					data->OutStream(data, CHAR_QUOTE);


				break; 

			case FORMAT_INT:
				TrioWriteNumber(data, parameters[i].data.number.as_unsigned, flags, width, precision, base);

				break; 


			case FORMAT_DOUBLE:
				TrioWriteDouble(data, parameters[i].data.longdoubleNumber, flags, width, precision, base);
				break; 


			case FORMAT_STRING:

				if (flags & FLAGS_WIDECHAR)
				{
					TrioWriteWideString(data, parameters[i].data.wstring, flags, width, precision);
				}
				else  {

					TrioWriteString(data, parameters[i].data.string, flags, width, precision);
				}
				break; 

			case FORMAT_POINTER:
			{
				trio_reference_t reference;

				reference.data = data;
				reference.parameter = &parameters[i];
				trio_print_pointer(&reference, parameters[i].data.pointer);
			}
			break; 

			case FORMAT_COUNT:
				pointer = parameters[i].data.pointer;
				if (NULL != pointer)
				{
					

					if (flags & FLAGS_SIZE_T)
						*(size_t*)pointer = (size_t)data->actually.committed;
					else   if (flags & FLAGS_PTRDIFF_T)


						*(ptrdiff_t*)pointer = (ptrdiff_t)data->actually.committed;
					else   if (flags & FLAGS_INTMAX_T)


						*(trio_intmax_t*)pointer = (trio_intmax_t)data->actually.committed;
					else  if (flags & FLAGS_QUAD)

					{
						*(trio_ulonglong_t*)pointer = (trio_ulonglong_t)data->actually.committed;
					}
					else if (flags & FLAGS_LONG)
					{
						*(long int*)pointer = (long int)data->actually.committed;
					}
					else if (flags & FLAGS_SHORT)
					{
						*(short int*)pointer = (short int)data->actually.committed;
					}
					else {
						*(int*)pointer = (int)data->actually.committed;
					}
				}
				break; 

			case FORMAT_PARAMETER:
				break; 


			case FORMAT_ERRNO:
				string = trio_error(parameters[i].data.errorNumber);
				if (string)
				{
					TrioWriteString(data, string, flags, width, precision);
				}
				else {
					data->OutStream(data, '#');
					TrioWriteNumber(data, (trio_uintmax_t)parameters[i].data.errorNumber, flags, width, precision, BASE_DECIMAL);
				}
				break; 



			case FORMAT_USER_DEFINED:
			{
				trio_reference_t reference;
				trio_userdef_t* def = NULL;

				if (parameters[i].flags & FLAGS_USER_DEFINED_PARAMETER)
				{
					
					if ((i > 0) || (parameters[i - 1].type == FORMAT_PARAMETER))
						def = (trio_userdef_t*)parameters[i - 1].data.pointer;
				}
				else {
					
					def = TrioFindNamespace(parameters[i].user_defined.namespace, NULL);
				}
				if (def)
				{
					reference.data = data;
					reference.parameter = &parameters[i];
					def->callback(&reference);
				}
			}
			break;


			default:
				break;
		} 

		
		offset = parameters[i].endOffset;
		i++;
	}

	return data->processed;
}



TRIO_PRIVATE int TrioFormatRef TRIO_ARGS5((reference, format, arglist, argfunc, argarray), trio_reference_t* reference, TRIO_CONST char* format, va_list arglist, trio_argfunc_t argfunc, trio_pointer_t* argarray)


{
	int status;
	trio_parameter_t parameters[MAX_PARAMETERS];

	status = TrioParse(TYPE_PRINT, format, parameters, arglist, argfunc, argarray);
	if (status < 0)
		return status;

	status = TrioFormatProcess(reference->data, format, parameters);
	if (reference->data->error != 0)
	{
		status = reference->data->error;
	}
	return status;
}



TRIO_PRIVATE int TrioFormat TRIO_ARGS7((destination, destinationSize, OutStream, format, arglist, argfunc, argarray), trio_pointer_t destination, size_t destinationSize, void(*OutStream) TRIO_PROTO((trio_class_t*, int)), TRIO_CONST char* format, va_list arglist, trio_argfunc_t argfunc, trio_pointer_t* argarray)




{
	int status;
	trio_class_t data;
	trio_parameter_t parameters[MAX_PARAMETERS];

	assert(VALID(OutStream));
	assert(VALID(format));

	memset(&data, 0, sizeof(data));
	data.OutStream = OutStream;
	data.location = destination;
	data.max = destinationSize;
	data.error = 0;


	if (NULL == internalLocaleValues)
	{
		TrioSetLocale();
	}


	status = TrioParse(TYPE_PRINT, format, parameters, arglist, argfunc, argarray);
	if (status < 0)
		return status;

	status = TrioFormatProcess(&data, format, parameters);
	if (data.error != 0)
	{
		status = data.error;
	}
	return status;
}



TRIO_PRIVATE void TrioOutStreamFile TRIO_ARGS2((self, output), trio_class_t* self, int output)
{
	FILE* file;

	assert(VALID(self));
	assert(VALID(self->location));

	file = (FILE*)self->location;
	self->processed++;
	if (fputc(output, file) == EOF)
	{
		self->error = TRIO_ERROR_RETURN(TRIO_EOF, 0);
	}
	else {
		self->actually.committed++;
	}
}




TRIO_PRIVATE void TrioOutStreamFileDescriptor TRIO_ARGS2((self, output), trio_class_t* self, int output)
{
	int fd;
	char ch;

	assert(VALID(self));

	fd = *((int*)self->location);
	ch = (char)output;
	self->processed++;
	if (write(fd, &ch, sizeof(char)) == -1)
	{
		self->error = TRIO_ERROR_RETURN(TRIO_ERRNO, 0);
	}
	else {
		self->actually.committed++;
	}
}




TRIO_PRIVATE void TrioOutStreamCustom TRIO_ARGS2((self, output), trio_class_t* self, int output)
{
	int status;
	trio_custom_t* data;

	assert(VALID(self));
	assert(VALID(self->location));

	data = (trio_custom_t*)self->location;
	if (data->stream.out)
	{
		status = (data->stream.out)(data->closure, output);
		if (status >= 0)
		{
			self->actually.committed++;
		}
		else {
			if (self->error == 0)
			{
				self->error = TRIO_ERROR_RETURN(TRIO_ECUSTOM, -status);
			}
		}
	}
	self->processed++;
}



TRIO_PRIVATE void TrioOutStreamString TRIO_ARGS2((self, output), trio_class_t* self, int output)
{
	char** buffer;

	assert(VALID(self));
	assert(VALID(self->location));

	buffer = (char**)self->location;
	**buffer = (char)output;
	(*buffer)++;
	self->processed++;
	self->actually.committed++;
}


TRIO_PRIVATE void TrioOutStreamStringMax TRIO_ARGS2((self, output), trio_class_t* self, int output)
{
	char** buffer;

	assert(VALID(self));
	assert(VALID(self->location));

	buffer = (char**)self->location;

	if (self->processed < self->max)
	{
		**buffer = (char)output;
		(*buffer)++;
		self->actually.committed++;
	}
	self->processed++;
}



TRIO_PRIVATE void TrioOutStreamStringDynamic TRIO_ARGS2((self, output), trio_class_t* self, int output)
{
	assert(VALID(self));
	assert(VALID(self->location));

	if (self->error == 0)
	{
		trio_xstring_append_char((trio_string_t*)self->location, (char)output);
		self->actually.committed++;
	}
	
	self->processed++;
}



static trio_pointer_t TrioArrayGetter(trio_pointer_t context, int index, int type)
{
	
	trio_pointer_t* argarray = (trio_pointer_t*)context;
	return argarray[index];
}









TRIO_PUBLIC int trio_printf TRIO_VARGS2((format, va_alist), TRIO_CONST char* format, TRIO_VA_DECL)
{
	int status;
	va_list args;

	assert(VALID(format));

	TRIO_VA_START(args, format);
	status = TrioFormat(stdout, 0, TrioOutStreamFile, format, args, NULL, NULL);
	TRIO_VA_END(args);
	return status;
}




TRIO_PUBLIC int trio_vprintf TRIO_ARGS2((format, args), TRIO_CONST char* format, va_list args)
{
	assert(VALID(format));

	return TrioFormat(stdout, 0, TrioOutStreamFile, format, args, NULL, NULL);
}




TRIO_PUBLIC int trio_printfv TRIO_ARGS2((format, args), TRIO_CONST char* format, trio_pointer_t* args)
{
	static va_list unused;

	assert(VALID(format));

	return TrioFormat(stdout, 0, TrioOutStreamFile, format, unused, TrioArrayGetter, args);
}






TRIO_PUBLIC int trio_fprintf TRIO_VARGS3((file, format, va_alist), FILE* file, TRIO_CONST char* format, TRIO_VA_DECL)
{
	int status;
	va_list args;

	assert(VALID(file));
	assert(VALID(format));

	TRIO_VA_START(args, format);
	status = TrioFormat(file, 0, TrioOutStreamFile, format, args, NULL, NULL);
	TRIO_VA_END(args);
	return status;
}




TRIO_PUBLIC int trio_vfprintf TRIO_ARGS3((file, format, args), FILE* file, TRIO_CONST char* format, va_list args)
{
	assert(VALID(file));
	assert(VALID(format));

	return TrioFormat(file, 0, TrioOutStreamFile, format, args, NULL, NULL);
}




TRIO_PUBLIC int trio_fprintfv TRIO_ARGS3((file, format, args), FILE* file, TRIO_CONST char* format, trio_pointer_t* args)
{
	static va_list unused;

	assert(VALID(file));
	assert(VALID(format));

	return TrioFormat(file, 0, TrioOutStreamFile, format, unused, TrioArrayGetter, args);
}






TRIO_PUBLIC int trio_dprintf TRIO_VARGS3((fd, format, va_alist), int fd, TRIO_CONST char* format, TRIO_VA_DECL)
{
	int status;
	va_list args;

	assert(VALID(format));

	TRIO_VA_START(args, format);
	status = TrioFormat(&fd, 0, TrioOutStreamFileDescriptor, format, args, NULL, NULL);
	TRIO_VA_END(args);
	return status;
}




TRIO_PUBLIC int trio_vdprintf TRIO_ARGS3((fd, format, args), int fd, TRIO_CONST char* format, va_list args)
{
	assert(VALID(format));

	return TrioFormat(&fd, 0, TrioOutStreamFileDescriptor, format, args, NULL, NULL);
}




TRIO_PUBLIC int trio_dprintfv TRIO_ARGS3((fd, format, args), int fd, TRIO_CONST char* format, trio_pointer_t* args)
{
	static va_list unused;

	assert(VALID(format));

	return TrioFormat(&fd, 0, TrioOutStreamFileDescriptor, format, unused, TrioArrayGetter, args);
}




TRIO_PUBLIC int trio_cprintf TRIO_VARGS4((stream, closure, format, va_alist), trio_outstream_t stream, trio_pointer_t closure, TRIO_CONST char* format, TRIO_VA_DECL)

{
	int status;
	va_list args;
	trio_custom_t data;

	assert(VALID(stream));
	assert(VALID(format));

	TRIO_VA_START(args, format);
	data.stream.out = stream;
	data.closure = closure;
	status = TrioFormat(&data, 0, TrioOutStreamCustom, format, args, NULL, NULL);
	TRIO_VA_END(args);
	return status;
}



TRIO_PUBLIC int trio_vcprintf TRIO_ARGS4((stream, closure, format, args), trio_outstream_t stream, trio_pointer_t closure, TRIO_CONST char* format, va_list args)

{
	trio_custom_t data;

	assert(VALID(stream));
	assert(VALID(format));

	data.stream.out = stream;
	data.closure = closure;
	return TrioFormat(&data, 0, TrioOutStreamCustom, format, args, NULL, NULL);
}



TRIO_PUBLIC int trio_cprintfv TRIO_ARGS4((stream, closure, format, args), trio_outstream_t stream, trio_pointer_t closure, TRIO_CONST char* format, trio_pointer_t* args)

{
	static va_list unused;
	trio_custom_t data;

	assert(VALID(stream));
	assert(VALID(format));

	data.stream.out = stream;
	data.closure = closure;
	return TrioFormat(&data, 0, TrioOutStreamCustom, format, unused, TrioArrayGetter, args);
}



TRIO_PUBLIC int trio_cprintff TRIO_ARGS5((stream, closure, format, argfunc, context), trio_outstream_t stream, trio_pointer_t closure, TRIO_CONST char* format, trio_argfunc_t argfunc, trio_pointer_t context)


{
	static va_list unused;
	trio_custom_t data;

	assert(VALID(stream));
	assert(VALID(format));
	assert(VALID(argfunc));

	data.stream.out = stream;
	data.closure = closure;
	return TrioFormat(&data, 0, TrioOutStreamCustom, format, unused, argfunc, (trio_pointer_t*)context);
}





TRIO_PUBLIC int trio_sprintf TRIO_VARGS3((buffer, format, va_alist), char* buffer, TRIO_CONST char* format, TRIO_VA_DECL)
{
	int status;
	va_list args;

	assert(VALID(buffer));
	assert(VALID(format));

	TRIO_VA_START(args, format);
	status = TrioFormat(&buffer, 0, TrioOutStreamString, format, args, NULL, NULL);
	*buffer = NIL; 
	TRIO_VA_END(args);
	return status;
}


TRIO_PUBLIC int trio_vsprintf TRIO_ARGS3((buffer, format, args), char* buffer, TRIO_CONST char* format, va_list args)
{
	int status;

	assert(VALID(buffer));
	assert(VALID(format));

	status = TrioFormat(&buffer, 0, TrioOutStreamString, format, args, NULL, NULL);
	*buffer = NIL;
	return status;
}


TRIO_PUBLIC int trio_sprintfv TRIO_ARGS3((buffer, format, args), char* buffer, TRIO_CONST char* format, trio_pointer_t* args)
{
	static va_list unused;
	int status;

	assert(VALID(buffer));
	assert(VALID(format));

	status = TrioFormat(&buffer, 0, TrioOutStreamString, format, unused, TrioArrayGetter, args);
	*buffer = NIL;
	return status;
}




TRIO_PUBLIC int trio_snprintf TRIO_VARGS4((buffer, max, format, va_alist), char* buffer, size_t max, TRIO_CONST char* format, TRIO_VA_DECL)
{
	int status;
	va_list args;

	assert(VALID(buffer) || (max == 0));
	assert(VALID(format));

	TRIO_VA_START(args, format);
	status = TrioFormat(&buffer, max > 0 ? max - 1 : 0, TrioOutStreamStringMax, format, args, NULL, NULL);
	if (max > 0)
		*buffer = NIL;
	TRIO_VA_END(args);
	return status;
}


TRIO_PUBLIC int trio_vsnprintf TRIO_ARGS4((buffer, max, format, args), char* buffer, size_t max, TRIO_CONST char* format, va_list args)
{
	int status;

	assert(VALID(buffer) || (max == 0));
	assert(VALID(format));

	status = TrioFormat(&buffer, max > 0 ? max - 1 : 0, TrioOutStreamStringMax, format, args, NULL, NULL);
	if (max > 0)
		*buffer = NIL;
	return status;
}


TRIO_PUBLIC int trio_snprintfv TRIO_ARGS4((buffer, max, format, args), char* buffer, size_t max, TRIO_CONST char* format, trio_pointer_t* args)
{
	static va_list unused;
	int status;

	assert(VALID(buffer) || (max == 0));
	assert(VALID(format));

	status = TrioFormat(&buffer, max > 0 ? max - 1 : 0, TrioOutStreamStringMax, format, unused, TrioArrayGetter, args);
	if (max > 0)
		*buffer = NIL;
	return status;
}



TRIO_PUBLIC int trio_snprintfcat TRIO_VARGS4((buffer, max, format, va_alist), char* buffer, size_t max, TRIO_CONST char* format, TRIO_VA_DECL)
{
	int status;
	va_list args;
	size_t buf_len;

	TRIO_VA_START(args, format);

	assert(VALID(buffer));
	assert(VALID(format));

	buf_len = trio_length(buffer);
	buffer = &buffer[buf_len];

	status = TrioFormat(&buffer, max - 1 - buf_len, TrioOutStreamStringMax, format, args, NULL, NULL);
	TRIO_VA_END(args);
	*buffer = NIL;
	return status;
}



TRIO_PUBLIC int trio_vsnprintfcat TRIO_ARGS4((buffer, max, format, args), char* buffer, size_t max, TRIO_CONST char* format, va_list args)
{
	int status;
	size_t buf_len;

	assert(VALID(buffer));
	assert(VALID(format));

	buf_len = trio_length(buffer);
	buffer = &buffer[buf_len];
	status = TrioFormat(&buffer, max - 1 - buf_len, TrioOutStreamStringMax, format, args, NULL, NULL);
	*buffer = NIL;
	return status;
}





TRIO_PUBLIC char* trio_aprintf TRIO_VARGS2((format, va_alist), TRIO_CONST char* format, TRIO_VA_DECL)
{
	va_list args;
	trio_string_t* info;
	char* result = NULL;

	assert(VALID(format));

	info = trio_xstring_duplicate("");
	if (info)
	{
		TRIO_VA_START(args, format);
		(void)TrioFormat(info, 0, TrioOutStreamStringDynamic, format, args, NULL, NULL);
		TRIO_VA_END(args);

		trio_string_terminate(info);
		result = trio_string_extract(info);
		trio_string_destroy(info);
	}
	return result;
}



TRIO_PUBLIC char* trio_vaprintf TRIO_ARGS2((format, args), TRIO_CONST char* format, va_list args)
{
	trio_string_t* info;
	char* result = NULL;

	assert(VALID(format));

	info = trio_xstring_duplicate("");
	if (info)
	{
		(void)TrioFormat(info, 0, TrioOutStreamStringDynamic, format, args, NULL, NULL);
		trio_string_terminate(info);
		result = trio_string_extract(info);
		trio_string_destroy(info);
	}
	return result;
}




TRIO_PUBLIC int trio_asprintf TRIO_VARGS3((result, format, va_alist), char** result, TRIO_CONST char* format, TRIO_VA_DECL)
{
	va_list args;
	int status;
	trio_string_t* info;

	assert(VALID(format));

	*result = NULL;

	info = trio_xstring_duplicate("");
	if (info == NULL)
	{
		status = TRIO_ERROR_RETURN(TRIO_ENOMEM, 0);
	}
	else {
		TRIO_VA_START(args, format);
		status = TrioFormat(info, 0, TrioOutStreamStringDynamic, format, args, NULL, NULL);
		TRIO_VA_END(args);
		if (status >= 0)
		{
			trio_string_terminate(info);
			*result = trio_string_extract(info);
		}
		trio_string_destroy(info);
	}
	return status;
}




TRIO_PUBLIC int trio_vasprintf TRIO_ARGS3((result, format, args), char** result, TRIO_CONST char* format, va_list args)
{
	int status;
	trio_string_t* info;

	assert(VALID(format));

	*result = NULL;

	info = trio_xstring_duplicate("");
	if (info == NULL)
	{
		status = TRIO_ERROR_RETURN(TRIO_ENOMEM, 0);
	}
	else {
		status = TrioFormat(info, 0, TrioOutStreamStringDynamic, format, args, NULL, NULL);
		if (status >= 0)
		{
			trio_string_terminate(info);
			*result = trio_string_extract(info);
		}
		trio_string_destroy(info);
	}
	return status;
}




TRIO_PUBLIC int trio_asprintfv TRIO_ARGS3((result, format, args), char** result, TRIO_CONST char* format, trio_pointer_t* args)
{
	static va_list unused;
	int status;
	trio_string_t* info;

	assert(VALID(format));

	*result = NULL;

	info = trio_xstring_duplicate("");
	if (info == NULL)
	{
		status = TRIO_ERROR_RETURN(TRIO_ENOMEM, 0);
	}
	else {
		status = TrioFormat(info, 0, TrioOutStreamStringDynamic, format, unused, TrioArrayGetter, args);
		if (status >= 0)
		{
			trio_string_terminate(info);
			*result = trio_string_extract(info);
		}
		trio_string_destroy(info);
	}
	return status;
}




















TRIO_PUBLIC trio_pointer_t trio_register TRIO_ARGS2((callback, name), trio_callback_t callback, TRIO_CONST char* name)
{
	trio_userdef_t* def;
	trio_userdef_t* prev = NULL;

	if (callback == NULL)
		return NULL;

	if (name)
	{
		
		if (name[0] == ':')
		{
			if (trio_equal(name, ":enter"))
			{
				internalEnterCriticalRegion = callback;
			}
			else if (trio_equal(name, ":leave"))
			{
				internalLeaveCriticalRegion = callback;
			}
			return NULL;
		}

		
		if (trio_length(name) >= MAX_USER_NAME)
			return NULL;

		
		def = TrioFindNamespace(name, &prev);
		if (def)
			return NULL;
	}

	def = (trio_userdef_t*)TRIO_MALLOC(sizeof(trio_userdef_t));
	if (def)
	{
		if (internalEnterCriticalRegion)
			(void)internalEnterCriticalRegion(NULL);

		if (name)
		{
			
			if (prev == NULL)
				internalUserDef = def;
			else prev->next = def;
		}
		
		def->callback = callback;
		def->name = (name == NULL) ? NULL : trio_duplicate(name);
		def->next = NULL;

		if (internalLeaveCriticalRegion)
			(void)internalLeaveCriticalRegion(NULL);
	}
	return (trio_pointer_t)def;
}


void trio_unregister TRIO_ARGS1((handle), trio_pointer_t handle)
{
	trio_userdef_t* self = (trio_userdef_t*)handle;
	trio_userdef_t* def;
	trio_userdef_t* prev = NULL;

	assert(VALID(self));

	if (self->name)
	{
		def = TrioFindNamespace(self->name, &prev);
		if (def)
		{
			if (internalEnterCriticalRegion)
				(void)internalEnterCriticalRegion(NULL);

			if (prev == NULL)
				internalUserDef = internalUserDef->next;
			else prev->next = def->next;

			if (internalLeaveCriticalRegion)
				(void)internalLeaveCriticalRegion(NULL);
		}
		trio_destroy(self->name);
	}
	TRIO_FREE(self);
}


TRIO_CONST char* trio_get_format TRIO_ARGS1((ref), trio_pointer_t ref)
{

	assert(((trio_reference_t*)ref)->parameter->type == FORMAT_USER_DEFINED);


	return (((trio_reference_t*)ref)->parameter->user_data);
}


trio_pointer_t trio_get_argument TRIO_ARGS1((ref), trio_pointer_t ref)
{

	assert(((trio_reference_t*)ref)->parameter->type == FORMAT_USER_DEFINED);


	return ((trio_reference_t*)ref)->parameter->data.pointer;
}


int trio_get_width TRIO_ARGS1((ref), trio_pointer_t ref)
{
	return ((trio_reference_t*)ref)->parameter->width;
}

void trio_set_width TRIO_ARGS2((ref, width), trio_pointer_t ref, int width)
{
	((trio_reference_t*)ref)->parameter->width = width;
}


int trio_get_precision TRIO_ARGS1((ref), trio_pointer_t ref)
{
	return (((trio_reference_t*)ref)->parameter->precision);
}

void trio_set_precision TRIO_ARGS2((ref, precision), trio_pointer_t ref, int precision)
{
	((trio_reference_t*)ref)->parameter->precision = precision;
}


int trio_get_base TRIO_ARGS1((ref), trio_pointer_t ref)
{
	return (((trio_reference_t*)ref)->parameter->base);
}

void trio_set_base TRIO_ARGS2((ref, base), trio_pointer_t ref, int base)
{
	((trio_reference_t*)ref)->parameter->base = base;
}


int trio_get_long TRIO_ARGS1((ref), trio_pointer_t ref)
{
	return (((trio_reference_t*)ref)->parameter->flags & FLAGS_LONG) ? TRUE : FALSE;
}

void trio_set_long TRIO_ARGS2((ref, is_long), trio_pointer_t ref, int is_long)
{
	if (is_long)
		((trio_reference_t*)ref)->parameter->flags |= FLAGS_LONG;
	else ((trio_reference_t*)ref)->parameter->flags &= ~FLAGS_LONG;
}


int trio_get_longlong TRIO_ARGS1((ref), trio_pointer_t ref)
{
	return (((trio_reference_t*)ref)->parameter->flags & FLAGS_QUAD) ? TRUE : FALSE;
}

void trio_set_longlong TRIO_ARGS2((ref, is_longlong), trio_pointer_t ref, int is_longlong)
{
	if (is_longlong)
		((trio_reference_t*)ref)->parameter->flags |= FLAGS_QUAD;
	else ((trio_reference_t*)ref)->parameter->flags &= ~FLAGS_QUAD;
}



int trio_get_longdouble TRIO_ARGS1((ref), trio_pointer_t ref)
{
	return (((trio_reference_t*)ref)->parameter->flags & FLAGS_LONGDOUBLE) ? TRUE : FALSE;
}

void trio_set_longdouble TRIO_ARGS2((ref, is_longdouble), trio_pointer_t ref, int is_longdouble)
{
	if (is_longdouble)
		((trio_reference_t*)ref)->parameter->flags |= FLAGS_LONGDOUBLE;
	else ((trio_reference_t*)ref)->parameter->flags &= ~FLAGS_LONGDOUBLE;
}



int trio_get_short TRIO_ARGS1((ref), trio_pointer_t ref)
{
	return (((trio_reference_t*)ref)->parameter->flags & FLAGS_SHORT) ? TRUE : FALSE;
}

void trio_set_short TRIO_ARGS2((ref, is_short), trio_pointer_t ref, int is_short)
{
	if (is_short)
		((trio_reference_t*)ref)->parameter->flags |= FLAGS_SHORT;
	else ((trio_reference_t*)ref)->parameter->flags &= ~FLAGS_SHORT;
}


int trio_get_shortshort TRIO_ARGS1((ref), trio_pointer_t ref)
{
	return (((trio_reference_t*)ref)->parameter->flags & FLAGS_SHORTSHORT) ? TRUE : FALSE;
}

void trio_set_shortshort TRIO_ARGS2((ref, is_shortshort), trio_pointer_t ref, int is_shortshort)
{
	if (is_shortshort)
		((trio_reference_t*)ref)->parameter->flags |= FLAGS_SHORTSHORT;
	else ((trio_reference_t*)ref)->parameter->flags &= ~FLAGS_SHORTSHORT;
}


int trio_get_alternative TRIO_ARGS1((ref), trio_pointer_t ref)
{
	return (((trio_reference_t*)ref)->parameter->flags & FLAGS_ALTERNATIVE) ? TRUE : FALSE;
}

void trio_set_alternative TRIO_ARGS2((ref, is_alternative), trio_pointer_t ref, int is_alternative)
{
	if (is_alternative)
		((trio_reference_t*)ref)->parameter->flags |= FLAGS_ALTERNATIVE;
	else ((trio_reference_t*)ref)->parameter->flags &= ~FLAGS_ALTERNATIVE;
}


int trio_get_alignment TRIO_ARGS1((ref), trio_pointer_t ref)
{
	return (((trio_reference_t*)ref)->parameter->flags & FLAGS_LEFTADJUST) ? TRUE : FALSE;
}

void trio_set_alignment TRIO_ARGS2((ref, is_leftaligned), trio_pointer_t ref, int is_leftaligned)
{
	if (is_leftaligned)
		((trio_reference_t*)ref)->parameter->flags |= FLAGS_LEFTADJUST;
	else ((trio_reference_t*)ref)->parameter->flags &= ~FLAGS_LEFTADJUST;
}


int trio_get_spacing TRIO_ARGS1((ref), trio_pointer_t ref)
{
	return (((trio_reference_t*)ref)->parameter->flags & FLAGS_SPACE) ? TRUE : FALSE;
}

void trio_set_spacing TRIO_ARGS2((ref, is_space), trio_pointer_t ref, int is_space)
{
	if (is_space)
		((trio_reference_t*)ref)->parameter->flags |= FLAGS_SPACE;
	else ((trio_reference_t*)ref)->parameter->flags &= ~FLAGS_SPACE;
}


int trio_get_sign TRIO_ARGS1((ref), trio_pointer_t ref)
{
	return (((trio_reference_t*)ref)->parameter->flags & FLAGS_SHOWSIGN) ? TRUE : FALSE;
}

void trio_set_sign TRIO_ARGS2((ref, is_sign), trio_pointer_t ref, int is_sign)
{
	if (is_sign)
		((trio_reference_t*)ref)->parameter->flags |= FLAGS_SHOWSIGN;
	else ((trio_reference_t*)ref)->parameter->flags &= ~FLAGS_SHOWSIGN;
}


int trio_get_padding TRIO_ARGS1((ref), trio_pointer_t ref)
{
	return (((trio_reference_t*)ref)->parameter->flags & FLAGS_NILPADDING) ? TRUE : FALSE;
}

void trio_set_padding TRIO_ARGS2((ref, is_padding), trio_pointer_t ref, int is_padding)
{
	if (is_padding)
		((trio_reference_t*)ref)->parameter->flags |= FLAGS_NILPADDING;
	else ((trio_reference_t*)ref)->parameter->flags &= ~FLAGS_NILPADDING;
}



int trio_get_quote TRIO_ARGS1((ref), trio_pointer_t ref)
{
	return (((trio_reference_t*)ref)->parameter->flags & FLAGS_QUOTE) ? TRUE : FALSE;
}

void trio_set_quote TRIO_ARGS2((ref, is_quote), trio_pointer_t ref, int is_quote)
{
	if (is_quote)
		((trio_reference_t*)ref)->parameter->flags |= FLAGS_QUOTE;
	else ((trio_reference_t*)ref)->parameter->flags &= ~FLAGS_QUOTE;
}



int trio_get_upper TRIO_ARGS1((ref), trio_pointer_t ref)
{
	return (((trio_reference_t*)ref)->parameter->flags & FLAGS_UPPER) ? TRUE : FALSE;
}

void trio_set_upper TRIO_ARGS2((ref, is_upper), trio_pointer_t ref, int is_upper)
{
	if (is_upper)
		((trio_reference_t*)ref)->parameter->flags |= FLAGS_UPPER;
	else ((trio_reference_t*)ref)->parameter->flags &= ~FLAGS_UPPER;
}



int trio_get_largest TRIO_ARGS1((ref), trio_pointer_t ref)
{
	return (((trio_reference_t*)ref)->parameter->flags & FLAGS_INTMAX_T) ? TRUE : FALSE;
}

void trio_set_largest TRIO_ARGS2((ref, is_largest), trio_pointer_t ref, int is_largest)
{
	if (is_largest)
		((trio_reference_t*)ref)->parameter->flags |= FLAGS_INTMAX_T;
	else ((trio_reference_t*)ref)->parameter->flags &= ~FLAGS_INTMAX_T;
}




int trio_get_ptrdiff TRIO_ARGS1((ref), trio_pointer_t ref)
{
	return (((trio_reference_t*)ref)->parameter->flags & FLAGS_PTRDIFF_T) ? TRUE : FALSE;
}

void trio_set_ptrdiff TRIO_ARGS2((ref, is_ptrdiff), trio_pointer_t ref, int is_ptrdiff)
{
	if (is_ptrdiff)
		((trio_reference_t*)ref)->parameter->flags |= FLAGS_PTRDIFF_T;
	else ((trio_reference_t*)ref)->parameter->flags &= ~FLAGS_PTRDIFF_T;
}




int trio_get_size TRIO_ARGS1((ref), trio_pointer_t ref)
{
	return (((trio_reference_t*)ref)->parameter->flags & FLAGS_SIZE_T) ? TRUE : FALSE;
}

void trio_set_size TRIO_ARGS2((ref, is_size), trio_pointer_t ref, int is_size)
{
	if (is_size)
		((trio_reference_t*)ref)->parameter->flags |= FLAGS_SIZE_T;
	else ((trio_reference_t*)ref)->parameter->flags &= ~FLAGS_SIZE_T;
}



void trio_print_int TRIO_ARGS2((ref, number), trio_pointer_t ref, int number)
{
	trio_reference_t* self = (trio_reference_t*)ref;

	TrioWriteNumber(self->data, (trio_uintmax_t)number, self->parameter->flags, self->parameter->width, self->parameter->precision, self->parameter->base);
}


void trio_print_uint TRIO_ARGS2((ref, number), trio_pointer_t ref, unsigned int number)
{
	trio_reference_t* self = (trio_reference_t*)ref;

	TrioWriteNumber(self->data, (trio_uintmax_t)number, self->parameter->flags | FLAGS_UNSIGNED, self->parameter->width, self->parameter->precision, self->parameter->base);
}



void trio_print_double TRIO_ARGS2((ref, number), trio_pointer_t ref, double number)
{
	trio_reference_t* self = (trio_reference_t*)ref;

	TrioWriteDouble(self->data, number, self->parameter->flags, self->parameter->width, self->parameter->precision, self->parameter->base);
}



void trio_print_string TRIO_ARGS2((ref, string), trio_pointer_t ref, TRIO_CONST char* string)
{
	trio_reference_t* self = (trio_reference_t*)ref;

	TrioWriteString(self->data, string, self->parameter->flags, self->parameter->width, self->parameter->precision);
}


int trio_print_ref TRIO_VARGS3((ref, format, va_alist), trio_pointer_t ref, TRIO_CONST char* format, TRIO_VA_DECL)
{
	int status;
	va_list arglist;

	assert(VALID(format));

	TRIO_VA_START(arglist, format);
	status = TrioFormatRef((trio_reference_t*)ref, format, arglist, NULL, NULL);
	TRIO_VA_END(arglist);
	return status;
}


int trio_vprint_ref TRIO_ARGS3((ref, format, arglist), trio_pointer_t ref, TRIO_CONST char* format, va_list arglist)
{
	assert(VALID(format));

	return TrioFormatRef((trio_reference_t*)ref, format, arglist, NULL, NULL);
}


int trio_printv_ref TRIO_ARGS3((ref, format, argarray), trio_pointer_t ref, TRIO_CONST char* format, trio_pointer_t* argarray)
{
	static va_list unused;

	assert(VALID(format));

	return TrioFormatRef((trio_reference_t*)ref, format, unused, TrioArrayGetter, argarray);
}




void trio_print_pointer TRIO_ARGS2((ref, pointer), trio_pointer_t ref, trio_pointer_t pointer)
{
	trio_reference_t* self = (trio_reference_t*)ref;
	trio_flags_t flags;
	trio_uintmax_t number;

	if (NULL == pointer)
	{
		TRIO_CONST char* string = internalNullString;
		while (*string)
			self->data->OutStream(self->data, *string++);
	}
	else {
		
		number = (trio_uintmax_t)((char*)pointer - (char*)0);
		
		number &= (trio_uintmax_t)-1;
		flags = self->parameter->flags;
		flags |= (FLAGS_UNSIGNED | FLAGS_ALTERNATIVE | FLAGS_NILPADDING);
		TrioWriteNumber(self->data, number, flags, POINTER_WIDTH, NO_PRECISION, BASE_HEX);
	}
}







TRIO_PUBLIC void trio_locale_set_decimal_point TRIO_ARGS1((decimalPoint), char* decimalPoint)
{

	if (NULL == internalLocaleValues)
	{
		TrioSetLocale();
	}

	internalDecimalPointLength = trio_length(decimalPoint);
	if (internalDecimalPointLength == 1)
	{
		internalDecimalPoint = *decimalPoint;
	}
	else {
		internalDecimalPoint = NIL;
		trio_copy_max(internalDecimalPointString, sizeof(internalDecimalPointString), decimalPoint);
	}
}




TRIO_PUBLIC void trio_locale_set_thousand_separator TRIO_ARGS1((thousandSeparator), char* thousandSeparator)
{

	if (NULL == internalLocaleValues)
	{
		TrioSetLocale();
	}

	trio_copy_max(internalThousandSeparator, sizeof(internalThousandSeparator), thousandSeparator);
	internalThousandSeparatorLength = trio_length(internalThousandSeparator);
}




TRIO_PUBLIC void trio_locale_set_grouping TRIO_ARGS1((grouping), char* grouping)
{

	if (NULL == internalLocaleValues)
	{
		TrioSetLocale();
	}

	trio_copy_max(internalGrouping, sizeof(internalGrouping), grouping);
}







TRIO_PRIVATE int TrioSkipWhitespaces TRIO_ARGS1((self), trio_class_t* self)
{
	int ch;

	ch = self->current;
	while (isspace(ch))
	{
		self->InStream(self, &ch);
	}
	return ch;
}



TRIO_PRIVATE void TrioGetCollation(TRIO_NOARGS)
{
	int i;
	int j;
	int k;
	char first[2];
	char second[2];

	
	first[1] = NIL;
	second[1] = NIL;
	for (i = 0; i < MAX_CHARACTER_CLASS; i++)
	{
		k = 0;
		first[0] = (char)i;
		for (j = 0; j < MAX_CHARACTER_CLASS; j++)
		{
			second[0] = (char)j;
			if (trio_equal_locale(first, second))
				internalCollationArray[i][k++] = (char)j;
		}
		internalCollationArray[i][k] = NIL;
	}
}



TRIO_PRIVATE int TrioGetCharacterClass TRIO_ARGS4((format, offsetPointer, flagsPointer, characterclass), TRIO_CONST char* format, int* offsetPointer, trio_flags_t* flagsPointer, int* characterclass)


{
	int offset = *offsetPointer;
	int i;
	char ch;
	char range_begin;
	char range_end;

	*flagsPointer &= ~FLAGS_EXCLUDE;

	if (format[offset] == QUALIFIER_CIRCUMFLEX)
	{
		*flagsPointer |= FLAGS_EXCLUDE;
		offset++;
	}
	
	if (format[offset] == SPECIFIER_UNGROUP)
	{
		characterclass[(int)SPECIFIER_UNGROUP]++;
		offset++;
	}
	
	if (format[offset] == QUALIFIER_MINUS)
	{
		characterclass[(int)QUALIFIER_MINUS]++;
		offset++;
	}
	
	for (ch = format[offset]; (ch != SPECIFIER_UNGROUP) && (ch != NIL); ch = format[++offset])
	{
		switch (ch)
		{
			case QUALIFIER_MINUS: 

				
				range_begin = format[offset - 1];
				range_end = format[++offset];
				if (range_end == SPECIFIER_UNGROUP)
				{
					
					characterclass[(int)ch]++;
					ch = range_end;
					break; 
				}
				if (range_end == NIL)
					return TRIO_ERROR_RETURN(TRIO_EINVAL, offset);
				if (range_begin > range_end)
					return TRIO_ERROR_RETURN(TRIO_ERANGE, offset);

				for (i = (int)range_begin; i <= (int)range_end; i++)
					characterclass[i]++;

				ch = range_end;
				break;



			case SPECIFIER_GROUP:

				switch (format[offset + 1])
				{
					case QUALIFIER_DOT: 
						
						for (i = offset + 2;; i++)
						{
							if (format[i] == NIL)
								
								return -1;
							else if (format[i] == QUALIFIER_DOT)
								break; 
						}
						if (format[++i] != SPECIFIER_UNGROUP)
							return -1;

						offset = i;
						break;

					case QUALIFIER_EQUAL: 
					{
						unsigned int j;
						unsigned int k;

						if (internalCollationUnconverted)
						{
							
							TrioGetCollation();
							internalCollationUnconverted = FALSE;
						}
						for (i = offset + 2;; i++)
						{
							if (format[i] == NIL)
								
								return -1;
							else if (format[i] == QUALIFIER_EQUAL)
								break; 
							else {
								
								k = (unsigned int)format[i];
								for (j = 0; internalCollationArray[k][j] != NIL; j++)
									characterclass[(int)internalCollationArray[k][j]]++;
							}
						}
						if (format[++i] != SPECIFIER_UNGROUP)
							return -1;

						offset = i;
					}
					break;

					case QUALIFIER_COLON: 

						if (trio_equal_max(CLASS_ALNUM, sizeof(CLASS_ALNUM) - 1, &format[offset]))
						{
							for (i = 0; i < MAX_CHARACTER_CLASS; i++)
								if (isalnum(i))
									characterclass[i]++;
							offset += sizeof(CLASS_ALNUM) - 1;
						}
						else if (trio_equal_max(CLASS_ALPHA, sizeof(CLASS_ALPHA) - 1, &format[offset]))
						{
							for (i = 0; i < MAX_CHARACTER_CLASS; i++)
								if (isalpha(i))
									characterclass[i]++;
							offset += sizeof(CLASS_ALPHA) - 1;
						}
						else if (trio_equal_max(CLASS_CNTRL, sizeof(CLASS_CNTRL) - 1, &format[offset]))
						{
							for (i = 0; i < MAX_CHARACTER_CLASS; i++)
								if (iscntrl(i))
									characterclass[i]++;
							offset += sizeof(CLASS_CNTRL) - 1;
						}
						else if (trio_equal_max(CLASS_DIGIT, sizeof(CLASS_DIGIT) - 1, &format[offset]))
						{
							for (i = 0; i < MAX_CHARACTER_CLASS; i++)
								if (isdigit(i))
									characterclass[i]++;
							offset += sizeof(CLASS_DIGIT) - 1;
						}
						else if (trio_equal_max(CLASS_GRAPH, sizeof(CLASS_GRAPH) - 1, &format[offset]))
						{
							for (i = 0; i < MAX_CHARACTER_CLASS; i++)
								if (isgraph(i))
									characterclass[i]++;
							offset += sizeof(CLASS_GRAPH) - 1;
						}
						else if (trio_equal_max(CLASS_LOWER, sizeof(CLASS_LOWER) - 1, &format[offset]))
						{
							for (i = 0; i < MAX_CHARACTER_CLASS; i++)
								if (islower(i))
									characterclass[i]++;
							offset += sizeof(CLASS_LOWER) - 1;
						}
						else if (trio_equal_max(CLASS_PRINT, sizeof(CLASS_PRINT) - 1, &format[offset]))
						{
							for (i = 0; i < MAX_CHARACTER_CLASS; i++)
								if (isprint(i))
									characterclass[i]++;
							offset += sizeof(CLASS_PRINT) - 1;
						}
						else if (trio_equal_max(CLASS_PUNCT, sizeof(CLASS_PUNCT) - 1, &format[offset]))
						{
							for (i = 0; i < MAX_CHARACTER_CLASS; i++)
								if (ispunct(i))
									characterclass[i]++;
							offset += sizeof(CLASS_PUNCT) - 1;
						}
						else if (trio_equal_max(CLASS_SPACE, sizeof(CLASS_SPACE) - 1, &format[offset]))
						{
							for (i = 0; i < MAX_CHARACTER_CLASS; i++)
								if (isspace(i))
									characterclass[i]++;
							offset += sizeof(CLASS_SPACE) - 1;
						}
						else if (trio_equal_max(CLASS_UPPER, sizeof(CLASS_UPPER) - 1, &format[offset]))
						{
							for (i = 0; i < MAX_CHARACTER_CLASS; i++)
								if (isupper(i))
									characterclass[i]++;
							offset += sizeof(CLASS_UPPER) - 1;
						}
						else if (trio_equal_max(CLASS_XDIGIT, sizeof(CLASS_XDIGIT) - 1, &format[offset]))
						{
							for (i = 0; i < MAX_CHARACTER_CLASS; i++)
								if (isxdigit(i))
									characterclass[i]++;
							offset += sizeof(CLASS_XDIGIT) - 1;
						}
						else {
							characterclass[(int)ch]++;
						}
						break;

					default:
						characterclass[(int)ch]++;
						break;
				}
				break;



			default:
				characterclass[(int)ch]++;
				break;
		}
	}
	return 0;
}


TRIO_PRIVATE BOOLEAN_T TrioReadNumber TRIO_ARGS5((self, target, flags, width, base), trio_class_t* self, trio_uintmax_t* target, trio_flags_t flags, int width, int base)

{
	trio_uintmax_t number = 0;
	int digit;
	int count;
	BOOLEAN_T isNegative = FALSE;
	BOOLEAN_T gotNumber = FALSE;
	int j;

	assert(VALID(self));
	assert(VALID(self->InStream));
	assert((base >= MIN_BASE && base <= MAX_BASE) || (base == NO_BASE));

	if (internalDigitsUnconverted)
	{
		
		memset(internalDigitArray, -1, sizeof(internalDigitArray));
		for (j = 0; j < (int)sizeof(internalDigitsLower) - 1; j++)
		{
			internalDigitArray[(int)internalDigitsLower[j]] = j;
			internalDigitArray[(int)internalDigitsUpper[j]] = j;
		}
		internalDigitsUnconverted = FALSE;
	}

	TrioSkipWhitespaces(self);

	
	if (self->current == '+')
	{
		self->InStream(self, NULL);
	}
	else if (self->current == '-')
	{
		self->InStream(self, NULL);
		isNegative = TRUE;
	}

	count = self->processed;

	if (flags & FLAGS_ALTERNATIVE)
	{
		switch (base)
		{
			case NO_BASE:
			case BASE_OCTAL:
			case BASE_HEX:
			case BASE_BINARY:
				if (self->current == '0')
				{
					self->InStream(self, NULL);
					if (self->current)
					{
						if ((base == BASE_HEX) && (trio_to_upper(self->current) == 'X'))
						{
							self->InStream(self, NULL);
						}
						else if ((base == BASE_BINARY) && (trio_to_upper(self->current) == 'B'))
						{
							self->InStream(self, NULL);
						}
					}
				}
				else return FALSE;
				break;
			default:
				break;
		}
	}

	while (((width == NO_WIDTH) || (self->processed - count < width)) && (!((self->current == EOF) || isspace(self->current))))
	{
		if (isascii(self->current))
		{
			digit = internalDigitArray[self->current];
			
			if ((digit == -1) || (digit >= base))
				break;
		}

		else if (flags & FLAGS_QUOTE)
		{
			
			for (j = 0; internalThousandSeparator[j] && self->current; j++)
			{
				if (internalThousandSeparator[j] != self->current)
					break;

				self->InStream(self, NULL);
			}
			if (internalThousandSeparator[j])
				break; 
			else continue;
		}

		else break;

		number *= base;
		number += digit;
		gotNumber = TRUE; 

		self->InStream(self, NULL);
	}

	
	if (!gotNumber)
		return FALSE;

	if (target)
		*target = (isNegative) ? (trio_uintmax_t)(-((trio_intmax_t)number)) : number;
	return TRUE;
}


TRIO_PRIVATE int TrioReadChar TRIO_ARGS4((self, target, flags, width), trio_class_t* self, char* target, trio_flags_t flags, int width)
{
	int i;
	char ch;
	trio_uintmax_t number;

	assert(VALID(self));
	assert(VALID(self->InStream));

	for (i = 0; (self->current != EOF) && (i < width); i++)
	{
		ch = (char)self->current;
		self->InStream(self, NULL);
		if ((flags & FLAGS_ALTERNATIVE) && (ch == CHAR_BACKSLASH))
		{
			switch (self->current)
			{
				case '\\':
					ch = '\\';
					break;
				case 'a':
					ch = '\007';
					break;
				case 'b':
					ch = '\b';
					break;
				case 'f':
					ch = '\f';
					break;
				case 'n':
					ch = '\n';
					break;
				case 'r':
					ch = '\r';
					break;
				case 't':
					ch = '\t';
					break;
				case 'v':
					ch = '\v';
					break;
				default:
					if (isdigit(self->current))
					{
						
						if (!TrioReadNumber(self, &number, 0, 3, BASE_OCTAL))
							return 0;
						ch = (char)number;
					}
					else if (trio_to_upper(self->current) == 'X')
					{
						
						self->InStream(self, NULL);
						if (!TrioReadNumber(self, &number, 0, 2, BASE_HEX))
							return 0;
						ch = (char)number;
					}
					else {
						ch = (char)self->current;
					}
					break;
			}
		}

		if (target)
			target[i] = ch;
	}
	return i + 1;
}


TRIO_PRIVATE BOOLEAN_T TrioReadString TRIO_ARGS4((self, target, flags, width), trio_class_t* self, char* target, trio_flags_t flags, int width)
{
	int i;

	assert(VALID(self));
	assert(VALID(self->InStream));

	TrioSkipWhitespaces(self);

	
	for (i = 0; ((width == NO_WIDTH) || (i < width)) && (!((self->current == EOF) || isspace(self->current)));
	     i++)
	{
		if (TrioReadChar(self, (target ? &target[i] : 0), flags, 1) == 0)
			break; 
	}
	if (target)
		target[i] = NIL;
	return TRUE;
}



TRIO_PRIVATE int TrioReadWideChar TRIO_ARGS4((self, target, flags, width), trio_class_t* self, trio_wchar_t* target, trio_flags_t flags, int width)
{
	int i;
	int j;
	int size;
	int amount = 0;
	trio_wchar_t wch;
	char buffer[MB_LEN_MAX + 1];

	assert(VALID(self));
	assert(VALID(self->InStream));

	for (i = 0; (self->current != EOF) && (i < width); i++)
	{
		if (isascii(self->current))
		{
			if (TrioReadChar(self, buffer, flags, 1) == 0)
				return 0;
			buffer[1] = NIL;
		}
		else {
			
			j = 0;
			do {
				buffer[j++] = (char)self->current;
				buffer[j] = NIL;
				self->InStream(self, NULL);
			} while ((j < (int)sizeof(buffer)) && (mblen(buffer, (size_t)j) != j));
		}
		if (target)
		{
			size = mbtowc(&wch, buffer, sizeof(buffer));
			if (size > 0)
				target[i] = wch;
		}
		amount += size;
		self->InStream(self, NULL);
	}
	return amount;
}




TRIO_PRIVATE BOOLEAN_T TrioReadWideString TRIO_ARGS4((self, target, flags, width), trio_class_t* self, trio_wchar_t* target, trio_flags_t flags, int width)

{
	int i;
	int size;

	assert(VALID(self));
	assert(VALID(self->InStream));

	TrioSkipWhitespaces(self);


	
	(void)mblen(NULL, 0);


	
	for (i = 0; ((width == NO_WIDTH) || (i < width)) && (!((self->current == EOF) || isspace(self->current)));)
	{
		size = TrioReadWideChar(self, &target[i], flags, 1);
		if (size == 0)
			break; 

		i += size;
	}
	if (target)
		target[i] = WCONST('\0');
	return TRUE;
}



TRIO_PRIVATE BOOLEAN_T TrioReadGroup TRIO_ARGS5((self, target, characterclass, flags, width), trio_class_t* self, char* target, int* characterclass, trio_flags_t flags, int width)

{
	int ch;
	int i;

	assert(VALID(self));
	assert(VALID(self->InStream));

	ch = self->current;
	for (i = 0; ((width == NO_WIDTH) || (i < width)) && (!((ch == EOF) || (((flags & FLAGS_EXCLUDE) != 0) ^ (characterclass[ch] == 0))));
	     i++)
	{
		if (target)
			target[i] = (char)ch;
		self->InStream(self, &ch);
	}

	if (i == 0)
		return FALSE;

	
	if (target)
		target[i] = NIL;
	return TRUE;
}



TRIO_PRIVATE BOOLEAN_T TrioReadDouble TRIO_ARGS4((self, target, flags, width), trio_class_t* self, trio_pointer_t target, trio_flags_t flags, int width)

{
	int ch;
	char doubleString[512];
	int offset = 0;
	int start;

	int j;

	BOOLEAN_T isHex = FALSE;
	trio_long_double_t infinity;

	doubleString[0] = 0;

	if ((width == NO_WIDTH) || (width > (int)sizeof(doubleString) - 1))
		width = sizeof(doubleString) - 1;

	TrioSkipWhitespaces(self);

	
	ch = self->current;
	if ((ch == '+') || (ch == '-'))
	{
		doubleString[offset++] = (char)ch;
		self->InStream(self, &ch);
		width--;
	}

	start = offset;
	switch (ch)
	{
		case 'n':
		case 'N':
			
			if (offset != 0)
				break;
			
		case 'i':
		case 'I':
			
			while (isalpha(ch) && (offset - start < width))
			{
				doubleString[offset++] = (char)ch;
				self->InStream(self, &ch);
			}
			doubleString[offset] = NIL;

			
			if (trio_equal(&doubleString[start], INFINITE_UPPER) || trio_equal(&doubleString[start], LONG_INFINITE_UPPER))
			{
				infinity = ((start == 1) && (doubleString[0] == '-')) ? trio_ninf() : trio_pinf();
				if (!target)
					return FALSE;

				if (flags & FLAGS_LONGDOUBLE)
				{
					*((trio_long_double_t*)target) = infinity;
				}
				else if (flags & FLAGS_LONG)
				{
					*((double*)target) = infinity;
				}
				else {
					*((float*)target) = infinity;
				}
				return TRUE;
			}
			if (trio_equal(doubleString, NAN_UPPER))
			{
				if (!target)
					return FALSE;

				
				if (flags & FLAGS_LONGDOUBLE)
				{
					*((trio_long_double_t*)target) = trio_nan();
				}
				else if (flags & FLAGS_LONG)
				{
					*((double*)target) = trio_nan();
				}
				else {
					*((float*)target) = trio_nan();
				}
				return TRUE;
			}
			return FALSE;

		case '0':
			doubleString[offset++] = (char)ch;
			self->InStream(self, &ch);
			if (trio_to_upper(ch) == 'X')
			{
				isHex = TRUE;
				doubleString[offset++] = (char)ch;
				self->InStream(self, &ch);
			}
			break;

		default:
			break;
	}

	while ((ch != EOF) && (offset - start < width))
	{
		
		if (isHex ? isxdigit(ch) : isdigit(ch))
		{
			doubleString[offset++] = (char)ch;
			self->InStream(self, &ch);
		}

		else if (flags & FLAGS_QUOTE)
		{
			
			for (j = 0; internalThousandSeparator[j] && self->current; j++)
			{
				if (internalThousandSeparator[j] != self->current)
					break;

				self->InStream(self, &ch);
			}
			if (internalThousandSeparator[j])
				break; 
			else continue;
		}

		else break;
	}
	if (ch == '.')
	{
		
		doubleString[offset++] = (char)ch;
		self->InStream(self, &ch);
		while ((isHex ? isxdigit(ch) : isdigit(ch)) && (offset - start < width))
		{
			doubleString[offset++] = (char)ch;
			self->InStream(self, &ch);
		}
	}
	if (isHex ? (trio_to_upper(ch) == 'P') : (trio_to_upper(ch) == 'E'))
	{
		
		doubleString[offset++] = (char)ch;
		self->InStream(self, &ch);
		if ((ch == '+') || (ch == '-'))
		{
			doubleString[offset++] = (char)ch;
			self->InStream(self, &ch);
		}
		while (isdigit(ch) && (offset - start < width))
		{
			doubleString[offset++] = (char)ch;
			self->InStream(self, &ch);
		}
	}

	if ((offset == start) || (*doubleString == NIL))
		return FALSE;

	doubleString[offset] = 0;

	if (flags & FLAGS_LONGDOUBLE)
	{
		if (!target)
			return FALSE;

		*((trio_long_double_t*)target) = trio_to_long_double(doubleString, NULL);
	}
	else if (flags & FLAGS_LONG)
	{
		if (!target)
			return FALSE;

		*((double*)target) = trio_to_double(doubleString, NULL);
	}
	else {
		if (!target)
			return FALSE;

		*((float*)target) = trio_to_float(doubleString, NULL);
	}
	return TRUE;
}



TRIO_PRIVATE BOOLEAN_T TrioReadPointer TRIO_ARGS3((self, target, flags), trio_class_t* self, trio_pointer_t* target, trio_flags_t flags)
{
	trio_uintmax_t number;
	char buffer[sizeof(internalNullString)];

	flags |= (FLAGS_UNSIGNED | FLAGS_ALTERNATIVE | FLAGS_NILPADDING);

	if (TrioReadNumber(self, &number, flags, POINTER_WIDTH, BASE_HEX))
	{
		if (target)
		{

			
			*target = &((char*)0)[number];

			*target = (trio_pointer_t)number;

		}
		return TRUE;
	}
	else if (TrioReadString(self, (flags & FLAGS_IGNORE) ? NULL : buffer, 0, sizeof(internalNullString) - 1))
	{
		if (trio_equal_case(buffer, internalNullString))
		{
			if (target)
				*target = NULL;
			return TRUE;
		}
	}
	return FALSE;
}


TRIO_PRIVATE int TrioScanProcess TRIO_ARGS3((data, format, parameters), trio_class_t* data, TRIO_CONST char* format, trio_parameter_t* parameters)
{
	int status;
	int assignment;
	int ch;
	int offset; 
	int i;      
	trio_flags_t flags;
	int width;
	int base;
	trio_pointer_t pointer;

	
	if (format[0] == NIL)
		return 0;

	status = 0;
	assignment = 0;
	i = 0;
	offset = 0;
	data->InStream(data, &ch);

	for (;;)
	{
		
		while (parameters[i].type == FORMAT_PARAMETER)
		{
			assert(i <= MAX_PARAMETERS);
			i++;
		}

		
		while (offset < parameters[i].beginOffset)
		{
			if ((CHAR_IDENTIFIER == format[offset]) && (CHAR_IDENTIFIER == format[offset + 1]))
			{
				
				if (CHAR_IDENTIFIER == ch)
				{
					data->InStream(data, &ch);
					offset += 2;
					continue; 
				}
				else {
					status = TRIO_ERROR_RETURN(TRIO_EINVAL, offset);
					goto end;
				}
			}
			else  {
				if (isspace((int)format[offset]))
				{
					
					ch = TrioSkipWhitespaces(data);
				}
				else if (ch == format[offset])
				{
					data->InStream(data, &ch);
				}
				else {
					status = assignment;
					goto end;
				}

				offset++;
			}
		}

		if (parameters[i].type == FORMAT_SENTINEL)
			break;

		if ((EOF == ch) && (parameters[i].type != FORMAT_COUNT))
		{
			status = (assignment > 0) ? assignment : EOF;
			goto end;
		}

		flags = parameters[i].flags;

		
		width = parameters[i].width;
		if (flags & FLAGS_WIDTH_PARAMETER)
		{
			
			width = (int)parameters[width].data.number.as_signed;
		}

		
		if (NO_BASE != parameters[i].baseSpecifier)
		{
			
			base = parameters[i].baseSpecifier;
		}
		else if (flags & FLAGS_BASE_PARAMETER)
		{
			
			base = parameters[i].base;
			base = (int)parameters[base].data.number.as_signed;
		}
		else {
			
			base = parameters[i].base;
		}

		switch (parameters[i].type)
		{
			case FORMAT_INT:
			{
				trio_uintmax_t number;

				if (0 == base)
					base = BASE_DECIMAL;

				if (!TrioReadNumber(data, &number, flags, width, base))
				{
					status = assignment;
					goto end;
				}

				if (!(flags & FLAGS_IGNORE))
				{
					assignment++;

					pointer = parameters[i].data.pointer;

					if (flags & FLAGS_SIZE_T)
						*(size_t*)pointer = (size_t)number;
					else   if (flags & FLAGS_PTRDIFF_T)


						*(ptrdiff_t*)pointer = (ptrdiff_t)number;
					else   if (flags & FLAGS_INTMAX_T)


						*(trio_intmax_t*)pointer = (trio_intmax_t)number;
					else  if (flags & FLAGS_QUAD)

						*(trio_ulonglong_t*)pointer = (trio_ulonglong_t)number;
					else if (flags & FLAGS_LONG)
						*(long int*)pointer = (long int)number;
					else if (flags & FLAGS_SHORT)
						*(short int*)pointer = (short int)number;
					else *(int*)pointer = (int)number;
				}
			}
			break; 

			case FORMAT_STRING:

				if (flags & FLAGS_WIDECHAR)
				{
					if (!TrioReadWideString( data, (flags & FLAGS_IGNORE) ? NULL : parameters[i].data.wstring, flags, width))

					{
						status = assignment;
						goto end;
					}
				}
				else  {

					if (!TrioReadString(data, (flags & FLAGS_IGNORE) ? NULL : parameters[i].data.string, flags, width))

					{
						status = assignment;
						goto end;
					}
				}
				if (!(flags & FLAGS_IGNORE))
					assignment++;
				break; 


			case FORMAT_DOUBLE:
			{
				if (flags & FLAGS_IGNORE)
				{
					pointer = NULL;
				}
				else {
					pointer = (flags & FLAGS_LONGDOUBLE)
					              ? (trio_pointer_t)parameters[i].data.longdoublePointer : (trio_pointer_t)parameters[i].data.doublePointer;
				}
				if (!TrioReadDouble(data, pointer, flags, width))
				{
					status = assignment;
					goto end;
				}
				if (!(flags & FLAGS_IGNORE))
				{
					assignment++;
				}
				break; 
			}


			case FORMAT_GROUP:
			{
				int characterclass[MAX_CHARACTER_CLASS + 1];

				
				while (format[offset] != SPECIFIER_GROUP)
				{
					offset++;
				}
				
				offset++;

				memset(characterclass, 0, sizeof(characterclass));
				status = TrioGetCharacterClass(format, &offset, &flags, characterclass);
				if (status < 0)
					goto end;

				if (!TrioReadGroup(data, (flags & FLAGS_IGNORE) ? NULL : parameters[i].data.string, characterclass, flags, parameters[i].width))
				{
					status = assignment;
					goto end;
				}
				if (!(flags & FLAGS_IGNORE))
					assignment++;
			}
			break; 

			case FORMAT_COUNT:
				pointer = parameters[i].data.pointer;
				if (NULL != pointer)
				{
					int count = data->processed;
					if (ch != EOF)
						count--; 

					if (flags & FLAGS_SIZE_T)
						*(size_t*)pointer = (size_t)count;
					else   if (flags & FLAGS_PTRDIFF_T)


						*(ptrdiff_t*)pointer = (ptrdiff_t)count;
					else   if (flags & FLAGS_INTMAX_T)


						*(trio_intmax_t*)pointer = (trio_intmax_t)count;
					else  if (flags & FLAGS_QUAD)

					{
						*(trio_ulonglong_t*)pointer = (trio_ulonglong_t)count;
					}
					else if (flags & FLAGS_LONG)
					{
						*(long int*)pointer = (long int)count;
					}
					else if (flags & FLAGS_SHORT)
					{
						*(short int*)pointer = (short int)count;
					}
					else {
						*(int*)pointer = (int)count;
					}
				}
				break; 

			case FORMAT_CHAR:

				if (flags & FLAGS_WIDECHAR)
				{
					if (TrioReadWideChar(data, (flags & FLAGS_IGNORE) ? NULL : parameters[i].data.wstring, flags, (width == NO_WIDTH) ? 1 : width) == 0)

					{
						status = assignment;
						goto end;
					}
				}
				else  {

					if (TrioReadChar(data, (flags & FLAGS_IGNORE) ? NULL : parameters[i].data.string, flags, (width == NO_WIDTH) ? 1 : width) == 0)

					{
						status = assignment;
						goto end;
					}
				}
				if (!(flags & FLAGS_IGNORE))
					assignment++;
				break; 

			case FORMAT_POINTER:
				if (!TrioReadPointer( data, (flags & FLAGS_IGNORE) ? NULL : (trio_pointer_t*)parameters[i].data.pointer, flags))


				{
					status = assignment;
					goto end;
				}
				if (!(flags & FLAGS_IGNORE))
					assignment++;
				break; 

			case FORMAT_PARAMETER:
				break; 

			default:
				status = TRIO_ERROR_RETURN(TRIO_EINVAL, offset);
				goto end;
		}

		ch = data->current;
		offset = parameters[i].endOffset;
		i++;
	}

	status = assignment;
end:
	if (data->UndoStream)
		data->UndoStream(data);
	return status;
}


TRIO_PRIVATE int TrioScan TRIO_ARGS8( (source, sourceSize, InStream, UndoStream, format, arglist, argfunc, argarray), trio_pointer_t source, size_t sourceSize, void(*InStream) TRIO_PROTO((trio_class_t*, int*)), void(*UndoStream) TRIO_PROTO((trio_class_t*)), TRIO_CONST char* format, va_list arglist, trio_argfunc_t argfunc, trio_pointer_t* argarray)



{
	int status;
	trio_parameter_t parameters[MAX_PARAMETERS];
	trio_class_t data;

	assert(VALID(InStream));
	assert(VALID(format));

	memset(&data, 0, sizeof(data));
	data.InStream = InStream;
	data.UndoStream = UndoStream;
	data.location = (trio_pointer_t)source;
	data.max = sourceSize;
	data.error = 0;


	if (NULL == internalLocaleValues)
	{
		TrioSetLocale();
	}


	status = TrioParse(TYPE_SCAN, format, parameters, arglist, argfunc, argarray);
	if (status < 0)
		return status;

	status = TrioScanProcess(&data, format, parameters);
	if (data.error != 0)
	{
		status = data.error;
	}
	return status;
}



TRIO_PRIVATE void TrioInStreamFile TRIO_ARGS2((self, intPointer), trio_class_t* self, int* intPointer)
{
	FILE* file = (FILE*)self->location;

	assert(VALID(self));
	assert(VALID(file));

	self->actually.cached = 0;

	
	if (self->current == EOF)
	{
		self->error = (ferror(file)) ? TRIO_ERROR_RETURN(TRIO_ERRNO, 0) : TRIO_ERROR_RETURN(TRIO_EOF, 0);
	}
	else {
		self->processed++;
		self->actually.cached++;
	}

	self->current = fgetc(file);

	if (VALID(intPointer))
	{
		*intPointer = self->current;
	}
}




TRIO_PRIVATE void TrioUndoStreamFile TRIO_ARGS1((self), trio_class_t* self)
{
	FILE* file = (FILE*)self->location;

	assert(VALID(self));
	assert(VALID(file));

	if (self->actually.cached > 0)
	{
		assert(self->actually.cached == 1);

		self->current = ungetc(self->current, file);
		self->actually.cached = 0;
	}
}




TRIO_PRIVATE void TrioInStreamFileDescriptor TRIO_ARGS2((self, intPointer), trio_class_t* self, int* intPointer)
{
	int fd = *((int*)self->location);
	int size;
	unsigned char input;

	assert(VALID(self));

	self->actually.cached = 0;

	size = read(fd, &input, sizeof(char));
	if (size == -1)
	{
		self->error = TRIO_ERROR_RETURN(TRIO_ERRNO, 0);
		self->current = EOF;
	}
	else {
		self->current = (size == 0) ? EOF : input;
	}
	if (self->current != EOF)
	{
		self->actually.cached++;
		self->processed++;
	}

	if (VALID(intPointer))
	{
		*intPointer = self->current;
	}
}




TRIO_PRIVATE void TrioInStreamCustom TRIO_ARGS2((self, intPointer), trio_class_t* self, int* intPointer)
{
	trio_custom_t* data;

	assert(VALID(self));
	assert(VALID(self->location));

	self->actually.cached = 0;

	data = (trio_custom_t*)self->location;

	self->current = (data->stream.in == NULL) ? NIL : (data->stream.in)(data->closure);

	if (self->current == NIL)
	{
		self->current = EOF;
	}
	else {
		self->processed++;
		self->actually.cached++;
	}

	if (VALID(intPointer))
	{
		*intPointer = self->current;
	}
}



TRIO_PRIVATE void TrioInStreamString TRIO_ARGS2((self, intPointer), trio_class_t* self, int* intPointer)
{
	unsigned char** buffer;

	assert(VALID(self));
	assert(VALID(self->location));

	self->actually.cached = 0;

	buffer = (unsigned char**)self->location;
	self->current = (*buffer)[0];
	if (self->current == NIL)
	{
		self->current = EOF;
	}
	else {
		(*buffer)++;
		self->processed++;
		self->actually.cached++;
	}

	if (VALID(intPointer))
	{
		*intPointer = self->current;
	}
}












TRIO_PUBLIC int trio_scanf TRIO_VARGS2((format, va_alist), TRIO_CONST char* format, TRIO_VA_DECL)
{
	int status;
	va_list args;

	assert(VALID(format));

	TRIO_VA_START(args, format);
	status = TrioScan((trio_pointer_t)stdin, 0, TrioInStreamFile, TrioUndoStreamFile, format, args, NULL, NULL);
	TRIO_VA_END(args);
	return status;
}




TRIO_PUBLIC int trio_vscanf TRIO_ARGS2((format, args), TRIO_CONST char* format, va_list args)
{
	assert(VALID(format));

	return TrioScan((trio_pointer_t)stdin, 0, TrioInStreamFile, TrioUndoStreamFile, format, args, NULL, NULL);
}




TRIO_PUBLIC int trio_scanfv TRIO_ARGS2((format, args), TRIO_CONST char* format, trio_pointer_t* args)
{
	static va_list unused;

	assert(VALID(format));

	return TrioScan((trio_pointer_t)stdin, 0, TrioInStreamFile, TrioUndoStreamFile, format, unused, TrioArrayGetter, args);
}






TRIO_PUBLIC int trio_fscanf TRIO_VARGS3((file, format, va_alist), FILE* file, TRIO_CONST char* format, TRIO_VA_DECL)
{
	int status;
	va_list args;

	assert(VALID(file));
	assert(VALID(format));

	TRIO_VA_START(args, format);
	status = TrioScan((trio_pointer_t)file, 0, TrioInStreamFile, TrioUndoStreamFile, format, args, NULL, NULL);
	TRIO_VA_END(args);
	return status;
}




TRIO_PUBLIC int trio_vfscanf TRIO_ARGS3((file, format, args), FILE* file, TRIO_CONST char* format, va_list args)
{
	assert(VALID(file));
	assert(VALID(format));

	return TrioScan((trio_pointer_t)file, 0, TrioInStreamFile, TrioUndoStreamFile, format, args, NULL, NULL);
}




TRIO_PUBLIC int trio_fscanfv TRIO_ARGS3((file, format, args), FILE* file, TRIO_CONST char* format, trio_pointer_t* args)
{
	static va_list unused;

	assert(VALID(file));
	assert(VALID(format));

	return TrioScan((trio_pointer_t)file, 0, TrioInStreamFile, TrioUndoStreamFile, format, unused, TrioArrayGetter, args);
}






TRIO_PUBLIC int trio_dscanf TRIO_VARGS3((fd, format, va_alist), int fd, TRIO_CONST char* format, TRIO_VA_DECL)
{
	int status;
	va_list args;

	assert(VALID(format));

	TRIO_VA_START(args, format);
	status = TrioScan((trio_pointer_t)&fd, 0, TrioInStreamFileDescriptor, NULL, format, args, NULL, NULL);
	TRIO_VA_END(args);
	return status;
}




TRIO_PUBLIC int trio_vdscanf TRIO_ARGS3((fd, format, args), int fd, TRIO_CONST char* format, va_list args)
{
	assert(VALID(format));

	return TrioScan((trio_pointer_t)&fd, 0, TrioInStreamFileDescriptor, NULL, format, args, NULL, NULL);
}




TRIO_PUBLIC int trio_dscanfv TRIO_ARGS3((fd, format, args), int fd, TRIO_CONST char* format, trio_pointer_t* args)
{
	static va_list unused;

	assert(VALID(format));

	return TrioScan((trio_pointer_t)&fd, 0, TrioInStreamFileDescriptor, NULL, format, unused, TrioArrayGetter, args);
}




TRIO_PUBLIC int trio_cscanf TRIO_VARGS4((stream, closure, format, va_alist), trio_instream_t stream, trio_pointer_t closure, TRIO_CONST char* format, TRIO_VA_DECL)

{
	int status;
	va_list args;
	trio_custom_t data;

	assert(VALID(stream));
	assert(VALID(format));

	TRIO_VA_START(args, format);
	data.stream.in = stream;
	data.closure = closure;
	status = TrioScan(&data, 0, TrioInStreamCustom, NULL, format, args, NULL, NULL);
	TRIO_VA_END(args);
	return status;
}



TRIO_PUBLIC int trio_vcscanf TRIO_ARGS4((stream, closure, format, args), trio_instream_t stream, trio_pointer_t closure, TRIO_CONST char* format, va_list args)

{
	trio_custom_t data;

	assert(VALID(stream));
	assert(VALID(format));

	data.stream.in = stream;
	data.closure = closure;
	return TrioScan(&data, 0, TrioInStreamCustom, NULL, format, args, NULL, NULL);
}



TRIO_PUBLIC int trio_cscanfv TRIO_ARGS4((stream, closure, format, args), trio_instream_t stream, trio_pointer_t closure, TRIO_CONST char* format, trio_pointer_t* args)

{
	static va_list unused;
	trio_custom_t data;

	assert(VALID(stream));
	assert(VALID(format));

	data.stream.in = stream;
	data.closure = closure;
	return TrioScan(&data, 0, TrioInStreamCustom, NULL, format, unused, TrioArrayGetter, args);
}



TRIO_PUBLIC int trio_cscanff TRIO_ARGS5((stream, closure, format, argfunc, context), trio_instream_t stream, trio_pointer_t closure, TRIO_CONST char* format, trio_argfunc_t argfunc, trio_pointer_t context)


{
	static va_list unused;
	trio_custom_t data;

	assert(VALID(stream));
	assert(VALID(format));
	assert(VALID(argfunc));

	data.stream.in = stream;
	data.closure = closure;
	return TrioScan(&data, 0, TrioInStreamCustom, NULL, format, unused, argfunc, (trio_pointer_t*)context);
}





TRIO_PUBLIC int trio_sscanf TRIO_VARGS3((buffer, format, va_alist), TRIO_CONST char* buffer, TRIO_CONST char* format, TRIO_VA_DECL)
{
	int status;
	va_list args;

	assert(VALID(buffer));
	assert(VALID(format));

	TRIO_VA_START(args, format);
	status = TrioScan((trio_pointer_t)&buffer, 0, TrioInStreamString, NULL, format, args, NULL, NULL);
	TRIO_VA_END(args);
	return status;
}


TRIO_PUBLIC int trio_vsscanf TRIO_ARGS3((buffer, format, args), TRIO_CONST char* buffer, TRIO_CONST char* format, va_list args)
{
	assert(VALID(buffer));
	assert(VALID(format));

	return TrioScan((trio_pointer_t)&buffer, 0, TrioInStreamString, NULL, format, args, NULL, NULL);
}


TRIO_PUBLIC int trio_sscanfv TRIO_ARGS3((buffer, format, args), TRIO_CONST char* buffer, TRIO_CONST char* format, trio_pointer_t* args)
{
	static va_list unused;

	assert(VALID(buffer));
	assert(VALID(format));

	return TrioScan((trio_pointer_t)&buffer, 0, TrioInStreamString, NULL, format, unused, TrioArrayGetter, args);
}






TRIO_PUBLIC TRIO_CONST char* trio_strerror TRIO_ARGS1((errorcode), int errorcode)
{

	
	switch (TRIO_ERROR_CODE(errorcode))
	{
		case TRIO_EOF:
			return "End of file";
		case TRIO_EINVAL:
			return "Invalid argument";
		case TRIO_ETOOMANY:
			return "Too many arguments";
		case TRIO_EDBLREF:
			return "Double reference";
		case TRIO_EGAP:
			return "Reference gap";
		case TRIO_ENOMEM:
			return "Out of memory";
		case TRIO_ERANGE:
			return "Invalid range";
		case TRIO_ECUSTOM:
			return "Custom error";
		default:
			return "Unknown";
	}

	return "Unknown";

}




