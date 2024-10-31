
























































































































struct _trio_string_t {
	char* content;
	size_t length;
	size_t allocated;
};


















TRIO_PRIVATE_STRING char* internal_duplicate_max TRIO_ARGS2((source, size), TRIO_CONST char* source, size_t size)
{
	char* target;

	assert(source);

	
	size++;
	target = trio_create(size);
	if (target)
	{
		trio_copy_max(target, size, source);
	}
	return target;
}






TRIO_PRIVATE_STRING trio_string_t* internal_string_alloc(TRIO_NOARGS)
{
	trio_string_t* self;

	self = (trio_string_t*)TRIO_MALLOC(sizeof(trio_string_t));
	if (self)
	{
		self->content = NULL;
		self->length = 0;
		self->allocated = 0;
	}
	return self;
}






TRIO_PRIVATE_STRING BOOLEAN_T internal_string_grow TRIO_ARGS2((self, delta), trio_string_t* self, size_t delta)
{
	BOOLEAN_T status = FALSE;
	char* new_content;
	size_t new_size;

	new_size = (delta == 0) ? ((self->allocated == 0) ? 1 : self->allocated * 2) : self->allocated + delta;

	new_content = (char*)TRIO_REALLOC(self->content, new_size);
	if (new_content)
	{
		self->content = new_content;
		self->allocated = new_size;
		status = TRUE;
	}
	return status;
}






TRIO_PRIVATE_STRING BOOLEAN_T internal_string_grow_to TRIO_ARGS2((self, length), trio_string_t* self, size_t length)
{
	length++; 
	return (self->allocated < length) ? internal_string_grow(self, length - self->allocated) : TRUE;
}





TRIO_PRIVATE_STRING TRIO_INLINE int internal_to_upper TRIO_ARGS1((source), int source)
{


	return toupper(source);



	
	return ((source >= (int)'a') && (source <= (int)'z')) ? source - 'a' + 'A' : source;


}






TRIO_PUBLIC_STRING char* trio_create TRIO_ARGS1((size), size_t size)
{
	return (char*)TRIO_MALLOC(size);
}






TRIO_PUBLIC_STRING void trio_destroy TRIO_ARGS1((string), char* string)
{
	if (string)
	{
		TRIO_FREE(string);
	}
}






TRIO_PUBLIC_STRING size_t trio_length TRIO_ARGS1((string), TRIO_CONST char* string)
{
	return strlen(string);
}






TRIO_PUBLIC_STRING size_t trio_length_max TRIO_ARGS2((string, max), TRIO_CONST char* string, size_t max)
{
	size_t i;

	for (i = 0; i < max; ++i)
	{
		if (string[i] == 0)
			break;
	}
	return i;
}






TRIO_PUBLIC_STRING int trio_append TRIO_ARGS2((target, source), char* target, TRIO_CONST char* source)
{
	assert(target);
	assert(source);

	return (strcat(target, source) != NULL);
}






TRIO_PUBLIC_STRING int trio_append_max TRIO_ARGS3((target, max, source), char* target, size_t max, TRIO_CONST char* source)
{
	size_t length;

	assert(target);
	assert(source);

	length = trio_length(target);

	if (max > length)
	{
		strncat(target, source, max - length - 1);
	}
	return TRUE;
}






TRIO_PUBLIC_STRING int trio_contains TRIO_ARGS2((string, substring), TRIO_CONST char* string, TRIO_CONST char* substring)
{
	assert(string);
	assert(substring);

	return (0 != strstr(string, substring));
}






TRIO_PUBLIC_STRING int trio_copy TRIO_ARGS2((target, source), char* target, TRIO_CONST char* source)
{
	assert(target);
	assert(source);

	(void)strcpy(target, source);
	return TRUE;
}






TRIO_PUBLIC_STRING int trio_copy_max TRIO_ARGS3((target, max, source), char* target, size_t max, TRIO_CONST char* source)
{
	assert(target);
	assert(source);
	assert(max > 0); 

	(void)strncpy(target, source, max - 1);
	target[max - 1] = (char)0;
	return TRUE;
}






TRIO_PUBLIC_STRING char* trio_duplicate TRIO_ARGS1((source), TRIO_CONST char* source)
{
	return internal_duplicate_max(source, trio_length(source));
}






TRIO_PUBLIC_STRING char* trio_duplicate_max TRIO_ARGS2((source, max), TRIO_CONST char* source, size_t max)
{
	size_t length;

	assert(source);
	assert(max > 0);

	length = trio_length(source);
	if (length > max)
	{
		length = max;
	}
	return internal_duplicate_max(source, length);
}






TRIO_PUBLIC_STRING int trio_equal TRIO_ARGS2((first, second), TRIO_CONST char* first, TRIO_CONST char* second)
{
	assert(first);
	assert(second);

	if ((first != NULL) && (second != NULL))
	{

		return (0 == strcasecmp(first, second));

		while ((*first != NIL) && (*second != NIL))
		{
			if (internal_to_upper(*first) != internal_to_upper(*second))
			{
				break;
			}
			first++;
			second++;
		}
		return ((*first == NIL) && (*second == NIL));

	}
	return FALSE;
}






TRIO_PUBLIC_STRING int trio_equal_case TRIO_ARGS2((first, second), TRIO_CONST char* first, TRIO_CONST char* second)
{
	assert(first);
	assert(second);

	if ((first != NULL) && (second != NULL))
	{
		return (0 == strcmp(first, second));
	}
	return FALSE;
}






TRIO_PUBLIC_STRING int trio_equal_case_max TRIO_ARGS3((first, max, second), TRIO_CONST char* first, size_t max, TRIO_CONST char* second)
{
	assert(first);
	assert(second);

	if ((first != NULL) && (second != NULL))
	{
		return (0 == strncmp(first, second, max));
	}
	return FALSE;
}






TRIO_PUBLIC_STRING int trio_equal_locale TRIO_ARGS2((first, second), TRIO_CONST char* first, TRIO_CONST char* second)
{
	assert(first);
	assert(second);


	return (strcoll(first, second) == 0);

	return trio_equal(first, second);

}






TRIO_PUBLIC_STRING int trio_equal_max TRIO_ARGS3((first, max, second), TRIO_CONST char* first, size_t max, TRIO_CONST char* second)
{
	assert(first);
	assert(second);

	if ((first != NULL) && (second != NULL))
	{

		return (0 == strncasecmp(first, second, max));

		
		size_t cnt = 0;
		while ((*first != NIL) && (*second != NIL) && (cnt <= max))
		{
			if (internal_to_upper(*first) != internal_to_upper(*second))
			{
				break;
			}
			first++;
			second++;
			cnt++;
		}
		return ((cnt == max) || ((*first == NIL) && (*second == NIL)));

	}
	return FALSE;
}






TRIO_PUBLIC_STRING TRIO_CONST char* trio_error TRIO_ARGS1((error_number), int error_number)
{


	return strerror(error_number);




	extern char* sys_errlist[];
	extern int sys_nerr;

	return ((error_number < 0) || (error_number >= sys_nerr)) ? "unknown" : sys_errlist[error_number];



	return "unknown";



}






TRIO_PUBLIC_STRING size_t trio_format_date_max TRIO_ARGS4((target, max, format, datetime), char* target, size_t max, TRIO_CONST char* format, TRIO_CONST struct tm* datetime)


{
	assert(target);
	assert(format);
	assert(datetime);
	assert(max > 0);

	return strftime(target, max, format, datetime);
}






TRIO_PUBLIC_STRING unsigned long trio_hash TRIO_ARGS2((string, type), TRIO_CONST char* string, int type)
{
	unsigned long value = 0L;
	char ch;

	assert(string);

	switch (type)
	{
		case TRIO_HASH_PLAIN:
			while ((ch = *string++) != NIL)
			{
				value *= 31;
				value += (unsigned long)ch;
			}
			break;
		default:
			assert(FALSE);
			break;
	}
	return value;
}






TRIO_PUBLIC_STRING char* trio_index TRIO_ARGS2((string, character), TRIO_CONST char* string, int character)
{
	assert(string);

	return strchr(string, character);
}






TRIO_PUBLIC_STRING char* trio_index_last TRIO_ARGS2((string, character), TRIO_CONST char* string, int character)
{
	assert(string);

	return strchr(string, character);
}






TRIO_PUBLIC_STRING int trio_lower TRIO_ARGS1((target), char* target)
{
	assert(target);

	return trio_span_function(target, target, trio_to_lower);
}






TRIO_PUBLIC_STRING int trio_match TRIO_ARGS2((string, pattern), TRIO_CONST char* string, TRIO_CONST char* pattern)
{
	assert(string);
	assert(pattern);

	for (; ('*' != *pattern); ++pattern, ++string)
	{
		if (NIL == *string)
		{
			return (NIL == *pattern);
		}
		if ((internal_to_upper((int)*string) != internal_to_upper((int)*pattern)) && ('?' != *pattern))
		{
			return FALSE;
		}
	}
	
	while ('*' == pattern[1])
		pattern++;

	do {
		if (trio_match(string, &pattern[1]))
		{
			return TRUE;
		}
	} while (*string++);

	return FALSE;
}






TRIO_PUBLIC_STRING int trio_match_case TRIO_ARGS2((string, pattern), TRIO_CONST char* string, TRIO_CONST char* pattern)
{
	assert(string);
	assert(pattern);

	for (; ('*' != *pattern); ++pattern, ++string)
	{
		if (NIL == *string)
		{
			return (NIL == *pattern);
		}
		if ((*string != *pattern) && ('?' != *pattern))
		{
			return FALSE;
		}
	}
	
	while ('*' == pattern[1])
		pattern++;

	do {
		if (trio_match_case(string, &pattern[1]))
		{
			return TRUE;
		}
	} while (*string++);

	return FALSE;
}






TRIO_PUBLIC_STRING size_t trio_span_function TRIO_ARGS3((target, source, Function), char* target, TRIO_CONST char* source, int(*Function) TRIO_PROTO((int)))

{
	size_t count = 0;

	assert(target);
	assert(source);
	assert(Function);

	while (*source != NIL)
	{
		*target++ = Function(*source++);
		count++;
	}
	return count;
}






TRIO_PUBLIC_STRING char* trio_substring TRIO_ARGS2((string, substring), TRIO_CONST char* string, TRIO_CONST char* substring)
{
	assert(string);
	assert(substring);

	return strstr(string, substring);
}






TRIO_PUBLIC_STRING char* trio_substring_max TRIO_ARGS3((string, max, substring), TRIO_CONST char* string, size_t max, TRIO_CONST char* substring)

{
	size_t count;
	size_t size;
	char* result = NULL;

	assert(string);
	assert(substring);

	size = trio_length(substring);
	if (size <= max)
	{
		for (count = 0; count <= max - size; count++)
		{
			if (trio_equal_max(substring, size, &string[count]))
			{
				result = (char*)&string[count];
				break;
			}
		}
	}
	return result;
}






TRIO_PUBLIC_STRING char* trio_tokenize TRIO_ARGS2((string, delimiters), char* string, TRIO_CONST char* delimiters)
{
	assert(delimiters);

	return strtok(string, delimiters);
}







TRIO_PUBLIC_STRING trio_long_double_t trio_to_long_double TRIO_ARGS2((source, endp), TRIO_CONST char* source, char** endp)

{

	return strtold(source, endp);

	int isNegative = FALSE;
	int isExponentNegative = FALSE;
	trio_long_double_t integer = 0.0;
	trio_long_double_t fraction = 0.0;
	unsigned long exponent = 0;
	trio_long_double_t base;
	trio_long_double_t fracdiv = 1.0;
	trio_long_double_t value = 0.0;

	
	if ((source[0] == '0') && ((source[1] == 'x') || (source[1] == 'X')))
	{
		base = 16.0;
		source += 2;
		while (isxdigit((int)*source))
		{
			integer *= base;
			integer += (isdigit((int)*source) ? (*source - '0')
			                                  : 10 + (internal_to_upper((int)*source) - 'A'));
			source++;
		}
		if (*source == '.')
		{
			source++;
			while (isxdigit((int)*source))
			{
				fracdiv /= base;
				fraction += fracdiv * (isdigit((int)*source)
				                           ? (*source - '0')
				                           : 10 + (internal_to_upper((int)*source) - 'A'));
				source++;
			}
			if ((*source == 'p') || (*source == 'P'))
			{
				source++;
				if ((*source == '+') || (*source == '-'))
				{
					isExponentNegative = (*source == '-');
					source++;
				}
				while (isdigit((int)*source))
				{
					exponent *= 10;
					exponent += (*source - '0');
					source++;
				}
			}
		}
		
		base = 2.0;
	}
	else  {
		base = 10.0;
		isNegative = (*source == '-');
		
		if ((*source == '+') || (*source == '-'))
			source++;

		
		while (isdigit((int)*source))
		{
			integer *= base;
			integer += (*source - '0');
			source++;
		}

		if (*source == '.')
		{
			source++; 
			while (isdigit((int)*source))
			{
				fracdiv /= base;
				fraction += (*source - '0') * fracdiv;
				source++;
			}
		}
		if ((*source == 'e') || (*source == 'E')

		    || (*source == 'd') || (*source == 'D')

		)
		{
			source++; 
			isExponentNegative = (*source == '-');
			if ((*source == '+') || (*source == '-'))
				source++;
			while (isdigit((int)*source))
			{
				exponent *= (int)base;
				exponent += (*source - '0');
				source++;
			}
		}
	}

	value = integer + fraction;
	if (exponent != 0)
	{
		if (isExponentNegative)
			value /= trio_powl(base, (trio_long_double_t)exponent);
		else value *= trio_powl(base, (trio_long_double_t)exponent);
	}
	if (isNegative)
		value = -value;

	if (endp)
		*endp = (char*)source;
	return value;

}






TRIO_PUBLIC_STRING double trio_to_double TRIO_ARGS2((source, endp), TRIO_CONST char* source, char** endp)
{

	return strtod(source, endp);

	return (double)trio_to_long_double(source, endp);

}






TRIO_PUBLIC_STRING float trio_to_float TRIO_ARGS2((source, endp), TRIO_CONST char* source, char** endp)
{

	return strtof(source, endp);

	return (float)trio_to_long_double(source, endp);

}






TRIO_PUBLIC_STRING long trio_to_long TRIO_ARGS3((string, endp, base), TRIO_CONST char* string, char** endp, int base)
{
	assert(string);
	assert((base >= 2) && (base <= 36));

	return strtol(string, endp, base);
}






TRIO_PUBLIC_STRING int trio_to_lower TRIO_ARGS1((source), int source)
{


	return tolower(source);



	
	return ((source >= (int)'A') && (source <= (int)'Z')) ? source - 'A' + 'a' : source;


}






TRIO_PUBLIC_STRING unsigned long trio_to_unsigned_long TRIO_ARGS3((string, endp, base), TRIO_CONST char* string, char** endp, int base)

{
	assert(string);
	assert((base >= 2) && (base <= 36));

	return strtoul(string, endp, base);
}






TRIO_PUBLIC_STRING int trio_to_upper TRIO_ARGS1((source), int source)
{
	return internal_to_upper(source);
}






TRIO_PUBLIC_STRING int trio_upper TRIO_ARGS1((target), char* target)
{
	assert(target);

	return trio_span_function(target, target, internal_to_upper);
}















TRIO_PUBLIC_STRING trio_string_t* trio_string_create TRIO_ARGS1((initial_size), int initial_size)
{
	trio_string_t* self;

	self = internal_string_alloc();
	if (self)
	{
		if (internal_string_grow(self, (size_t)((initial_size > 0) ? initial_size : 1)))
		{
			self->content[0] = (char)0;
			self->allocated = initial_size;
		}
		else {
			trio_string_destroy(self);
			self = NULL;
		}
	}
	return self;
}






TRIO_PUBLIC_STRING void trio_string_destroy TRIO_ARGS1((self), trio_string_t* self)
{
	assert(self);

	if (self)
	{
		trio_destroy(self->content);
		TRIO_FREE(self);
	}
}






TRIO_PUBLIC_STRING char* trio_string_get TRIO_ARGS2((self, offset), trio_string_t* self, int offset)
{
	char* result = NULL;

	assert(self);

	if (self->content != NULL)
	{
		if (self->length == 0)
		{
			(void)trio_string_length(self);
		}
		if (offset >= 0)
		{
			if (offset > (int)self->length)
			{
				offset = self->length;
			}
		}
		else {
			offset += self->length + 1;
			if (offset < 0)
			{
				offset = 0;
			}
		}
		result = &(self->content[offset]);
	}
	return result;
}






TRIO_PUBLIC_STRING char* trio_string_extract TRIO_ARGS1((self), trio_string_t* self)
{
	char* result;

	assert(self);

	result = self->content;
	
	self->content = NULL;
	self->length = self->allocated = 0;
	return result;
}






TRIO_PUBLIC_STRING void trio_xstring_set TRIO_ARGS2((self, buffer), trio_string_t* self, char* buffer)
{
	assert(self);

	trio_destroy(self->content);
	self->content = trio_duplicate(buffer);
}






TRIO_PUBLIC_STRING int trio_string_size TRIO_ARGS1((self), trio_string_t* self)
{
	assert(self);

	return self->allocated;
}






TRIO_PUBLIC_STRING void trio_string_terminate TRIO_ARGS1((self), trio_string_t* self)
{
	trio_xstring_append_char(self, 0);
}






TRIO_PUBLIC_STRING int trio_string_append TRIO_ARGS2((self, other), trio_string_t* self, trio_string_t* other)
{
	size_t length;

	assert(self);
	assert(other);

	length = self->length + other->length;
	if (!internal_string_grow_to(self, length))
		goto error;
	trio_copy(&self->content[self->length], other->content);
	self->length = length;
	return TRUE;

error:
	return FALSE;
}






TRIO_PUBLIC_STRING int trio_xstring_append TRIO_ARGS2((self, other), trio_string_t* self, TRIO_CONST char* other)
{
	size_t length;

	assert(self);
	assert(other);

	length = self->length + trio_length(other);
	if (!internal_string_grow_to(self, length))
		goto error;
	trio_copy(&self->content[self->length], other);
	self->length = length;
	return TRUE;

error:
	return FALSE;
}






TRIO_PUBLIC_STRING int trio_xstring_append_char TRIO_ARGS2((self, character), trio_string_t* self, char character)
{
	assert(self);

	if ((int)self->length >= trio_string_size(self))
	{
		if (!internal_string_grow(self, 0))
			goto error;
	}
	self->content[self->length] = character;
	self->length++;
	return TRUE;

error:
	return FALSE;
}






TRIO_PUBLIC_STRING int trio_xstring_append_max TRIO_ARGS3((self, other, max), trio_string_t* self, TRIO_CONST char* other, size_t max)
{
	size_t length;

	assert(self);
	assert(other);

	length = self->length + trio_length_max(other, max);
	if (!internal_string_grow_to(self, length))
		goto error;

	
	trio_copy_max(&self->content[self->length], max + 1, other);
	self->length = length;
	return TRUE;

error:
	return FALSE;
}






TRIO_PUBLIC_STRING int trio_string_contains TRIO_ARGS2((self, other), trio_string_t* self, trio_string_t* other)
{
	assert(self);
	assert(other);

	return trio_contains(self->content, other->content);
}






TRIO_PUBLIC_STRING int trio_xstring_contains TRIO_ARGS2((self, other), trio_string_t* self, TRIO_CONST char* other)
{
	assert(self);
	assert(other);

	return trio_contains(self->content, other);
}






TRIO_PUBLIC_STRING int trio_string_copy TRIO_ARGS2((self, other), trio_string_t* self, trio_string_t* other)
{
	assert(self);
	assert(other);

	self->length = 0;
	return trio_string_append(self, other);
}






TRIO_PUBLIC_STRING int trio_xstring_copy TRIO_ARGS2((self, other), trio_string_t* self, TRIO_CONST char* other)
{
	assert(self);
	assert(other);

	self->length = 0;
	return trio_xstring_append(self, other);
}






TRIO_PUBLIC_STRING trio_string_t* trio_string_duplicate TRIO_ARGS1((other), trio_string_t* other)
{
	trio_string_t* self;

	assert(other);

	self = internal_string_alloc();
	if (self)
	{
		self->content = internal_duplicate_max(other->content, other->length);
		if (self->content)
		{
			self->length = other->length;
			self->allocated = self->length + 1;
		}
		else {
			self->length = self->allocated = 0;
		}
	}
	return self;
}






TRIO_PUBLIC_STRING trio_string_t* trio_xstring_duplicate TRIO_ARGS1((other), TRIO_CONST char* other)
{
	trio_string_t* self;

	assert(other);

	self = internal_string_alloc();
	if (self)
	{
		self->content = internal_duplicate_max(other, trio_length(other));
		if (self->content)
		{
			self->length = trio_length(self->content);
			self->allocated = self->length + 1;
		}
		else {
			self->length = self->allocated = 0;
		}
	}
	return self;
}






TRIO_PUBLIC_STRING int trio_string_equal TRIO_ARGS2((self, other), trio_string_t* self, trio_string_t* other)
{
	assert(self);
	assert(other);

	return trio_equal(self->content, other->content);
}






TRIO_PUBLIC_STRING int trio_xstring_equal TRIO_ARGS2((self, other), trio_string_t* self, TRIO_CONST char* other)
{
	assert(self);
	assert(other);

	return trio_equal(self->content, other);
}






TRIO_PUBLIC_STRING int trio_string_equal_max TRIO_ARGS3((self, max, other), trio_string_t* self, size_t max, trio_string_t* other)
{
	assert(self);
	assert(other);

	return trio_equal_max(self->content, max, other->content);
}





TRIO_PUBLIC_STRING int trio_xstring_equal_max TRIO_ARGS3((self, max, other), trio_string_t* self, size_t max, TRIO_CONST char* other)
{
	assert(self);
	assert(other);

	return trio_equal_max(self->content, max, other);
}






TRIO_PUBLIC_STRING int trio_string_equal_case TRIO_ARGS2((self, other), trio_string_t* self, trio_string_t* other)
{
	assert(self);
	assert(other);

	return trio_equal_case(self->content, other->content);
}






TRIO_PUBLIC_STRING int trio_xstring_equal_case TRIO_ARGS2((self, other), trio_string_t* self, TRIO_CONST char* other)
{
	assert(self);
	assert(other);

	return trio_equal_case(self->content, other);
}






TRIO_PUBLIC_STRING int trio_string_equal_case_max TRIO_ARGS3((self, max, other), trio_string_t* self, size_t max, trio_string_t* other)

{
	assert(self);
	assert(other);

	return trio_equal_case_max(self->content, max, other->content);
}






TRIO_PUBLIC_STRING int trio_xstring_equal_case_max TRIO_ARGS3((self, max, other), trio_string_t* self, size_t max, TRIO_CONST char* other)

{
	assert(self);
	assert(other);

	return trio_equal_case_max(self->content, max, other);
}






TRIO_PUBLIC_STRING size_t trio_string_format_date_max TRIO_ARGS4((self, max, format, datetime), trio_string_t* self, size_t max, TRIO_CONST char* format, TRIO_CONST struct tm* datetime)


{
	assert(self);

	return trio_format_date_max(self->content, max, format, datetime);
}






TRIO_PUBLIC_STRING char* trio_string_index TRIO_ARGS2((self, character), trio_string_t* self, int character)
{
	assert(self);

	return trio_index(self->content, character);
}






TRIO_PUBLIC_STRING char* trio_string_index_last TRIO_ARGS2((self, character), trio_string_t* self, int character)
{
	assert(self);

	return trio_index_last(self->content, character);
}






TRIO_PUBLIC_STRING int trio_string_length TRIO_ARGS1((self), trio_string_t* self)
{
	assert(self);

	if (self->length == 0)
	{
		self->length = trio_length(self->content);
	}
	return self->length;
}






TRIO_PUBLIC_STRING int trio_string_lower TRIO_ARGS1((self), trio_string_t* self)
{
	assert(self);

	return trio_lower(self->content);
}






TRIO_PUBLIC_STRING int trio_string_match TRIO_ARGS2((self, other), trio_string_t* self, trio_string_t* other)
{
	assert(self);
	assert(other);

	return trio_match(self->content, other->content);
}






TRIO_PUBLIC_STRING int trio_xstring_match TRIO_ARGS2((self, other), trio_string_t* self, TRIO_CONST char* other)
{
	assert(self);
	assert(other);

	return trio_match(self->content, other);
}






TRIO_PUBLIC_STRING int trio_string_match_case TRIO_ARGS2((self, other), trio_string_t* self, trio_string_t* other)
{
	assert(self);
	assert(other);

	return trio_match_case(self->content, other->content);
}






TRIO_PUBLIC_STRING int trio_xstring_match_case TRIO_ARGS2((self, other), trio_string_t* self, TRIO_CONST char* other)
{
	assert(self);
	assert(other);

	return trio_match_case(self->content, other);
}






TRIO_PUBLIC_STRING char* trio_string_substring TRIO_ARGS2((self, other), trio_string_t* self, trio_string_t* other)
{
	assert(self);
	assert(other);

	return trio_substring(self->content, other->content);
}






TRIO_PUBLIC_STRING char* trio_xstring_substring TRIO_ARGS2((self, other), trio_string_t* self, TRIO_CONST char* other)
{
	assert(self);
	assert(other);

	return trio_substring(self->content, other);
}






TRIO_PUBLIC_STRING int trio_string_upper TRIO_ARGS1((self), trio_string_t* self)
{
	assert(self);

	return trio_upper(self->content);
}




