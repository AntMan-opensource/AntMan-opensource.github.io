







static bool valid_variable_name(const char *name)
{
	const unsigned char *ptr = (const unsigned char *) name;

	
	if (*ptr == '\0')
		return false;

	while (*ptr)
	{
		if (IS_HIGHBIT_SET(*ptr) || strchr("ABCDEFGHIJKLMNOPQRSTUVWXYZ" "abcdefghijklmnopqrstuvwxyz" "_0123456789", *ptr) != NULL)

			ptr++;
		else return false;
	}

	return true;
}


VariableSpace CreateVariableSpace(void)
{
	struct _variable *ptr;

	ptr = pg_malloc(sizeof *ptr);
	ptr->name = NULL;
	ptr->value = NULL;
	ptr->substitute_hook = NULL;
	ptr->assign_hook = NULL;
	ptr->next = NULL;

	return ptr;
}


const char * GetVariable(VariableSpace space, const char *name)
{
	struct _variable *current;

	if (!space)
		return NULL;

	for (current = space->next; current; current = current->next)
	{
		int			cmp = strcmp(current->name, name);

		if (cmp == 0)
		{
			
			return current->value;
		}
		if (cmp > 0)
			break;				
	}

	return NULL;
}


bool ParseVariableBool(const char *value, const char *name, bool *result)
{
	size_t		len;
	bool		valid = true;

	
	if (value == NULL)
		value = "";

	len = strlen(value);

	if (len > 0 && pg_strncasecmp(value, "true", len) == 0)
		*result = true;
	else if (len > 0 && pg_strncasecmp(value, "false", len) == 0)
		*result = false;
	else if (len > 0 && pg_strncasecmp(value, "yes", len) == 0)
		*result = true;
	else if (len > 0 && pg_strncasecmp(value, "no", len) == 0)
		*result = false;
	
	else if (pg_strncasecmp(value, "on", (len > 2 ? len : 2)) == 0)
		*result = true;
	else if (pg_strncasecmp(value, "off", (len > 2 ? len : 2)) == 0)
		*result = false;
	else if (pg_strcasecmp(value, "1") == 0)
		*result = true;
	else if (pg_strcasecmp(value, "0") == 0)
		*result = false;
	else {
		
		if (name)
			psql_error("unrecognized value \"%s\" for \"%s\": Boolean expected\n", value, name);
		valid = false;
	}
	return valid;
}


bool ParseVariableNum(const char *value, const char *name, int *result)
{
	char	   *end;
	long		numval;

	
	if (value == NULL)
		value = "";

	errno = 0;
	numval = strtol(value, &end, 0);
	if (errno == 0 && *end == '\0' && end != value && numval == (int) numval)
	{
		*result = (int) numval;
		return true;
	}
	else {
		
		if (name)
			psql_error("invalid value \"%s\" for \"%s\": integer expected\n", value, name);
		return false;
	}
}


void PrintVariables(VariableSpace space)
{
	struct _variable *ptr;

	if (!space)
		return;

	for (ptr = space->next; ptr; ptr = ptr->next)
	{
		if (ptr->value)
			printf("%s = '%s'\n", ptr->name, ptr->value);
		if (cancel_pressed)
			break;
	}
}


bool SetVariable(VariableSpace space, const char *name, const char *value)
{
	struct _variable *current, *previous;

	if (!space || !name)
		return false;

	if (!valid_variable_name(name))
	{
		
		if (!value)
			return true;
		psql_error("invalid variable name: \"%s\"\n", name);
		return false;
	}

	for (previous = space, current = space->next;
		 current;
		 previous = current, current = current->next)
	{
		int			cmp = strcmp(current->name, name);

		if (cmp == 0)
		{
			
			char	   *new_value = value ? pg_strdup(value) : NULL;
			bool		confirmed;

			if (current->substitute_hook)
				new_value = current->substitute_hook(new_value);

			if (current->assign_hook)
				confirmed = current->assign_hook(new_value);
			else confirmed = true;

			if (confirmed)
			{
				if (current->value)
					pg_free(current->value);
				current->value = new_value;

				
				if (new_value == NULL && current->substitute_hook == NULL && current->assign_hook == NULL)

				{
					previous->next = current->next;
					free(current->name);
					free(current);
				}
			}
			else if (new_value)
				pg_free(new_value); 

			return confirmed;
		}
		if (cmp > 0)
			break;				
	}

	
	if (value)
	{
		current = pg_malloc(sizeof *current);
		current->name = pg_strdup(name);
		current->value = pg_strdup(value);
		current->substitute_hook = NULL;
		current->assign_hook = NULL;
		current->next = previous->next;
		previous->next = current;
	}
	return true;
}


void SetVariableHooks(VariableSpace space, const char *name, VariableSubstituteHook shook, VariableAssignHook ahook)


{
	struct _variable *current, *previous;

	if (!space || !name)
		return;

	if (!valid_variable_name(name))
		return;

	for (previous = space, current = space->next;
		 current;
		 previous = current, current = current->next)
	{
		int			cmp = strcmp(current->name, name);

		if (cmp == 0)
		{
			
			current->substitute_hook = shook;
			current->assign_hook = ahook;
			if (shook)
				current->value = (*shook) (current->value);
			if (ahook)
				(void) (*ahook) (current->value);
			return;
		}
		if (cmp > 0)
			break;				
	}

	
	current = pg_malloc(sizeof *current);
	current->name = pg_strdup(name);
	current->value = NULL;
	current->substitute_hook = shook;
	current->assign_hook = ahook;
	current->next = previous->next;
	previous->next = current;
	if (shook)
		current->value = (*shook) (current->value);
	if (ahook)
		(void) (*ahook) (current->value);
}


bool SetVariableBool(VariableSpace space, const char *name)
{
	return SetVariable(space, name, "on");
}


bool DeleteVariable(VariableSpace space, const char *name)
{
	return SetVariable(space, name, NULL);
}


void PsqlVarEnumError(const char *name, const char *value, const char *suggestions)
{
	psql_error("unrecognized value \"%s\" for \"%s\"\nAvailable values are: %s.\n", value, name, suggestions);
}
