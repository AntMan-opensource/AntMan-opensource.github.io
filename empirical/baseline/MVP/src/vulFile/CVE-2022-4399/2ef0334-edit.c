














static char* bname;
static char* bdate;


static void draw(char* data)
{
	
	clear();
	
	attron(A_BOLD);
	printw("%s (%s):\n",bname,bdate);
	attroff(A_BOLD);
	
	printw("%s",data);
	
	refresh();
}


static int edit_builtin(char* name, char* date, char* data)
{
	char buffer[256];
	int bl;
	
	int quit = 0;
	
	int plch = 0;
	int lch = 0;
	int ch = 0;

	
	bname = name;
	bdate = date;
	
	bl = strlen(data);
	
	
	memset(&buffer,0,256);

	
	if (bl > 255) {
		data[255] = 0;
		bl = 255;
	}

	
	sprintf(buffer, "%s", data);

	
	initscr();
	
	cbreak();
	
	keypad(stdscr, TRUE);
	
	noecho();

	
	while (!quit) {
		
		draw(buffer);
		
		plch = lch;
		
		lch = ch;
		
		ch = getch();
		
		if (isprint(ch) || ch == '\n') {
			bl++;
			
			if (bl < 255) {
				buffer[bl-1] = ch;
				buffer[bl] = 0;
			}
		
		}else if (ch == 127 || ch == KEY_BACKSPACE) {
			
			if (bl > 0) {
				bl--;
				buffer[bl] = 0;
			}
		}

		
		if (plch == '\n' && lch == '.' && ch == '\n') {
			
			bl -= 3;
			buffer[bl] = 0;
			quit = 1;
		
		}else if (ch == 27) {
			quit = 1;
		}
	}

	
	endwin();

	
	if (!db_update(name,buffer))
		return 1;

	
	printf("%s saved\n",name);

	return 0;
}


static int edit_ext(char* editor, char* name, char* date, char* data)
{
	int fd;
	int st;
	int sz;
	char* b;
	char* l;
	char buff[512];
	pid_t pid;

	strcpy(buff,"/tmp/nodau.XXXXXX");
	fd = mkstemp(buff);

	if (fd < 0)
		return 1;

	pid = fork();

	if (pid < 0) {
		return 1;
	}else if (pid) {
		close(fd);
		waitpid(pid,&st,0);
		if (!st) {
			if ((fd = open(buff,O_RDONLY)) < 0)
				return 1;
			
			sz = lseek(fd,0,SEEK_END);
			lseek(fd,0,SEEK_SET);
			if (sz) {
				
				b = alloca(sz+1);
				if (sz != read(fd,b,sz))
					return 1;
				close(fd);
				
				remove(buff);
				b[sz] = 0;
				
				l = strstr(b,"-----");
				if (l) {
					
					l += 6;
					if (db_update(name,l))
						return 1;

					
					printf("%s saved\n",name);
				}
			}
		}
		return st;
	}

	sz = strlen(name)+strlen(date)+strlen(data)+50;
	b = alloca(sz);

	
	sz = sprintf( b, "%s (%s)\nText above this line is ignored\n-----\n%s", name, date, data );





	if (write(fd,b,sz) != sz) {
		exit(1);
	}
	fsync(fd);
	close(fd);

	st = execl(editor,editor,buff,(char*)NULL);

	
	exit(st);

	
	return 1;
}


int edit_stdin(char* name, char* date, char* data, int append)
{
	char buff[1024];
	int l;
	int s;
	int r;
	char* d;
	char* b;

	
	l = strlen(data);
	if (l < 512) {
		s = 512;
	}else{
		s = l*2;
	}

	d = malloc(s);
	if (!d)
		return 1;

	
	if (append && strcmp(data,"new entry")) {
		strcpy(d,data);
	}else{
		l = 0;
	}

	
	while ((r = read(STDIN_FILENO,buff,1024)) > 0) {
		
		if (l+r+1 > s) {
			s = l+r+512;
			b = realloc(d,s);
			if (!b)
				return 1;
			d = b;
		}
		memcpy(d+l,buff,r);
		l += r;
	}

	
	if (l+1 > s) {
		s = l+1;
		b = realloc(d,s);
		if (!b)
			return 1;
		d = b;
	}

	d[l] = 0;

	
	return db_update(name,d);
}


int edit(char* name, char* date, char* data)
{
	char* ed;
	char* pt;
	char* editor;
	char* p = NULL;
	struct stat st;

	if (!isatty(STDIN_FILENO))
		return edit_stdin(name,date,data,0);

	pt = getenv("PATH");

	ed = config_read("external_editor",NULL);
	if (!ed)
		ed = getenv("EDITOR");

	
	if (config_read("force_builtin_editor","true") || !ed || (ed[0] != '/' && !pt))
		return edit_builtin(name,date,data);

	
	if (ed[0] == '/') {
		stat(ed,&st);
		
		if (S_ISREG(st.st_mode)) {
			p = ed;
			editor = strdup(ed);
		}
	}else{
		p = strtok(pt,":");
		while (p) {
			p = strtok(NULL,":");

			if (asprintf(&editor,"%s/%s",p,ed) < 0)
				continue;

			stat(editor,&st);
			
			if (S_ISREG(st.st_mode))
				break;

			free(editor);
		}
	}

	
	if (!p || edit_ext(editor,name,date,data))
		return edit_builtin(name,date,data);

	return 0;
}
