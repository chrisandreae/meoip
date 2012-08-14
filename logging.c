#include "logging.h"

#include <stdarg.h>
#include <stdio.h>

static enum log_level gVerbose = NORMAL;

void setVerbosity(enum log_level level){
	gVerbose = level;
}

enum log_level getVerbosity(){
	return gVerbose;
}

void log_msg(const enum log_level level, const char* fmt, ...){
	if(gVerbose >= level){
		va_list ap;
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
	}
}

