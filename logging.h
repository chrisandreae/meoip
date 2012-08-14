#ifndef __LOGGING_H
#define __LOGGING_H

// verbosity levels
enum log_level {
	NORMAL=0,
	VERBOSE,
	DEBUG,
	PACKETS
};

void setVerbosity(enum log_level level);

enum log_level getVerbosity();

void log_msg(const enum log_level level, const char* fmt, ...);

#endif // __LOGGING_H
