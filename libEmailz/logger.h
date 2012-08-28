/*
 *  logger.h
 *  Static
 *
 *  Created by Curtis Jones on 2009.12.22.
 *  Copyright 2009 Curtis Jones. All rights reserved.
 *
 */

#ifndef __CJ_LOGGER_H__
#define __CJ_LOGGER_H__

#include <stdio.h>
#include <string.h>

#if !(defined (G_STMT_START) && defined (G_STMT_END))
#  if defined (__GNUC__) && !defined (__STRICT_ANSI__) && !defined (__cplusplus)
#    define G_STMT_START	(void)(
#    define G_STMT_END		)
#  else
#    if (defined (sun) || defined (__sun__))
#      define G_STMT_START	if (1)
#      define G_STMT_END	else (void)0
#    else
#      define G_STMT_START	do
#      define G_STMT_END	while (0)
#    endif
#  endif
#endif

#define LOGX(...) G_STMT_START{ printf("%s+%d [%s] : ", __FILE__, __LINE__, __PRETTY_FUNCTION__); printf(__VA_ARGS__); printf("\n"); }G_STMT_END

#ifdef LOG_LEVEL

//
// error
//
#if LOG_LEVEL >= 1
#define LOG1(...) LOGX(__VA_ARGS__)
#else
#define LOG1(...) ((void)0)
#endif

//
// ?
//
#if LOG_LEVEL >= 2
#define LOG2(...) LOGX(__VA_ARGS__)
#else
#define LOG2(...) ((void)0)
#endif

//
// standard
//
#if LOG_LEVEL >= 3
#define LOG3(...) LOGX(__VA_ARGS__)
#else
#define LOG3(...) ((void)0)
#endif

//
// ?
//
#if LOG_LEVEL >= 4
#define LOG4(...) LOGX(__VA_ARGS__)
#else
#define LOG4(...) ((void)0)
#endif

//
// debug
//
#if LOG_LEVEL >= 5
#define LOG5(...) LOGX(__VA_ARGS__)
#else
#define LOG5(...) ((void)0)
#endif

#else

#define LOG1(...) ((void)0)
#define LOG2(...) ((void)0)
#define LOG3(...) ((void)0)
#define LOG4(...) ((void)0)
#define LOG5(...) ((void)0)

#endif

#define LOG_ERROR_AND_BREAK(...) {LOGX(__VA_ARGS__); break;}
#define LOG_ERROR_AND_CONTINUE(...) {LOGX(__VA_ARGS__); continue;}
#define LOG_ERROR_AND_GOTO(a,b,...) {LOGX(__VA_ARGS__); error=a; goto b;}
#define LOG_ERROR_AND_RETURN(a,...) {LOGX(__VA_ARGS__); return a;}

#endif /* __CJ_LOGGER_H__ */
