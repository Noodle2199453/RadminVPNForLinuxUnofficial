#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <windows.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ===================================================================
 * Logging (console + file in %TEMP%)
 * =================================================================== */

// Function declarations
void InitLog(void);
void LogTimestamp(void);
void LogMsg(const char* fmt, ...);
void LogHex(const BYTE* data, DWORD len, const char* prefix);
void DisableLog(void);
void EnableLog(void);
void LogMsgAndHex(const char* fmt, const BYTE* data, DWORD dataLen, const char* hexPrefix, ...);

// Helper macro for cleaner logging
#define LOG(fmt, ...) LogMsg(fmt, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif // LOG_H