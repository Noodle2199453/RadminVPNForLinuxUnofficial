#include <windows.h>
#include <mmsystem.h>      // for MMRESULT, LPHWAVEOUT, etc.

static HMODULE g_hRealWinMM = NULL;

// Corrected FORWARD macro: separate declaration and call arguments
#define FORWARD(FUNC, RET, DECL, ARGS)                                 \
    RET WINAPI FUNC DECL {                                             \
        static RET (WINAPI *pReal) DECL = NULL;                       \
        if (!pReal) {                                                  \
            pReal = (RET (WINAPI *)DECL) GetProcAddress(g_hRealWinMM, #FUNC); \
            if (!pReal) return (RET)0;                                 \
        }                                                              \
        return pReal ARGS;                                             \
    }

/* -------- All exported functions (based on real winmm.dll) -------- */

// PlaySound
FORWARD(PlaySoundA,          BOOL, (LPCSTR pszSound, HMODULE hmod, DWORD fdwSound), (pszSound, hmod, fdwSound))
FORWARD(PlaySoundW,          BOOL, (LPCWSTR pszSound, HMODULE hmod, DWORD fdwSound), (pszSound, hmod, fdwSound))
FORWARD(sndPlaySoundA,       BOOL, (LPCSTR pszSound, UINT fuSound), (pszSound, fuSound))
FORWARD(sndPlaySoundW,       BOOL, (LPCWSTR pszSound, UINT fuSound), (pszSound, fuSound))

// WaveOut
FORWARD(waveOutOpen,         MMRESULT, (LPHWAVEOUT phwo, UINT uDeviceID, LPCWAVEFORMATEX pwfx, DWORD_PTR dwCallback, DWORD_PTR dwInstance, DWORD fdwOpen), (phwo, uDeviceID, pwfx, dwCallback, dwInstance, fdwOpen))
FORWARD(waveOutClose,        MMRESULT, (HWAVEOUT hwo), (hwo))
FORWARD(waveOutWrite,        MMRESULT, (HWAVEOUT hwo, LPWAVEHDR pwh, UINT cbwh), (hwo, pwh, cbwh))
FORWARD(waveOutPrepareHeader,MMRESULT, (HWAVEOUT hwo, LPWAVEHDR pwh, UINT cbwh), (hwo, pwh, cbwh))
FORWARD(waveOutUnprepareHeader,MMRESULT, (HWAVEOUT hwo, LPWAVEHDR pwh, UINT cbwh), (hwo, pwh, cbwh))
FORWARD(waveOutReset,        MMRESULT, (HWAVEOUT hwo), (hwo))
FORWARD(waveOutPause,        MMRESULT, (HWAVEOUT hwo), (hwo))
FORWARD(waveOutRestart,      MMRESULT, (HWAVEOUT hwo), (hwo))
FORWARD(waveOutGetPosition,  MMRESULT, (HWAVEOUT hwo, LPMMTIME pmmt, UINT cbmmt), (hwo, pmmt, cbmmt))
FORWARD(waveOutGetVolume,    MMRESULT, (HWAVEOUT hwo, LPDWORD pdwVolume), (hwo, pdwVolume))
FORWARD(waveOutSetVolume,    MMRESULT, (HWAVEOUT hwo, DWORD dwVolume), (hwo, dwVolume))
FORWARD(waveOutBreakLoop,    MMRESULT, (HWAVEOUT hwo), (hwo))
FORWARD(waveOutMessage,      MMRESULT, (HWAVEOUT hwo, UINT uMsg, DWORD_PTR dw1, DWORD_PTR dw2), (hwo, uMsg, dw1, dw2))
FORWARD(waveOutGetDevCapsA,  MMRESULT, (UINT_PTR uDeviceID, LPWAVEOUTCAPSA pwoc, UINT cbwoc), (uDeviceID, pwoc, cbwoc))
FORWARD(waveOutGetDevCapsW,  MMRESULT, (UINT_PTR uDeviceID, LPWAVEOUTCAPSW pwoc, UINT cbwoc), (uDeviceID, pwoc, cbwoc))
FORWARD(waveOutGetNumDevs,   UINT,     (void), ())
FORWARD(waveOutGetPlaybackRate, MMRESULT, (HWAVEOUT hwo, LPDWORD pdwRate), (hwo, pdwRate))
FORWARD(waveOutSetPlaybackRate, MMRESULT, (HWAVEOUT hwo, DWORD dwRate), (hwo, dwRate))
FORWARD(waveOutGetPitch,     MMRESULT, (HWAVEOUT hwo, LPDWORD pdwPitch), (hwo, pdwPitch))
FORWARD(waveOutSetPitch,     MMRESULT, (HWAVEOUT hwo, DWORD dwPitch), (hwo, dwPitch))
FORWARD(waveOutGetID,        MMRESULT, (HWAVEOUT hwo, LPUINT puDeviceID), (hwo, puDeviceID))

// WaveIn
FORWARD(waveInOpen,          MMRESULT, (LPHWAVEIN phwi, UINT uDeviceID, LPCWAVEFORMATEX pwfx, DWORD_PTR dwCallback, DWORD_PTR dwInstance, DWORD fdwOpen), (phwi, uDeviceID, pwfx, dwCallback, dwInstance, fdwOpen))
FORWARD(waveInClose,         MMRESULT, (HWAVEIN hwi), (hwi))
FORWARD(waveInStart,         MMRESULT, (HWAVEIN hwi), (hwi))
FORWARD(waveInStop,          MMRESULT, (HWAVEIN hwi), (hwi))
FORWARD(waveInReset,         MMRESULT, (HWAVEIN hwi), (hwi))
FORWARD(waveInAddBuffer,     MMRESULT, (HWAVEIN hwi, LPWAVEHDR pwh, UINT cbwh), (hwi, pwh, cbwh))
FORWARD(waveInPrepareHeader, MMRESULT, (HWAVEIN hwi, LPWAVEHDR pwh, UINT cbwh), (hwi, pwh, cbwh))
FORWARD(waveInUnprepareHeader,MMRESULT, (HWAVEIN hwi, LPWAVEHDR pwh, UINT cbwh), (hwi, pwh, cbwh))
FORWARD(waveInGetDevCapsA,   MMRESULT, (UINT_PTR uDeviceID, LPWAVEINCAPSA pwic, UINT cbwic), (uDeviceID, pwic, cbwic))
FORWARD(waveInGetDevCapsW,   MMRESULT, (UINT_PTR uDeviceID, LPWAVEINCAPSW pwic, UINT cbwic), (uDeviceID, pwic, cbwic))
FORWARD(waveInGetNumDevs,    UINT,     (void), ())
FORWARD(waveInGetPosition,   MMRESULT, (HWAVEIN hwi, LPMMTIME pmmt, UINT cbmmt), (hwi, pmmt, cbmmt))
FORWARD(waveInMessage,       MMRESULT, (HWAVEIN hwi, UINT uMsg, DWORD_PTR dw1, DWORD_PTR dw2), (hwi, uMsg, dw1, dw2))
FORWARD(waveInGetID,         MMRESULT, (HWAVEIN hwi, LPUINT puDeviceID), (hwi, puDeviceID))

// MidiOut
FORWARD(midiOutOpen,         MMRESULT, (LPHMIDIOUT phmo, UINT uDeviceID, DWORD_PTR dwCallback, DWORD_PTR dwInstance, DWORD fdwOpen), (phmo, uDeviceID, dwCallback, dwInstance, fdwOpen))
FORWARD(midiOutClose,        MMRESULT, (HMIDIOUT hmo), (hmo))
FORWARD(midiOutShortMsg,     MMRESULT, (HMIDIOUT hmo, DWORD dwMsg), (hmo, dwMsg))
FORWARD(midiOutLongMsg,      MMRESULT, (HMIDIOUT hmo, LPMIDIHDR pmh, UINT cbmh), (hmo, pmh, cbmh))
FORWARD(midiOutReset,        MMRESULT, (HMIDIOUT hmo), (hmo))
FORWARD(midiOutGetDevCapsA,  MMRESULT, (UINT_PTR uDeviceID, LPMIDIOUTCAPSA pmoc, UINT cbmoc), (uDeviceID, pmoc, cbmoc))
FORWARD(midiOutGetDevCapsW,  MMRESULT, (UINT_PTR uDeviceID, LPMIDIOUTCAPSW pmoc, UINT cbmoc), (uDeviceID, pmoc, cbmoc))
FORWARD(midiOutGetNumDevs,   UINT,     (void), ())
FORWARD(midiOutGetVolume,    MMRESULT, (HMIDIOUT hmo, LPDWORD pdwVolume), (hmo, pdwVolume))
FORWARD(midiOutSetVolume,    MMRESULT, (HMIDIOUT hmo, DWORD dwVolume), (hmo, dwVolume))
FORWARD(midiOutMessage,      MMRESULT, (HMIDIOUT hmo, UINT uMsg, DWORD_PTR dw1, DWORD_PTR dw2), (hmo, uMsg, dw1, dw2))
FORWARD(midiOutPrepareHeader,MMRESULT, (HMIDIOUT hmo, LPMIDIHDR pmh, UINT cbmh), (hmo, pmh, cbmh))
FORWARD(midiOutUnprepareHeader,MMRESULT, (HMIDIOUT hmo, LPMIDIHDR pmh, UINT cbmh), (hmo, pmh, cbmh))
FORWARD(midiOutCachePatches, MMRESULT, (HMIDIOUT hmo, UINT uBank, LPWORD pwpa, UINT fuCache), (hmo, uBank, pwpa, fuCache))
FORWARD(midiOutCacheDrumPatches,MMRESULT, (HMIDIOUT hmo, UINT uPatch, LPWORD pwk, UINT fuCache), (hmo, uPatch, pwk, fuCache))
FORWARD(midiOutGetID,        MMRESULT, (HMIDIOUT hmo, LPUINT puDeviceID), (hmo, puDeviceID))

// MidiIn
FORWARD(midiInOpen,          MMRESULT, (LPHMIDIIN phmi, UINT uDeviceID, DWORD_PTR dwCallback, DWORD_PTR dwInstance, DWORD fdwOpen), (phmi, uDeviceID, dwCallback, dwInstance, fdwOpen))
FORWARD(midiInClose,         MMRESULT, (HMIDIIN hmi), (hmi))
FORWARD(midiInStart,         MMRESULT, (HMIDIIN hmi), (hmi))
FORWARD(midiInStop,          MMRESULT, (HMIDIIN hmi), (hmi))
FORWARD(midiInReset,         MMRESULT, (HMIDIIN hmi), (hmi))
FORWARD(midiInAddBuffer,     MMRESULT, (HMIDIIN hmi, LPMIDIHDR pmh, UINT cbmh), (hmi, pmh, cbmh))
FORWARD(midiInPrepareHeader, MMRESULT, (HMIDIIN hmi, LPMIDIHDR pmh, UINT cbmh), (hmi, pmh, cbmh))
FORWARD(midiInUnprepareHeader,MMRESULT, (HMIDIIN hmi, LPMIDIHDR pmh, UINT cbmh), (hmi, pmh, cbmh))
FORWARD(midiInGetDevCapsA,   MMRESULT, (UINT_PTR uDeviceID, LPMIDIINCAPSA pmiic, UINT cbmiic), (uDeviceID, pmiic, cbmiic))
FORWARD(midiInGetDevCapsW,   MMRESULT, (UINT_PTR uDeviceID, LPMIDIINCAPSW pmiic, UINT cbmiic), (uDeviceID, pmiic, cbmiic))
FORWARD(midiInGetNumDevs,    UINT,     (void), ())
FORWARD(midiInMessage,       MMRESULT, (HMIDIIN hmi, UINT uMsg, DWORD_PTR dw1, DWORD_PTR dw2), (hmi, uMsg, dw1, dw2))
FORWARD(midiInGetID,         MMRESULT, (HMIDIIN hmi, LPUINT puDeviceID), (hmi, puDeviceID))

// MidiStream
FORWARD(midiStreamOpen,      MMRESULT, (LPHMIDISTRM phms, LPUINT puDeviceID, DWORD cMidi, DWORD_PTR dwCallback, DWORD_PTR dwInstance, DWORD fdwOpen), (phms, puDeviceID, cMidi, dwCallback, dwInstance, fdwOpen))
FORWARD(midiStreamClose,     MMRESULT, (HMIDISTRM hms), (hms))
FORWARD(midiStreamOut,       MMRESULT, (HMIDISTRM hms, LPMIDIHDR pmh, UINT cbmh), (hms, pmh, cbmh))
FORWARD(midiStreamPause,     MMRESULT, (HMIDISTRM hms), (hms))
FORWARD(midiStreamRestart,   MMRESULT, (HMIDISTRM hms), (hms))
FORWARD(midiStreamStop,      MMRESULT, (HMIDISTRM hms), (hms))
FORWARD(midiStreamPosition,  MMRESULT, (HMIDISTRM hms, LPMMTIME pmmt, UINT cbmmt), (hms, pmmt, cbmmt))
// FORWARD(midiStreamProperty,  MMRESULT, (HMIDISTRM hms, LPVOID pProperty, DWORD dwProperty), (hms, pProperty, dwProperty))

// Aux
FORWARD(auxGetDevCapsA,      MMRESULT, (UINT_PTR uDeviceID, LPAUXCAPSA pac, UINT cbac), (uDeviceID, pac, cbac))
FORWARD(auxGetDevCapsW,      MMRESULT, (UINT_PTR uDeviceID, LPAUXCAPSW pac, UINT cbac), (uDeviceID, pac, cbac))
FORWARD(auxGetNumDevs,       UINT,     (void), ())
FORWARD(auxGetVolume,        MMRESULT, (UINT uDeviceID, LPDWORD pdwVolume), (uDeviceID, pdwVolume))
FORWARD(auxSetVolume,        MMRESULT, (UINT uDeviceID, DWORD dwVolume), (uDeviceID, dwVolume))
FORWARD(auxOutMessage,       MMRESULT, (UINT uDeviceID, UINT uMsg, DWORD_PTR dw1, DWORD_PTR dw2), (uDeviceID, uMsg, dw1, dw2))

// Mixer
FORWARD(mixerOpen,           MMRESULT, (LPHMIXER phmx, UINT uMxId, DWORD_PTR dwCallback, DWORD_PTR dwInstance, DWORD fdwOpen), (phmx, uMxId, dwCallback, dwInstance, fdwOpen))
FORWARD(mixerClose,          MMRESULT, (HMIXER hmx), (hmx))
FORWARD(mixerGetControlDetailsA, MMRESULT, (HMIXEROBJ hmxobj, LPMIXERCONTROLDETAILS pmxcd, DWORD fdwDetails), (hmxobj, pmxcd, fdwDetails))
FORWARD(mixerGetControlDetailsW, MMRESULT, (HMIXEROBJ hmxobj, LPMIXERCONTROLDETAILS pmxcd, DWORD fdwDetails), (hmxobj, pmxcd, fdwDetails))
FORWARD(mixerGetLineControlsA,   MMRESULT, (HMIXEROBJ hmxobj, LPMIXERLINECONTROLS pmxlc, DWORD fdwControls), (hmxobj, pmxlc, fdwControls))
// FORWARD(mixerGetLineControlsW,   MMRESULT, (HMIXEROBJ hmxobj, LPMIXERLINECONTROLS pmxlc, DWORD fdwControls), (hmxobj, pmxlc, fdwControls))
FORWARD(mixerGetLineInfoA,   MMRESULT, (HMIXEROBJ hmxobj, LPMIXERLINE pmxl, DWORD fdwInfo), (hmxobj, pmxl, fdwInfo))
// FORWARD(mixerGetLineInfoW,   MMRESULT, (HMIXEROBJ hmxobj, LPMIXERLINE pmxl, DWORD fdwInfo), (hmxobj, pmxl, fdwInfo))
FORWARD(mixerGetDevCapsA,    MMRESULT, (UINT_PTR uMxId, LPMIXERCAPSA pmxcaps, UINT cbmxcaps), (uMxId, pmxcaps, cbmxcaps))
FORWARD(mixerGetDevCapsW,    MMRESULT, (UINT_PTR uMxId, LPMIXERCAPSW pmxcaps, UINT cbmxcaps), (uMxId, pmxcaps, cbmxcaps))
FORWARD(mixerGetNumDevs,     UINT,     (void), ())
// FORWARD(mixerMessage,        MMRESULT, (HMIXER hmx, UINT uMsg, DWORD_PTR dw1, DWORD_PTR dw2), (hmx, uMsg, dw1, dw2))
FORWARD(mixerGetID,          MMRESULT, (HMIXEROBJ hmxobj, LPUINT puMxId, DWORD fdwId), (hmxobj, puMxId, fdwId))
FORWARD(mixerSetControlDetails, MMRESULT, (HMIXEROBJ hmxobj, LPMIXERCONTROLDETAILS pmxcd, DWORD fdwDetails), (hmxobj, pmxcd, fdwDetails))

// Time
FORWARD(timeGetTime,         DWORD,    (void), ())
FORWARD(timeBeginPeriod,     MMRESULT, (UINT uPeriod), (uPeriod))
FORWARD(timeEndPeriod,       MMRESULT, (UINT uPeriod), (uPeriod))
FORWARD(timeGetDevCaps,      MMRESULT, (LPTIMECAPS ptc, UINT cbtc), (ptc, cbtc))
FORWARD(timeGetSystemTime,   MMRESULT, (LPMMTIME pmmt, UINT cbmmt), (pmmt, cbmmt))
FORWARD(timeKillEvent,       MMRESULT, (UINT uTimerID), (uTimerID))
FORWARD(timeSetEvent,        MMRESULT, (UINT uDelay, UINT uResolution, LPTIMECALLBACK fptc, DWORD_PTR dwUser, UINT fuEvent), (uDelay, uResolution, fptc, dwUser, fuEvent))

// MCI
FORWARD(mciSendCommandA,     MCIERROR, (MCIDEVICEID IDDevice, UINT uMsg, DWORD_PTR fdwCommand, DWORD_PTR dwParam), (IDDevice, uMsg, fdwCommand, dwParam))
FORWARD(mciSendCommandW,     MCIERROR, (MCIDEVICEID IDDevice, UINT uMsg, DWORD_PTR fdwCommand, DWORD_PTR dwParam), (IDDevice, uMsg, fdwCommand, dwParam))
FORWARD(mciSendStringA,      MCIERROR, (LPCSTR lpstrCommand, LPSTR lpstrReturnString, UINT uReturnLength, HWND hwndCallback), (lpstrCommand, lpstrReturnString, uReturnLength, hwndCallback))
FORWARD(mciSendStringW,      MCIERROR, (LPCWSTR lpstrCommand, LPWSTR lpstrReturnString, UINT uReturnLength, HWND hwndCallback), (lpstrCommand, lpstrReturnString, uReturnLength, hwndCallback))
FORWARD(mciGetDeviceIDA,     MCIDEVICEID, (LPCSTR lpszDevice), (lpszDevice))
FORWARD(mciGetDeviceIDW,     MCIDEVICEID, (LPCWSTR lpszDevice), (lpszDevice))
// FORWARD(mciGetDeviceIDFromElementIDA, MCIDEVICEID, (LPCSTR lpszElement, LPCSTR lpszDevice), (lpszElement, lpszDevice))
// FORWARD(mciGetDeviceIDFromElementIDW, MCIDEVICEID, (LPCWSTR lpszElement, LPCWSTR lpszDevice), (lpszElement, lpszDevice))
FORWARD(mciGetErrorStringA,  BOOL, (MCIERROR mcierr, LPSTR lpszErrorText, UINT cchErrorText), (mcierr, lpszErrorText, cchErrorText))
FORWARD(mciGetErrorStringW,  BOOL, (MCIERROR mcierr, LPWSTR lpszErrorText, UINT cchErrorText), (mcierr, lpszErrorText, cchErrorText))
FORWARD(mciGetYieldProc,     YIELDPROC, (MCIDEVICEID IDDevice, LPDWORD pdwYieldData), (IDDevice, pdwYieldData))
FORWARD(mciSetYieldProc,     BOOL, (MCIDEVICEID IDDevice, YIELDPROC fpYieldProc, DWORD dwYieldData), (IDDevice, fpYieldProc, dwYieldData))
FORWARD(mciExecute,          BOOL, (LPCSTR lpstrCommand), (lpstrCommand))
FORWARD(mciFreeCommandResource, BOOL, (UINT uTable), (uTable))
// FORWARD(mciLoadCommandResource, HANDLE, (HINSTANCE hInstance, LPCSTR lpResName, UINT wType), (hInstance, lpResName, wType))
// FORWARD(mciGetCreatorTask,   WORD,   (MCIDEVICEID IDDevice), (IDDevice))
FORWARD(mciSetDriverData,    BOOL,   (MCIDEVICEID IDDevice, DWORD dwData), (IDDevice, dwData))
FORWARD(mciGetDriverData,    DWORD,  (MCIDEVICEID IDDevice), (IDDevice))
// FORWARD(mciDriverNotify,     BOOL,   (HWND hwndCallback, MCIDEVICEID IDDevice, UINT uStatus), (hwndCallback, IDDevice, uStatus))
FORWARD(mciDriverYield,      UINT,   (MCIDEVICEID IDDevice), (IDDevice))

// MMIO
FORWARD(mmioOpenA,           HMMIO,  (LPSTR pszFileName, LPMMIOINFO pmmioinfo, DWORD fdwOpen), (pszFileName, pmmioinfo, fdwOpen))
FORWARD(mmioOpenW,           HMMIO,  (LPWSTR pszFileName, LPMMIOINFO pmmioinfo, DWORD fdwOpen), (pszFileName, pmmioinfo, fdwOpen))
FORWARD(mmioClose,           MMRESULT, (HMMIO hmmio, UINT uFlags), (hmmio, uFlags))
FORWARD(mmioRead,            LONG,    (HMMIO hmmio, HPSTR pch, LONG cch), (hmmio, pch, cch))
FORWARD(mmioWrite,           LONG,    (HMMIO hmmio, const char *pch, LONG cch), (hmmio, pch, cch))
FORWARD(mmioSeek,            LONG,    (HMMIO hmmio, LONG lOffset, int iOrigin), (hmmio, lOffset, iOrigin))
FORWARD(mmioGetInfo,         MMRESULT, (HMMIO hmmio, LPMMIOINFO pmmioinfo, UINT cb), (hmmio, pmmioinfo, cb))
// FORWARD(mmioSetInfo,         MMRESULT, (HMMIO hmmio, const LPMMIOINFO pmmioinfo, UINT cb), (hmmio, pmmioinfo, cb))
FORWARD(mmioSetBuffer,       MMRESULT, (HMMIO hmmio, LPSTR pchBuffer, LONG cchBuffer, UINT fuBuffer), (hmmio, pchBuffer, cchBuffer, fuBuffer))
FORWARD(mmioFlush,           MMRESULT, (HMMIO hmmio, UINT fuFlush), (hmmio, fuFlush))
FORWARD(mmioAdvance,         MMRESULT, (HMMIO hmmio, LPMMIOINFO pmmioinfo, UINT fuAdvance), (hmmio, pmmioinfo, fuAdvance))
FORWARD(mmioAscend,          MMRESULT, (HMMIO hmmio, LPMMCKINFO pmmcki, UINT fuAscend), (hmmio, pmmcki, fuAscend))
// FORWARD(mmioDescend,         MMRESULT, (HMMIO hmmio, LPMMCKINFO pmmcki, const LPMMCKINFO pmmckiParent, UINT fuDescend), (hmmio, pmmcki, pmmckiParent, fuDescend))
FORWARD(mmioCreateChunk,     MMRESULT, (HMMIO hmmio, LPMMCKINFO pmmcki, UINT fuCreate), (hmmio, pmmcki, fuCreate))
FORWARD(mmioStringToFOURCCA, FOURCC,  (LPCSTR sz, UINT uFlags), (sz, uFlags))
FORWARD(mmioStringToFOURCCW, FOURCC,  (LPCWSTR sz, UINT uFlags), (sz, uFlags))
FORWARD(mmioInstallIOProcA,  LPMMIOPROC, (FOURCC fccIOProc, LPMMIOPROC pIOProc, DWORD dwFlags), (fccIOProc, pIOProc, dwFlags))
FORWARD(mmioInstallIOProcW,  LPMMIOPROC, (FOURCC fccIOProc, LPMMIOPROC pIOProc, DWORD dwFlags), (fccIOProc, pIOProc, dwFlags))
FORWARD(mmioRenameA,        MMRESULT, (LPCSTR pszFileName, LPCSTR pszNewFileName, LPCMMIOINFO pmmioinfo, DWORD fdwRename), (pszFileName, pszNewFileName, pmmioinfo, fdwRename))
FORWARD(mmioRenameW,        MMRESULT, (LPCWSTR pszFileName, LPCWSTR pszNewFileName, LPCMMIOINFO pmmioinfo, DWORD fdwRename), (pszFileName, pszNewFileName, pmmioinfo, fdwRename))

// Driver helpers
FORWARD(CloseDriver,          LRESULT, (HDRVR hDriver, LPARAM lParam1, LPARAM lParam2), (hDriver, lParam1, lParam2))
FORWARD(DefDriverProc,       LRESULT, (DWORD_PTR dwDeviceID, HDRVR hDriver, UINT uMsg, LPARAM lParam1, LPARAM lParam2), (dwDeviceID, hDriver, uMsg, lParam1, lParam2))
FORWARD(DriverCallback,      BOOL,    (DWORD_PTR dwCallback, DWORD dwFlags, HDRVR hDevice, DWORD dwMsg, DWORD_PTR dwUser, DWORD_PTR dwParam1, DWORD_PTR dwParam2), (dwCallback, dwFlags, hDevice, dwMsg, dwUser, dwParam1, dwParam2))
FORWARD(DrvClose,            LRESULT, (HDRVR hDriver, LPARAM lParam1, LPARAM lParam2), (hDriver, lParam1, lParam2))
FORWARD(DrvDefDriverProc,    LRESULT, (DWORD_PTR dwDeviceID, HDRVR hDriver, UINT uMsg, LPARAM lParam1, LPARAM lParam2), (dwDeviceID, hDriver, uMsg, lParam1, lParam2))
FORWARD(DrvGetModuleHandle,  HMODULE, (HDRVR hDriver), (hDriver))
FORWARD(DrvSendMessage,      LRESULT, (HDRVR hDriver, UINT uMsg, LPARAM lParam1, LPARAM lParam2), (hDriver, uMsg, lParam1, lParam2))
FORWARD(DrvOpen,             HDRVR,   (LPCSTR lpDriverName, LPCSTR lpSectionName, LPARAM lParam), (lpDriverName, lpSectionName, lParam))
FORWARD(DrvOpenA,            HDRVR,   (LPCSTR lpDriverName, LPCSTR lpSectionName, LPARAM lParam), (lpDriverName, lpSectionName, lParam))
FORWARD(SendDriverMessage,   LRESULT, (HDRVR hDriver, UINT uMsg, LPARAM lParam1, LPARAM lParam2), (hDriver, uMsg, lParam1, lParam2))
FORWARD(OpenDriver,          HDRVR,   (LPCWSTR szDriverName, LPCWSTR szSectionName, LPARAM lParam2), (szDriverName, szSectionName, lParam2))
FORWARD(OpenDriverA,         HDRVR,   (LPCSTR lpDriverName, LPCSTR lpSectionName, LPARAM lParam), (lpDriverName, lpSectionName, lParam))
FORWARD(GetDriverFlags,      DWORD,   (HDRVR hDriver), (hDriver))
FORWARD(GetDriverModuleHandle, HMODULE,(HDRVR hDriver), (hDriver))

// Misc
FORWARD(mmsystemGetVersion,  UINT,     (void), ())
FORWARD(mmGetCurrentTask,    DWORD,    (void), ())
FORWARD(mmTaskBlock,         VOID,     (BOOL fBlock), (fBlock))
// FORWARD(mmTaskCreate,        DWORD,    (LPTASKCALLBACK lpfnCallback, LPUINT lpuInst), (lpfnCallback, lpuInst))
FORWARD(mmTaskSignal,        VOID,     (DWORD dwThreadID), (dwThreadID))
FORWARD(mmTaskYield,         VOID,     (void), ())
FORWARD(joyConfigChanged,    MMRESULT, (DWORD dwFlags), (dwFlags))
FORWARD(joyGetDevCapsA,      MMRESULT, (UINT_PTR uJoyID, LPJOYCAPSA pjc, UINT cjc), (uJoyID, pjc, cjc))
FORWARD(joyGetDevCapsW,      MMRESULT, (UINT_PTR uJoyID, LPJOYCAPSW pjc, UINT cjc), (uJoyID, pjc, cjc))
FORWARD(joyGetNumDevs,       UINT,     (void), ())
FORWARD(joyGetPos,           MMRESULT, (UINT uJoyID, LPJOYINFO pji), (uJoyID, pji))
FORWARD(joyGetPosEx,         MMRESULT, (UINT uJoyID, LPJOYINFOEX pjie), (uJoyID, pjie))
FORWARD(joyGetThreshold,     MMRESULT, (UINT uJoyID, LPUINT puThreshold), (uJoyID, puThreshold))
FORWARD(joyReleaseCapture,   MMRESULT, (UINT uJoyID), (uJoyID))
FORWARD(joySetCapture,       MMRESULT, (HWND hwnd, UINT uJoyID, UINT uPeriod, BOOL fChanged), (hwnd, uJoyID, uPeriod, fChanged))
FORWARD(joySetThreshold,     MMRESULT, (UINT uJoyID, UINT uThreshold), (uJoyID, uThreshold))

/* ------------------------------------------------------------------ */
/*  Extra exports that are actually used & must match the real API   */
/* ------------------------------------------------------------------ */

/* PlaySound is a real separate export (not an alias in the DLL);
   it simply forwards to PlaySoundA. */
#undef PlaySound   // kill the macro, so the symbol stays as "PlaySound"
BOOL WINAPI PlaySound(LPCSTR pszSound, HMODULE hmod, DWORD fdwSound)
{
    // Forward to the real PlaySoundA (which is already defined by FORWARD)
    return PlaySoundA(pszSound, hmod, fdwSound);
}

/* mciDriverNotify – correct signature uses HANDLE */
FORWARD(mciDriverNotify, BOOL, (HANDLE hwndCallback, MCIDEVICEID wDeviceID, UINT uStatus),
        (hwndCallback, wDeviceID, uStatus))

/* mciGetCreatorTask – returns HTASK (pointer), not WORD */
FORWARD(mciGetCreatorTask, HTASK, (MCIDEVICEID IDDevice),
        (IDDevice))

/* mciGetDeviceIDFromElementIDA/W – first parameter is DWORD element ID */
FORWARD(mciGetDeviceIDFromElementIDA, MCIDEVICEID, (DWORD dwElementID, LPCSTR lpstrType),
        (dwElementID, lpstrType))
FORWARD(mciGetDeviceIDFromElementIDW, MCIDEVICEID, (DWORD dwElementID, LPCWSTR lpstrType),
        (dwElementID, lpstrType))

/* mciLoadCommandResource – returns UINT, takes LPCWSTR */
FORWARD(mciLoadCommandResource, UINT, (HANDLE hInstance, LPCWSTR lpResName, UINT wType),
        (hInstance, lpResName, wType))

/* Error‑text helpers (these are standard) */
FORWARD(midiInGetErrorTextA,  MMRESULT, (MMRESULT mmrError, LPSTR pszText, UINT cchText),
        (mmrError, pszText, cchText))
FORWARD(midiInGetErrorTextW,  MMRESULT, (MMRESULT mmrError, LPWSTR pszText, UINT cchText),
        (mmrError, pszText, cchText))
FORWARD(midiOutGetErrorTextA, MMRESULT, (MMRESULT mmrError, LPSTR pszText, UINT cchText),
        (mmrError, pszText, cchText))
FORWARD(midiOutGetErrorTextW, MMRESULT, (MMRESULT mmrError, LPWSTR pszText, UINT cchText),
        (mmrError, pszText, cchText))
FORWARD(waveInGetErrorTextA,  MMRESULT, (MMRESULT mmrError, LPSTR pszText, UINT cchText),
        (mmrError, pszText, cchText))
FORWARD(waveInGetErrorTextW,  MMRESULT, (MMRESULT mmrError, LPWSTR pszText, UINT cchText),
        (mmrError, pszText, cchText))
FORWARD(waveOutGetErrorTextA, MMRESULT, (MMRESULT mmrError, LPSTR pszText, UINT cchText),
        (mmrError, pszText, cchText))
FORWARD(waveOutGetErrorTextW, MMRESULT, (MMRESULT mmrError, LPWSTR pszText, UINT cchText),
        (mmrError, pszText, cchText))

/* Mixer W‑functions – use the correct structure types */
FORWARD(mixerGetLineControlsW, MMRESULT, (HMIXEROBJ hmxobj, LPMIXERLINECONTROLSW pmxlc, DWORD fdwControls),
        (hmxobj, pmxlc, fdwControls))
FORWARD(mixerGetLineInfoW,     MMRESULT, (HMIXEROBJ hmxobj, LPMIXERLINEW pmxl, DWORD fdwInfo),
        (hmxobj, pmxl, fdwInfo))
FORWARD(mixerMessage,          DWORD,    (HMIXER hmx, UINT uMsg, DWORD_PTR dwParam1, DWORD_PTR dwParam2),
        (hmx, uMsg, dwParam1, dwParam2))

/* midiStreamProperty – second parameter is LPBYTE */
FORWARD(midiStreamProperty, MMRESULT, (HMIDISTRM hms, LPBYTE lppropdata, DWORD dwProperty),
        (hms, lppropdata, dwProperty))

/* mmioDescend / mmioSetInfo – correct types */
FORWARD(mmioDescend,  MMRESULT, (HMMIO hmmio, LPMMCKINFO pmmcki, const MMCKINFO *pmmckiParent, UINT fuDescend),
        (hmmio, pmmcki, pmmckiParent, fuDescend))
FORWARD(mmioSetInfo,  MMRESULT, (HMMIO hmmio, LPCMMIOINFO pmmioinfo, UINT fuInfo),
        (hmmio, pmmioinfo, fuInfo))

/* mmTaskCreate – leave commented out, Radmin VPN never calls it */
// FORWARD(mmTaskCreate, UINT, (LPTASKCALLBACK lpfn, DWORD_PTR dwInst, DWORD_PTR dwParam),
//         (lpfn, dwInst, dwParam))


FORWARD(midiConnect,      MMRESULT, (HMIDI hmi, HMIDIOUT hmo, LPVOID pReserved), (hmi, hmo, pReserved))
FORWARD(midiDisconnect,   MMRESULT, (HMIDI hmi, HMIDIOUT hmo, LPVOID pReserved), (hmi, hmo, pReserved))
FORWARD(mmioSendMessage,  LRESULT,  (HMMIO hmmio, UINT uMsg, LPARAM lParam1, LPARAM lParam2), (hmmio, uMsg, lParam1, lParam2))

// -------- Injection entry called from DllMain ----------
void run_injection(void);   // from inject.c

// -------- DllMain ----------
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        char sysPath[MAX_PATH];
        GetSystemDirectoryA(sysPath, MAX_PATH);
        strcat_s(sysPath, MAX_PATH, "\\winmm.dll");
        g_hRealWinMM = LoadLibraryA(sysPath);
        if (!g_hRealWinMM) {
            MessageBoxA(NULL, "Failed to load real winmm.dll!", "Proxy Error", MB_OK);
            return FALSE;
        }
        run_injection();
    }
    else if (fdwReason == DLL_PROCESS_DETACH) {
        if (g_hRealWinMM) FreeLibrary(g_hRealWinMM);
    }
    return TRUE;
}