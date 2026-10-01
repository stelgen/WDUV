// defs.h — constants, signature file sets and the pinned source table.
#ifndef VDU_DEFS_H
#define VDU_DEFS_H

#include <stddef.h>

#define APP_NAME    "Vista Defender Updater"
#define APP_VERSION "3.0.0"

// Registry: HKLM\SOFTWARE\Microsoft\Windows Defender\Signatures
// Values "Antivirus"/"AntiSpyware" (REG_SZ) name the current definition
// subfolder under the Definition Updates directory.
#define DEF_REG_KEY      "SOFTWARE\\Microsoft\\Windows Defender\\Signatures"
#define DEF_REG_AV       "Antivirus"
#define DEF_REG_AS       "AntiSpyware"
#define DEF_SERVICE      "WinDefend"

#define DEF_FWLINK_URL   "https://go.microsoft.com/fwlink/?LinkID=121721"

// Signature file names.
#define FILE_MPAS_BASE   "mpasbase.vdm"
#define FILE_MPAS_DELTA  "mpasdlta.vdm"
#define FILE_MPAV_BASE   "mpavbase.vdm"
#define FILE_MPAV_DELTA  "mpavdlta.vdm"
#define FILE_ENGINE      "mpengine.dll"
#define FILE_SIGSTUB     "MpSigStub.exe"

// Backup folder (under the Definition Updates root's parent).
#define BACKUP_NAME      "vdu-backup"
#define BACKUP_MANIFEST  "manifest.json"

typedef struct {
    const char *name;     // short id for -source
    const char *url;      // download url
    const char *sha256;   // pinned package hash (NULL = not pinned)
    const char *engine;   // engine version measured inside the package
    const char *mpas;     // mpasdlta (definition) generation measured inside
    int         year;     // package era (informational)
    const char *note;     // what it is
} vdu_source;

// Ranked freshest-first. "current" follows Microsoft's fwlink (changes
// daily, therefore unpinned); the archive.org entries are frozen packages
// with measured engine/definition versions and pinned SHA-256.
static const vdu_source VDU_SOURCES[] = {
    { "current",
      DEF_FWLINK_URL,
      NULL,
      "1.1.26080.3", "1.459.497.0", 2026,
      "Microsoft fwlink: today's Security Intelligence Update (built for the modern Defender line)" },
    { "vista-x86-2019",
      "https://archive.org/download/mseinstall_202510/mpam-fe_vista_x86.exe",
      "90605061b7c5195b358e446b58097ff37765211953825d3d82d1211245f55087",
      "1.2.1009.0", "1.305.416.0", 2019,
      "Frozen package tagged for Windows Vista x86 (archive.org mseinstall_202510)" },
    { "win7-x86-2018",
      "https://archive.org/download/mpam-fe-x64/Win7PostInstall/x86/security_utilities/mpam-fe.exe",
      "5352acbcb7fead7196b2c37024a1dfa1f9968a186c63f601afa8f6c63b28c89f",
      "1.2.1009.0", "1.283.1902.0", 2018,
      "Windows 7 era antimalware package (archive.org mpam-fe-x64)" },
    { "xp-2016",
      "https://archive.org/download/mseWinXP/mpam-fe.exe",
      "62343aa538380445adba69661b0e4629c88f6d8720032e91f742c551a91f99c2",
      "1.2.1003.0", "1.225.2438.0", 2016,
      "April 2016 package (archive.org mseWinXP)" },
};
#define VDU_SOURCE_COUNT (sizeof(VDU_SOURCES) / sizeof(VDU_SOURCES[0]))

#endif
