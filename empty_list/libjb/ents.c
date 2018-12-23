/*
 *  in-kernel entitlements
 *
 *  Copyright (c) 2017 xerub
 */


#include <CommonCrypto/CommonDigest.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const int offsetof_p_textvp = 0x248;		/* proc::p_textvp */
static const int offsetof_vu_ubcinfo = 0x78;		/* vnode::v_un::vu_ubcinfo */
static const int offsetof_cs_blobs = 0x50;		/* ubc_info::cs_blobs */
static const int offsetof_csb_cd = 0x80;		/* cs_blob::csb_cd */
static const int offsetof_csb_entitlements_blob = 0x90;	/* cs_blob::csb_entitlements_blob */

size_t kread(uint64_t where, void *p, size_t size);
uint32_t kread_uint32(uint64_t where);
uint64_t kread_uint64(uint64_t where);
size_t kwrite(uint64_t where, const void *p, size_t size);

#define CS_OPS_ENTITLEMENTS_BLOB 7	/* get entitlements blob */

int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

#define SWAP32(p) __builtin_bswap32(p)

/*
 * Magic numbers used by Code Signing
 */
enum {
	CSMAGIC_REQUIREMENT	= 0xfade0c00,		/* single Requirement blob */
	CSMAGIC_REQUIREMENTS = 0xfade0c01,		/* Requirements vector (internal requirements) */
	CSMAGIC_CODEDIRECTORY = 0xfade0c02,		/* CodeDirectory blob */
	CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0, /* embedded form of signature data */
	CSMAGIC_DETACHED_SIGNATURE = 0xfade0cc1, /* multi-arch collection of embedded signatures */
	
	CSSLOT_CODEDIRECTORY = 0,				/* slot index for CodeDirectory */
	CSSLOT_ENTITLEMENTS = 5,
};

typedef struct __SC_GenericBlob {
	uint32_t magic;					/* magic number */
	uint32_t length;				/* total length of blob */
	char data[];
} CS_GenericBlob;

/*
 * C form of a CodeDirectory.
 */
typedef struct __CodeDirectory {
	uint32_t magic;					/* magic number (CSMAGIC_CODEDIRECTORY) */
	uint32_t length;				/* total length of CodeDirectory blob */
	uint32_t version;				/* compatibility version */
	uint32_t flags;					/* setup and mode flags */
	uint32_t hashOffset;			/* offset of hash slot element at index zero */
	uint32_t identOffset;			/* offset of identifier string */
	uint32_t nSpecialSlots;			/* number of special hash slots */
	uint32_t nCodeSlots;			/* number of ordinary (code) hash slots */
	uint32_t codeLimit;				/* limit to main image signature range */
	uint8_t hashSize;				/* size of each hash in bytes */
	uint8_t hashType;				/* type of hash (cdHashType* constants) */
	uint8_t spare1;					/* unused (must be zero) */
	uint8_t	pageSize;				/* log2(page size in bytes); 0 => infinite */
	uint32_t spare2;				/* unused (must be zero) */
	/* followed by dynamic content as located by offset fields above */
} CS_CodeDirectory;

int
entitle(uint64_t proc, const char *ent, int verbose)
{
    int rv;
    CS_CodeDirectory cdir;
    CS_GenericBlob *blob;
    unsigned char buf[32];
    unsigned char digest[32];
    uint32_t length, newlen;
    uint64_t cdir_off, blob_off, off;

    off = kread_uint64(proc + offsetof_p_textvp);
    off = kread_uint64(off + offsetof_vu_ubcinfo);
    off = kread_uint64(off + offsetof_cs_blobs);

    cdir_off = kread_uint64(off + offsetof_csb_cd);
    blob_off = kread_uint64(off + offsetof_csb_entitlements_blob);
    kread(cdir_off, &cdir, sizeof(cdir));

    if (SWAP32(cdir.magic) != CSMAGIC_CODEDIRECTORY) {
        printf("bad magic\n");
        return -1;
    }

    length = SWAP32(kread_uint32(blob_off + 4));
    if (length < 8) {
        printf("bad length\n");
        return -1;
    }

    blob = malloc(length);
    if (!blob) {
        printf("no memory\n");
        return -1;
    }

    kread(blob_off, blob, length);

    if (verbose) {
        printf("blob[%d]: {%.*s}\n", length, length - 8, blob->data);
    }

    off = cdir_off + SWAP32(cdir.hashOffset) - CSSLOT_ENTITLEMENTS * cdir.hashSize;
    kread(off, buf, sizeof(buf));

    CC_SHA256(blob, length, digest);
    if (memcmp(buf, digest, sizeof(digest))) {
        printf("bad SHA2\n");
        free(blob);
        return -1;
    }

    newlen = snprintf(blob->data, length - 8,
"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
"<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
"<plist version=\"1.0\">\n"
"<dict>\n"
"%s\n"
"</dict>\n"
"</plist>\n", ent);

    if (newlen >= length - 8) {
        printf("too long\n");
        free(blob);
        return -1;
    }

    CC_SHA256(blob, length, digest);

    kwrite(off, digest, sizeof(digest));
    kwrite(blob_off, blob, length);

    rv = csops(getpid(), CS_OPS_ENTITLEMENTS_BLOB, blob, length);
    if (rv) {
        printf("bad blob\n");
    } else if (verbose) {
        printf("blob: {%.*s}\n", length - 8, blob->data);
    }
    free(blob);
    return rv;
}
