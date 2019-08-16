
/*
 * RSA auth over CAPI and windows certificates for PuTTY.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <windows.h>
#include <WinCrypt.h>
#include <CryptuiAPI.h>

#include "ssh.h"
#include "misc.h"
#include "mpint.h"

struct capi_info {
	HCERTSTORE cstore;
	PCCERT_CONTEXT cert;
	RSAKey key;
	ssh_key sshk;
};
typedef struct capi_info capi_info;

const ssh_keyalg ssh_capi;

char *capi_getcomment(ssh_key *key)
{
	capi_info *ci = container_of(key, capi_info, sshk);
	return ci->key.comment;
}

/*
 * Open CertStore and finds cert or open dialog.
 */
static ssh_key *capi_newkey(const ssh_keyalg *self,	ptrlen data)
{
	struct capi_info *ci;
    int nlen;
		
    ci = snew(capi_info);
    if (!ci)
		return NULL;
	memset(ci, 0, sizeof(capi_info));
	ci->sshk.vt = &ssh_capi;

	/* open cert store */
	ci->cstore = CertOpenStore(
		CERT_STORE_PROV_SYSTEM,
		0,
		(HCRYPTPROV_LEGACY)NULL,
		CERT_SYSTEM_STORE_CURRENT_USER,
		L"MY");
	if (!ci->cstore)
		goto fail;

	/* searching for a cert with name */
	if (data.ptr)
		ci->cert = CertFindCertificateInStore(
			ci->cstore,
			(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING),
			0,
			CERT_FIND_SUBJECT_STR,
			data.ptr,
			NULL);
	else
		ci->cert = CryptUIDlgSelectCertificateFromStore(
			ci->cstore,
			NULL,
			NULL,
			NULL,
			CRYPTUI_SELECT_LOCATION_COLUMN,
			0,
			NULL);
	if (!ci->cert)
		goto fail;
	/* get size of name */
	nlen = CertGetNameString(
		ci->cert,
		CERT_NAME_SIMPLE_DISPLAY_TYPE,
		0,
		NULL,
		NULL,
		0);
	if (nlen == 1)
		ci->key.comment = strdup("Noname");
	else {
		ci->key.comment = snewn(nlen, char);
		CertGetNameString(
			ci->cert,
			CERT_NAME_SIMPLE_DISPLAY_TYPE,
			0,
			NULL,
			ci->key.comment,
			nlen);
	}
	/* fill the RSA struture */
	{
		PCRYPT_BIT_BLOB cbb = &ci->cert->pCertInfo->SubjectPublicKeyInfo.PublicKey;
		unsigned char *p = cbb->pbData;
		size_t size;
		int i;
#define GET_SIZE(s) if (*p<0x80) s=(unsigned int)*p++; else {for(i=0x80, s=0; i<*p; i++) s = (s << 8) + p[i-0x7f]; p+=i-0x7f;}
		/* Get modulus and exponent, user bignum_from_bytes to add to ci->key */
		if (*p++ != 0x30)
			goto fail; /* Something is very wrong... Does not begin with 0x30 */
		GET_SIZE(size);
		if (size > cbb->cbData)
			goto fail; /* blob problem */
		if (*p++ != 0x02)
			goto fail;
		GET_SIZE(size);

		ci->key.modulus = mp_from_bytes_be(make_ptrlen(p, size));
		p += size;
		if (*p++ != 0x02)
			goto fail;
		GET_SIZE(size);
		ci->key.exponent = mp_from_bytes_be(make_ptrlen(p, size));
#undef GET_SIZE
	}
    return &ci->sshk;

fail:
	freersakey(&ci->key);
	if (ci->cert)
		CertFreeCertificateContext(ci->cert);
	if (ci->cstore)
		CertCloseStore(ci->cstore,CERT_CLOSE_STORE_FORCE_FLAG);
	sfree(ci);
	return NULL;
}

/*
 * Release resources
 */
static void capi_freekey(ssh_key *key)
{
	capi_info *ci = container_of(key, capi_info, sshk);
	freersakey(&ci->key);
	if(ci->cert)
		CertFreeCertificateContext(ci->cert);
	if(ci->cstore)
		CertCloseStore(ci->cstore,CERT_CLOSE_STORE_FORCE_FLAG);
    sfree(ci);
}

/*
 * Public blob wrapper
 */
static void capi_public_blob(ssh_key *key, BinarySink *bs)
{
	capi_info *ci = container_of(key, capi_info, sshk);

	// copy from sshrsa.c
	put_stringz(bs, "ssh-rsa");
	put_mp_ssh2(bs, ci->key.exponent);
	put_mp_ssh2(bs, ci->key.modulus);
}

/*
 * Sign data
 */
static void capi_sign(ssh_key *key, ptrlen data, unsigned flags, BinarySink *bs)
{
	capi_info *ci = container_of(key, capi_info, sshk);
    size_t nbytes;
	unsigned char *tmpsig = 0;
    unsigned char *tmpbytes = 0;
	int tmpnbytes;
	int i;
	const char *sign_alg_name;

	CRYPT_SIGN_MESSAGE_PARA   SignMessagePara;
	HCRYPTMSG hMsg;

	// Optional check?
	i = MessageBox(
			NULL,
			"Do you want to sign the request?",
			"Pageant - Sign request",
			MB_YESNO | MB_ICONQUESTION);
	if (i != IDYES)
		return;
	// 
	memset(&SignMessagePara, 0, sizeof(CRYPT_SIGN_MESSAGE_PARA));
	SignMessagePara.cbSize = sizeof(CRYPT_SIGN_MESSAGE_PARA);

	if (flags & SSH_AGENT_RSA_SHA2_256) {
		sign_alg_name = "rsa-sha2-256";
		SignMessagePara.HashAlgorithm.pszObjId = szOID_RSA_SHA256RSA;
	} else if (flags & SSH_AGENT_RSA_SHA2_512) {
		sign_alg_name = "rsa-sha2-512";
		SignMessagePara.HashAlgorithm.pszObjId = szOID_RSA_SHA512RSA;
	} else {
		sign_alg_name = "ssh-rsa";
		SignMessagePara.HashAlgorithm.pszObjId = szOID_RSA_SHA1RSA;
	}

	SignMessagePara.pSigningCert = ci->cert;
	SignMessagePara.dwMsgEncodingType = (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING);
	SignMessagePara.cMsgCert = 0;
	SignMessagePara.rgpMsgCert = NULL;
	
	if (CryptSignMessage(
		&SignMessagePara,
		TRUE,
		1,
		(const BYTE **)&data.ptr,
		&data.len,
		NULL,
		&tmpnbytes))
	{
		tmpbytes = snewn(tmpnbytes, unsigned char);
		if (!tmpbytes)
			return;
	}
	else
		return;
	if(!CryptSignMessage(
			&SignMessagePara,
			TRUE,
			1,
			(const BYTE **)&data.ptr,
			&data.len,
			tmpbytes,
			&tmpnbytes))
	{
		goto fail1;
	}
	/* We have a signed bytes, now decode into raw signature */
	hMsg = CryptMsgOpenToDecode(
				(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING),
				CMSG_DETACHED_FLAG,
				0,
				(HCRYPTPROV_LEGACY)NULL,
				NULL,
				NULL);
	if (!hMsg) {
		goto fail1;
	}
	
	if(!CryptMsgUpdate(
		hMsg,
		tmpbytes,
		tmpnbytes,
		TRUE))
	{
		goto fail1;
	}
	
	if(!CryptMsgGetParam(
		hMsg,
		CMSG_ENCRYPTED_DIGEST,
		0,
		NULL,
		&nbytes))
	{
		goto fail1;
	}
	tmpsig = snewn(nbytes, unsigned char);
	if (!tmpsig)
		goto fail1;
	if(!CryptMsgGetParam(
		hMsg,
		CMSG_ENCRYPTED_DIGEST,
		0,
		tmpsig,
		&nbytes))
	{
		sfree(tmpsig);
		tmpsig = NULL;
		goto fail1;
	}
    CryptMsgClose(hMsg);

	put_stringz(bs, sign_alg_name);
	put_uint32(bs, nbytes);

	for (size_t i = 0; i < nbytes; i++)
		put_byte(bs, tmpsig[i]);

fail1:
	if (tmpbytes)
		sfree(tmpbytes);
	if (tmpsig)
		sfree(tmpsig);
}

char *capi_invalid(ssh_key *key, unsigned flags)
{
	capi_info *ci = container_of(key, capi_info, sshk);
	// todo
	if (flags != 0 && flags != SSH_AGENT_RSA_SHA2_256 && flags != SSH_AGENT_RSA_SHA2_512) {
		return dupprintf("unknown flags for capi: %x", flags);
	}
	return NULL;
}

const ssh_keyalg ssh_capi = {
	capi_newkey, /* new_pub */
	NULL, /* new_priv */
	NULL, /* new_priv_openssh */
	capi_freekey, /* freekey */
	capi_invalid, /* invalid */
	capi_sign, /* sign */
	NULL, /* verify */
	capi_public_blob, /* public_blob */
	NULL, /* private_blob */
	NULL, /* openssh_blob */
	NULL, /* cache_str */
	NULL, /* pubkey_bits */
	"ssh-rsa-capi", /* ssh_id */
	"rsa2", /* cache_id */
	NULL, /* extra */
	SSH_AGENT_RSA_SHA2_256 | SSH_AGENT_RSA_SHA2_512,
};