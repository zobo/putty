
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

struct capi_info {
	HCERTSTORE cstore;
	PCCERT_CONTEXT cert;
	struct RSAKey *key;
};


char *capi_getcomment(void *data)
{
	struct capi_info *ci = (struct capi_info *) data;
	return ci->key->comment;
}

/*
 * Open CertStore and finds cert or open dialog.
 */
static void *capi_newkey(const struct ssh_signkey *self,
	const char *data, int len)
{
	struct capi_info *ci;
    int nlen;
		
    ci = snew(struct capi_info);
    if (!ci)
		return NULL;
	memset(ci, 0, sizeof(struct capi_info));

	ci->key = snew(struct RSAKey); 
	if (!ci->key)
		goto fail;
	memset(ci->key, 0, sizeof(struct RSAKey));
	/* open cert store */
	ci->cstore = CertOpenStore(
		CERT_STORE_PROV_SYSTEM,
		0,
		(HCRYPTPROV_LEGACY)NULL,
		CERT_SYSTEM_STORE_CURRENT_USER,
		L"MY");
	if (!ci->cstore)
		goto fail;

	/* iscemo certifikat z dolocenim imenom */
	if (data)
		ci->cert = CertFindCertificateInStore(
			ci->cstore,
			(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING),
			0,
			CERT_FIND_SUBJECT_STR,
			data,
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
		ci->key->comment = strdup("Noname");
	else {
		ci->key->comment = snewn(nlen, char);
		CertGetNameString(
			ci->cert,
			CERT_NAME_SIMPLE_DISPLAY_TYPE,
			0,
			NULL,
			ci->key->comment,
			nlen);
	}
	/* polnjenje RSA strukture */
	{
		PCRYPT_BIT_BLOB cbb = &ci->cert->pCertInfo->SubjectPublicKeyInfo.PublicKey;
		unsigned char *p = cbb->pbData;
		unsigned int size;
		int i;
#define GET_SIZE(s) if (*p<0x80) s=(unsigned int)*p++; else {for(i=0x80, s=0; i<*p; i++) s = (s << 8) + p[i-0x7f]; p+=i-0x7f;}
		/* Tukaj se izlusci modulus in exponent, in se jih z bignum_from_bytes doda v ci->key*/
		if (*p++ != 0x30)
			goto fail; /* neki je hudo narobe z replayem.. ne zacne se na 0x30 */
		GET_SIZE(size);
		if (size > cbb->cbData)
			goto fail; /* spet problem v blobu */
		if (*p++ != 0x02)
			goto fail;
		GET_SIZE(size);
		ci->key->modulus = bignum_from_bytes(p, size);
		p += size;
		if (*p++ != 0x02)
			goto fail;
		GET_SIZE(size);
		ci->key->exponent = bignum_from_bytes(p, size);
#undef GET_SIZE
	}
    return ci;

fail:
	if (ci->key)
		freersakey(ci->key);
	if (ci->cert)
		CertFreeCertificateContext(ci->cert);
	if (ci->cstore)
		CertCloseStore(ci->cstore,CERT_CLOSE_STORE_FORCE_FLAG);
	sfree(ci);
	return NULL;
}

/*
 * Sprosti vse resourse
 */
static void capi_freekey(void *data)
{
    struct capi_info *ci = (struct capi_info *) data;
	if (ci->key)
		freersakey(ci->key);
	if(ci->cert)
		CertFreeCertificateContext(ci->cert);
	if(ci->cstore)
		CertCloseStore(ci->cstore,CERT_CLOSE_STORE_FORCE_FLAG);
    sfree(ci);
}

/*
 * Wraper za public blob
 */
static unsigned char *capi_public_blob(void *data, int *len)
{
	struct capi_info *ci = (struct capi_info *) data;
	return ssh_rsa.public_blob(ci->key, len);
}

/*
 * To podpise data.. Lahko samo upam, da ga podpisuje na pravi nacin.. sicer sem fucked!!
 */
static unsigned char *capi_sign(void *key, const char *data, int datalen,
				int *siglen)
{
    struct capi_info *ci = (struct capi_info *) key;
    unsigned char *bytes;
    int nbytes;
	unsigned char *tmpsig;
    unsigned char *tmpbytes;
	int tmpnbytes;
	int i;

	CRYPT_SIGN_MESSAGE_PARA   SignMessagePara;
	HCRYPTMSG hMsg;
	// Optional check?
	i = MessageBox(
			NULL,
			"Do you want to sign the request?",
			"Pageant - Sign request",
			MB_YESNO | MB_ICONQUESTION);
	if (i != IDYES)
		return NULL;
	// 

	memset(&SignMessagePara, 0, sizeof(CRYPT_SIGN_MESSAGE_PARA));
	SignMessagePara.cbSize = sizeof(CRYPT_SIGN_MESSAGE_PARA);
	SignMessagePara.HashAlgorithm.pszObjId = szOID_RSA_SHA1RSA;
	SignMessagePara.pSigningCert = ci->cert;
	SignMessagePara.dwMsgEncodingType = (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING);
	SignMessagePara.cMsgCert = 0;
	SignMessagePara.rgpMsgCert = NULL;
	
	if(CryptSignMessage(
			&SignMessagePara,
			TRUE,
			1,
			&data,
			&datalen,
			NULL,
			&tmpnbytes))
	{
		tmpbytes = snewn(tmpnbytes, unsigned char);
		if (!tmpbytes)
			return NULL;
	}
	else
		return NULL;
	if(!CryptSignMessage(
			&SignMessagePara,
			TRUE,
			1,
			&data,
			&datalen,
			tmpbytes,
			&tmpnbytes))
	{
		goto fail1;
	}
	/* imamo podpisano krneki */
	/* probamo dobit raw podpis */
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
		goto fail1;
	}
    CryptMsgClose(hMsg);

	// Od tu naprej se oblikuje razultat. V nbytes pride rezultat priv key op (128?)
    bytes = snewn(4 + 7 + 4 + nbytes, unsigned char);
    PUT_32BIT(bytes, 7);
    memcpy(bytes + 4, "ssh-rsa", 7);
    PUT_32BIT(bytes + 4 + 7, nbytes);
    for (i = 0; i < nbytes; i++)
	bytes[4 + 7 + 4 + i] = tmpsig[i];
    sfree(tmpsig);

    *siglen = 4 + 7 + 4 + nbytes;
    return bytes;

fail1:
		sfree(tmpbytes);
		return NULL;
}

const struct ssh_signkey ssh_capi = {
    capi_newkey,
    capi_freekey,
    NULL, /* fmtkey, */
    capi_public_blob,
    NULL, /* private_blob */
    NULL, /* createkey */
    NULL, /* openssh_createkey */
    NULL, /* openssh_fmtkey, */
	0,    /* openssh_private_npieces */
	NULL, /* pubkey_bits */
    NULL, /* verifysig */
    capi_sign,
    "ssh-rsa-capi",
    "rsa2",
	NULL
};