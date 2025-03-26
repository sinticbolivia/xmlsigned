#include <libxml/valid.h>
#include <libxml/xmlstring.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#ifndef XMLSEC_NO_XSLT
#include <libxslt/xslt.h>
#include <libxslt/security.h>
#endif /* XMLSEC_NO_XSLT */

#include <xmlsec/xmlsec.h>
#include <xmlsec/transforms.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/templates.h>
#include <xmlsec/crypto.h>

#define CLEANUP_XML_PROCESS(dsigCtx, doc) if(dsigCtx != NULL) {xmlSecDSigCtxDestroy(dsigCtx);} if( doc != NULL ) {xmlFreeDoc(doc);}

#ifndef XMLSEC_NO_XSLT
xsltSecurityPrefsPtr xsltSecPrefs = NULL;
#endif /* XMLSEC_NO_XSLT */

int xmlsec_init()
{
    /* Init libxml and libxslt libraries */
    xmlInitParser();
    LIBXML_TEST_VERSION
    xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
    xmlSubstituteEntitiesDefault(1);
    #ifndef XMLSEC_NO_XSLT
    xmlIndentTreeOutput = 1;
    #endif /* XMLSEC_NO_XSLT */
    /* Init libxslt */
    #ifndef XMLSEC_NO_XSLT
    /* disable everything */
    xsltSecPrefs = xsltNewSecurityPrefs();
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_READ_FILE,        xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_WRITE_FILE,       xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_CREATE_DIRECTORY, xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_READ_NETWORK,     xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_WRITE_NETWORK,    xsltSecurityForbid);
    xsltSetDefaultSecurityPrefs(xsltSecPrefs);
    #endif /* XMLSEC_NO_XSLT */
    /* Init xmlsec library */
    if(xmlSecInit() < 0)
    {
        fprintf(stderr, "Error: xmlsec initialization failed.\n");
        return(-1);
    }
    /* Check loaded library version */
    if(xmlSecCheckVersion() != 1)
    {
        fprintf(stderr, "Error: loaded xmlsec library version is not compatible.\n");
        return(-1);
    }
    /* Load default crypto engine if we are supporting dynamic
     * loading for xmlsec-crypto libraries. Use the crypto library
     * name ("openssl", "nss", etc.) to load corresponding
     * xmlsec-crypto library.
     */
    #ifdef XMLSEC_CRYPTO_DYNAMIC_LOADING
    if(xmlSecCryptoDLLoadLibrary(NULL) < 0) {
        fprintf(stderr, "Error: unable to load default xmlsec-crypto library. Make sure\n"
                        "that you have it installed and check shared libraries path\n"
                        "(LD_LIBRARY_PATH and/or LTDL_LIBRARY_PATH) environment variables.\n");
        return(-1);
    }
    #endif /* XMLSEC_CRYPTO_DYNAMIC_LOADING */

    /* Init crypto library */
    if(xmlSecCryptoAppInit(NULL) < 0) {
        fprintf(stderr, "Error: crypto initialization failed.\n");
        return(-1);
    }

    /* Init xmlsec-crypto library */
    if(xmlSecCryptoInit() < 0) {
        fprintf(stderr, "Error: xmlsec-crypto initialization failed.\n");
        return(-1);
    }
    return 0;
}
void xmlsec_shutdown()
{
    /* Shutdown xmlsec-crypto library */
    xmlSecCryptoShutdown();
    /* Shutdown crypto library */
    xmlSecCryptoAppShutdown();
    /* Shutdown xmlsec library */
    xmlSecShutdown();
    /* Shutdown libxslt/libxml */
    #ifndef XMLSEC_NO_XSLT
    xsltFreeSecurityPrefs(xsltSecPrefs);
    xsltCleanupGlobals();
    #endif /* XMLSEC_NO_XSLT */
    xmlCleanupParser();
}
/**
 * sign_file:
 * @tmpl_file:          the signature template file name.
 * @key_file:           the PEM private key file name.
 *
 * Signs the #tmpl_file using private key from #key_file.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int xmlsec_sign_file(const char* tmpl_file, const char* key_file, const char* cert_file, xmlChar** signed_xml)
{
    xmlDocPtr doc = NULL;
    xmlNodePtr signNode = NULL;
    xmlNodePtr refNode = NULL;
    xmlNodePtr keyInfoNode = NULL;
    xmlNodePtr x509DataNode = NULL;
    xmlSecDSigCtxPtr dsigCtx = NULL;
    assert(tmpl_file);
    assert(key_file);
    assert(cert_file);

    doc = xmlReadFile(tmpl_file, NULL, XML_PARSE_PEDANTIC | XML_PARSE_NONET);
    if( doc == NULL || xmlDocGetRootElement(doc) == NULL )
    {
        fprintf(stderr, "Error: unable to parse file \"%s\"\n", tmpl_file);
        CLEANUP_XML_PROCESS(dsigCtx, doc)
        return -1;
    }
    signNode = xmlSecTmplSignatureCreate(doc,
        //xmlSecTransformExclC14N,
        xmlSecTransformExclC14NWithCommentsId,
        //xmlSecTransformRsaSha1Id,
        xmlSecTransformRsaSha256Id,
        NULL
    );
    if(signNode == NULL)
    {
        fprintf(stderr, "Error: failed to create signature template\n");
        CLEANUP_XML_PROCESS(dsigCtx, doc)
        return -1;
    }
    /* add <dsig:Signature/> node to the doc */
    xmlAddChild(xmlDocGetRootElement(doc), signNode);
    /* add reference */
    refNode = xmlSecTmplSignatureAddReference(
        signNode,
        //xmlSecTransformSha1Id,
        xmlSecTransformSha256Id,
        NULL,
        "",
        NULL
    );
    if(refNode == NULL)
    {
        fprintf(stderr, "Error: failed to add reference to signature template\n");
        CLEANUP_XML_PROCESS(dsigCtx, doc)
        return -1;
    }
    /* add enveloped transform */
    if( xmlSecTmplReferenceAddTransform(refNode, xmlSecTransformEnvelopedId) == NULL )
    {
        fprintf(stderr, "Error: failed to add enveloped transform to reference\n");
        CLEANUP_XML_PROCESS(dsigCtx, doc)
        return -1;
    }
    /* add <dsig:KeyInfo/> and <dsig:X509Data/> */
    keyInfoNode = xmlSecTmplSignatureEnsureKeyInfo(signNode, NULL);
    if(keyInfoNode == NULL)
    {
        fprintf(stderr, "Error: failed to add key info\n");
        CLEANUP_XML_PROCESS(dsigCtx, doc)
        return -1;
    }
    x509DataNode = xmlSecTmplKeyInfoAddX509Data(keyInfoNode);
    if(x509DataNode == NULL)
    {
        fprintf(stderr, "Error: failed to add X509Data node\n");
        CLEANUP_XML_PROCESS(dsigCtx, doc)
        return -1;
    }
    /*
    if(xmlSecTmplX509DataAddSubjectName(x509DataNode) == NULL)
    {
        fprintf(stderr, "Error: failed to add X509SubjectName node\n");
        CLEANUP_XML_PROCESS(dsigCtx, doc)
        return -1;
    }
    */
    if(xmlSecTmplX509DataAddCertificate(x509DataNode) == NULL)
    {
        fprintf(stderr, "Error: failed to add X509Certificate node\n");
        CLEANUP_XML_PROCESS(dsigCtx, doc)
        return -1;
    }
    /* create signature context, we don't need keys manager in this example */
    dsigCtx = xmlSecDSigCtxCreate(NULL);
    if(dsigCtx == NULL)
    {
        fprintf(stderr,"Error: failed to create signature context\n");
        CLEANUP_XML_PROCESS(dsigCtx, doc)
        return -1;
    }
    /* load private key, assuming that there is not password */
    dsigCtx->signKey = xmlSecCryptoAppKeyLoadEx(
        key_file,
        xmlSecKeyDataTypePrivate,
        xmlSecKeyDataFormatPem,
        NULL,
        NULL,
        NULL
    );
    if(dsigCtx->signKey == NULL)
    {
        fprintf(stderr,"Error: failed to load private pem key from \"%s\"\n", key_file);
        CLEANUP_XML_PROCESS(dsigCtx, doc)
        return -1;
    }
    /* load certificate and add to the key */
    if(xmlSecCryptoAppKeyCertLoad(dsigCtx->signKey, cert_file, xmlSecKeyDataFormatPem) < 0)
    {
        fprintf(stderr,"Error: failed to load pem certificate \"%s\"\n", cert_file);
        CLEANUP_XML_PROCESS(dsigCtx, doc)
        return -1;
    }

    /* set key name to the file name, this is just an example! */
    //*
    if(xmlSecKeySetName(dsigCtx->signKey, BAD_CAST key_file) < 0)
    {
        fprintf(stderr,"Error: failed to set key name for key from \"%s\"\n", key_file);
        CLEANUP_XML_PROCESS(dsigCtx, doc)
        return -1;
    }
    //*/
    /* sign the template */
    if(xmlSecDSigCtxSign(dsigCtx, signNode) < 0)
    {
        fprintf(stderr,"Error: signature failed\n");
        CLEANUP_XML_PROCESS(dsigCtx, doc)
        return -1;
    }
    /* print signed document to stdout */
    //xmlDocDump(stdout, doc);
    //xmlChar *_signed_xml;
    int size = 0;
    xmlDocDumpMemory(doc, signed_xml, &size);
    //printf("SIGNED XML:\n%s\n", (char*)_signed_xml);
    //CLEANUP_XML_PROCESS(dsigCtx, doc)
    if(dsigCtx != NULL) {
        xmlSecDSigCtxDestroy(dsigCtx);
    }
    if(doc != NULL) {
        xmlFreeDoc(doc);
        //free(doc);
    }
    return 0;
}
