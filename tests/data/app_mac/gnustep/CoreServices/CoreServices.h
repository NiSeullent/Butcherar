/* syntax-check stub: the CoreFoundation / LaunchServices pieces src/mac uses */
#ifndef STUB_CORESERVICES_H
#define STUB_CORESERVICES_H
typedef const struct __CFString *CFStringRef;
typedef const void *CFTypeRef;
typedef const struct __CFData *CFDataRef;
typedef signed int OSStatus;
typedef unsigned int OSType;
typedef unsigned int LSRolesMask;
enum { noErr = 0 };
enum { kLSRolesAll = 0xFFFFFFFF };
enum { kGenericDocumentIcon = 0x646F6375 };
extern const CFStringRef kUTTagClassFilenameExtension;
CFStringRef UTTypeCreatePreferredIdentifierForTag(CFStringRef tagClass, CFStringRef tag, CFStringRef conformingToUTI);
CFStringRef UTTypeCopyDescription(CFStringRef uti);
unsigned char UTTypeIsDynamic(CFStringRef uti);
OSStatus LSSetDefaultRoleHandlerForContentType(CFStringRef contentType, LSRolesMask role, CFStringRef handlerBundleID);
void CFRelease(CFTypeRef cf);
#endif
