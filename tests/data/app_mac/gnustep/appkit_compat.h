/*
 * Syntax check of src/mac on Linux: what GNUstep (0.30) lacks of the macOS 10.13..11 SDK,
 * declarations only, with the signatures of Apple's headers. Force-included before each
 * src/mac/*.m by tests/cases/app_mac.py; never part of a build.
 */
#ifdef __OBJC__
#import <Cocoa/Cocoa.h>
#import <dispatch/dispatch.h>
#import <CoreServices/CoreServices.h>

/* clang's literals instead of GNUstep's "#define YES 1" (@YES must stay a literal) */
#undef YES
#undef NO
#define YES __objc_yes
#define NO __objc_no

/* constants under their 10.12 / 10.13 names */
#define NSAlertStyleWarning NSWarningAlertStyle
#define NSAlertStyleInformational NSInformationalAlertStyle
#define NSAlertStyleCritical NSCriticalAlertStyle
#define NSProgressIndicatorStyleBar NSProgressIndicatorBarStyle
#define NSEventTypeApplicationDefined NSApplicationDefined
#define NSEventModifierFlagCommand NSCommandKeyMask
#define NSEventModifierFlagOption NSAlternateKeyMask
#define NSEventModifierFlagControl NSControlKeyMask
#define NSEventModifierFlagDeviceIndependentFlagsMask NSDeviceIndependentModifierFlagsMask
#define NSCompositingOperationSourceOver NSCompositeSourceOver
#define NSBezelStyleRecessed NSRecessedBezelStyle
extern NSString *const NSPasteboardTypeFileURL;
extern NSString *const NSPasteboardURLReadingFileURLsOnlyKey;
extern NSString *const NSApplicationLaunchIsDefaultLaunchKey;
extern NSString *const NSAboutPanelOptionApplicationName;
extern NSString *const NSAboutPanelOptionApplicationVersion;
extern NSString *const NSAboutPanelOptionVersion;
extern NSString *const NSAboutPanelOptionCredits;
extern NSString *const NSAboutPanelOptionApplicationIcon;
typedef NS_ENUM(NSInteger, NSTableViewStyle) { NSTableViewStyleAutomatic, NSTableViewStyleFullWidth,
                                              NSTableViewStyleInset, NSTableViewStyleSourceList, NSTableViewStylePlain };
typedef NS_ENUM(NSInteger, NSWindowToolbarStyle) { NSWindowToolbarStyleAutomatic, NSWindowToolbarStyleExpanded };

/* CoreGraphics */
#define kCGColorSpaceSRGB ((CFStringRef)0)
typedef struct CGColorSpace *CGColorSpaceRef;
typedef struct CGDataProvider *CGDataProviderRef;
typedef struct CGImage *CGImageRef;
typedef uint32_t CGBitmapInfo;
enum { kCGImageAlphaPremultipliedFirst = 2, kCGBitmapByteOrder32Little = 2 << 12 };
enum { kCGRenderingIntentDefault = 0 };
CGColorSpaceRef CGColorSpaceCreateWithName(CFStringRef name);
void CGColorSpaceRelease(CGColorSpaceRef);
CGDataProviderRef CGDataProviderCreateWithCFData(CFDataRef);
void CGDataProviderRelease(CGDataProviderRef);
CGImageRef CGImageCreate(size_t w, size_t h, size_t bpc, size_t bpp, size_t bpr, CGColorSpaceRef cs, CGBitmapInfo bi,
                         CGDataProviderRef dp, const CGFloat *decode, bool interpolate, int intent);
void CGImageRelease(CGImageRef);
id CFBridgingRelease(CFTypeRef X);

/* classes and protocols */
@protocol NSSplitViewDelegate <NSObject>
@end
@protocol NSFilePromiseProviderDelegate;
@interface NSFilePromiseProvider : NSObject <NSPasteboardWriting>
- (instancetype)initWithFileType:(NSString *)fileType delegate:(id<NSFilePromiseProviderDelegate>)delegate;
@property (copy) NSString *fileType;
@property (weak) id<NSFilePromiseProviderDelegate> delegate;
@property (strong) id userInfo;
@end
@protocol NSFilePromiseProviderDelegate <NSObject>
- (NSString *)filePromiseProvider:(NSFilePromiseProvider *)filePromiseProvider fileNameForType:(NSString *)fileType;
- (void)filePromiseProvider:(NSFilePromiseProvider *)filePromiseProvider writePromiseToURL:(NSURL *)url
          completionHandler:(void (^)(NSError *errorOrNil))completionHandler;
@optional
- (NSOperationQueue *)operationQueueForFilePromiseProvider:(NSFilePromiseProvider *)filePromiseProvider;
@end
@interface NSTableCellView : NSView
@property (strong) NSTextField *textField;
@property (strong) NSImageView *imageView;
@end

/* methods and properties (GNUstep often has the method but not the property) */
@interface NSWindow (GZCompat)
@property (readonly, getter=isVisible) BOOL visible;
@property (getter=isReleasedWhenClosed) BOOL releasedWhenClosed;
@property (copy) NSURL *representedURL;
@property NSWindowToolbarStyle toolbarStyle;
- (void)beginSheet:(NSWindow *)sheet completionHandler:(void (^)(NSModalResponse returnCode))handler;
- (void)endSheet:(NSWindow *)sheet returnCode:(NSModalResponse)returnCode;
@end
@interface NSApplication (GZCompat)
@property (strong) NSMenu *helpMenu;
- (BOOL)setActivationPolicy:(NSApplicationActivationPolicy)activationPolicy;
@end
@interface NSAlert (GZCompat)
@property (strong) NSView *accessoryView;
@property (readonly, strong) NSWindow *window;
@property BOOL showsSuppressionButton;
@property (readonly, strong) NSButton *suppressionButton;
- (void)layout;
- (void)beginSheetModalForWindow:(NSWindow *)sheetWindow completionHandler:(void (^)(NSModalResponse returnCode))handler;
@end
@interface NSTextField (GZCompat)
+ (instancetype)labelWithString:(NSString *)stringValue;
+ (instancetype)wrappingLabelWithString:(NSString *)stringValue;
+ (instancetype)textFieldWithString:(NSString *)stringValue;
@property NSLineBreakMode lineBreakMode;
@property CGFloat preferredMaxLayoutWidth;
@end
@interface NSButton (GZCompat)
+ (instancetype)buttonWithTitle:(NSString *)title target:(id)target action:(SEL)action;
+ (instancetype)buttonWithImage:(NSImage *)image target:(id)target action:(SEL)action;
+ (instancetype)checkboxWithTitle:(NSString *)title target:(id)target action:(SEL)action;
+ (instancetype)radioButtonWithTitle:(NSString *)title target:(id)target action:(SEL)action;
@property NSControlSize controlSize;
@end
@interface NSView (GZCompat)
@property BOOL translatesAutoresizingMaskIntoConstraints;
@property (readonly) NSSize fittingSize;
@property (getter=isHidden) BOOL hidden;
@property (copy) NSString *identifier;
@property (readonly) NSLayoutXAxisAnchor *leadingAnchor, *trailingAnchor, *centerXAnchor;
@property (readonly) NSLayoutYAxisAnchor *topAnchor, *bottomAnchor, *centerYAnchor;
@property (readonly) NSLayoutDimension *widthAnchor, *heightAnchor;
- (void)setContentCompressionResistancePriority:(NSLayoutPriority)priority
                                 forOrientation:(NSLayoutConstraintOrientation)orientation;
- (void)setContentHuggingPriority:(NSLayoutPriority)priority forOrientation:(NSLayoutConstraintOrientation)orientation;
@end
@interface NSImageView (GZCompat)
+ (instancetype)imageViewWithImage:(NSImage *)image;
@end
@interface NSImage (GZCompat)
+ (instancetype)imageWithSize:(NSSize)size flipped:(BOOL)drawingHandlerShouldBeCalledWithFlippedContext
               drawingHandler:(BOOL (^)(NSRect dstRect))drawingHandler;
@property (getter=isTemplate) BOOL template;
@end
@interface NSBitmapImageRep (GZCompat)
- (instancetype)initWithCGImage:(CGImageRef)cgImage;
@end
@interface NSFont (GZCompat)
+ (NSFont *)monospacedDigitSystemFontOfSize:(CGFloat)fontSize weight:(NSFontWeight)weight;
+ (NSFont *)systemFontOfSize:(CGFloat)fontSize weight:(NSFontWeight)weight;
@end
@interface NSPasteboard (GZCompat)
- (NSArray *)readObjectsForClasses:(NSArray<Class> *)classArray options:(NSDictionary *)options;
@end
@interface NSTableView (GZCompat)
@property NSTableViewStyle style;
- (id)makeViewWithIdentifier:(NSUserInterfaceItemIdentifier)identifier owner:(id)owner;
@end
@interface NSTableColumn (GZCompat)
@property (copy) NSString *title;
@end
@interface NSProgressIndicator (GZCompat)
@property (getter=isIndeterminate) BOOL indeterminate;
@end
@interface NSBox (GZCompat)
@property (strong) __kindof NSView *contentView;
@end
@interface NSMenu (GZCompat)
- (BOOL)popUpMenuPositioningItem:(NSMenuItem *)item atLocation:(NSPoint)location inView:(NSView *)view;
- (void)removeAllItems;
@end
@interface NSOperationQueue (GZCompat)
@property NSQualityOfService qualityOfService;
@end
@interface NSFileManager (GZCompat)
- (NSArray<NSURL *> *)URLsForDirectory:(NSSearchPathDirectory)directory inDomains:(NSSearchPathDomainMask)domainMask;
@end
@interface NSString (GZCompat)
@property (readonly, getter=isAbsolutePath) BOOL absolutePath;
@end
#endif
