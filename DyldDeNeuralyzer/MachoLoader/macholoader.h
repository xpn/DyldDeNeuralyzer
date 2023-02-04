//
//  macholoader.h
//  DyldDeNeuralyzer
//
//  Created by Adam Chester on 17/01/2023.
//

#ifndef macholoader_h
#define macholoader_h

typedef void entryfunc(void);

struct section_info {
    uint64 addr;
    uint64 size;
};

struct segment_info {
    uint64 addr;
    uint64 size;
};

@interface MachoLoader :NSObject
-(void) loadMachoBundle: (NSString *)filename;
-(void) loadMachoBundleFromMemory: (NSData *)memory withEntryPoint: (NSString *)name;
@end

@interface Symbol :NSObject
@property NSString *section;

@end

#endif /* macholoader_h */
