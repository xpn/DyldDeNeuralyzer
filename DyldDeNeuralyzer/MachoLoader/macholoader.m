#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/fixup-chains.h>
#include <mach/mach.h>
#include <sys/mman.h>
#include <mach-o/nlist.h>
#include <dlfcn.h>
#include <ptrauth.h>

#include "macholoader.h"
#include "queue.h"

#define VMADDR(x) (baseAlloc + x)

@implementation MachoLoader

// Base vmaddr we will load the mach-o into
void *baseAlloc;
void *indirectSymbols;

NSPointerArray *segments;
NSMutableDictionary *sections;
NSPointerArray *commands;
NSMutableArray *dylds;
NSMutableDictionary *symbols;
NSPointerArray *orderedSymbols;

/// Store section information for lookup later
- (void) storeSectionInfo: (const char *)name withStart: (int64_t)start andSize: (int64_t)size {
    struct section_info *info;
    char nameTruncated[17];
    
    // Fix names which take up the full 16 bytes
    memset(nameTruncated, 0, sizeof(nameTruncated));
    memcpy(nameTruncated, name, 16);
    
    info = (struct section_info *)malloc(sizeof(struct section_info));
    info->size = size;
    info->addr = start;
    sections[@(nameTruncated)] = [NSValue valueWithPointer:info];
}

/// Allows iteration of each section
- (void) foreachSection:(void (^)(NSString *name, struct section_info *info)) sectionCallback {
    [sections enumerateKeysAndObjectsUsingBlock: ^(id key, id obj, BOOL *stop) {
        sectionCallback(key, [obj pointerValue]);
    }];
}

/// Process a section64 load command
- (void) handleSection64: (struct section_64 *)section fromSegment: (struct segment_command_64 *)segment withBase: (unsigned char *)base {
    kern_return_t ret;
    void *sectionLoadAddr = 0;
    
    printf("\t[*] Section Name: %s\n", section->sectname);
    
    switch(section->flags & 0xFF) {
        case S_SYMBOL_STUBS:
            printf("\t[*] Section contains stubs\n");
            break;
    }
    
    [self storeSectionInfo:section->sectname withStart:section->addr andSize:section->size];
    
    sectionLoadAddr = VMADDR(section->addr);
    
    // Update the memory protection so we can copy over the data for this section
    ret = vm_protect(mach_task_self(), (vm_address_t)sectionLoadAddr, section->size, false, PROT_READ | PROT_WRITE);
    if (ret != 0) {
        printf("\t[!] Error during vm_protect: %d\n", ret);
    }
    
    memcpy(sectionLoadAddr, base + section->offset, section->size);
    
    // Reset memory protection to the segment
    ret = vm_protect(mach_task_self(), (vm_address_t)sectionLoadAddr, section->size, false, segment->initprot);
    if (ret != 0) {
        printf("\t[!] Error during vm_protect: %d\n", ret);
    }
}

/// Process a segment64 load command
- (void) handleLoadCommandSegment64: (struct segment_command_64 *)segment withBase: (unsigned char *)base {
    kern_return_t ret;
    void *loadAddr = 0;
    struct section_64 *section_64;
    
    printf("\t[*] Segment Name: %s\n", segment->segname);
    printf("\t[*] Address: %llx\n", segment->vmaddr);
    printf("\t[*] Size: %llx\n", segment->vmsize);
    printf("\t[*] Number of sections: %d\n", segment->nsects);
    
    loadAddr = VMADDR(segment->vmaddr);
    
    memcpy(loadAddr, base + segment->fileoff, segment->filesize);
    
    ret = vm_protect(mach_task_self(), (vm_address_t)VMADDR(segment->vmaddr), segment->vmsize, false, segment->initprot);
    if (ret != 0) {
        printf("\t[!] Error during vm_protect: %d\n", ret);
    }
    
    printf("\t[*] Loaded segment to address: %p\n", loadAddr);
    
    // Now process each section appended to the segment
    section_64 = (struct section_64 *)((char *)segment + sizeof(struct segment_command_64));
    
    for(int i=0; i < segment->nsects; i++) {
        [self handleSection64:&section_64[i] fromSegment: segment withBase:base];
    }
}

/// Process a dylib load command
- (void) handleLoadCommandLoadDylib: (struct dylib_command *)dylib withBase: (unsigned char *)base {
    printf("\t[*] Dylib Path: %s\n", (char *)dylib + dylib->dylib.name.offset);
    
    char *dyldName = (char *)dylib + dylib->dylib.name.offset;
    
    [dylds addObject:@(dyldName)];
}

/// Process a symtab load command
- (void) handleLoadCommandSymTab: (struct symtab_command *)symtab withBase: (unsigned char *)base {
    char *stringTable;
    struct nlist_64 *nl;
    
    printf("\t[*] Number of symbols: %d\n", symtab->nsyms);
    
    stringTable = (char *)base + symtab->stroff;
    
    nl = (struct nlist_64 *)((char *)base + symtab->symoff);
    for(int i=0; i < symtab->nsyms; i++) {
        switch(nl[i].n_type) {
            case N_SECT:
                printf("\t[*] Section Index: %d\n", nl[i].n_sect);
                symbols[@(stringTable + nl[i].n_un.n_strx)] = [NSValue valueWithPointer:(void*)nl[i].n_value];
                break;
            case N_EXT:
                printf("\t[*] External Symbol\n");
                symbols[@(stringTable + nl[i].n_un.n_strx)] = [NSValue valueWithPointer:(void*)nl[i].n_value];
                break;
            default:
                symbols[@(stringTable + nl[i].n_un.n_strx)] = [NSValue valueWithPointer:(void*)nl[i].n_value];
                break;
        }
        [orderedSymbols addPointer:(void*)nl[i].n_value];
        printf("\t[*] Symbol: %s\n", stringTable + nl[i].n_un.n_strx);
    }
}

/// Process a dysymtab load command
- (void) handleLoadCommandDySymTab: (struct dysymtab_command *)dysymtab withBase: (unsigned char *)base {
    printf("\t[*] Number of local symbols: %d\n", dysymtab->nlocalsym);
    printf("\t[*] Number of indirect symbols: %d\n", dysymtab->nindirectsyms);
    indirectSymbols = (void*)malloc(sizeof(int) * dysymtab->nindirectsyms);
    memcpy(indirectSymbols, base + dysymtab->indirectsymoff,sizeof(int) * dysymtab->nindirectsyms);
}

/// Process the UUID load command
- (void) handleLoadCommandUUID: (struct uuid_command *)uuid withBase: (unsigned char *)base {
    struct uuid_command *uuid_command;
    
    uuid_command = (struct uuid_command *)uuid;
    
    printf("\t[*] UUID: %02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n",
           uuid_command->uuid[0],
           uuid_command->uuid[1],
           uuid_command->uuid[2],
           uuid_command->uuid[3],
           uuid_command->uuid[4],
           uuid_command->uuid[5],
           uuid_command->uuid[6],
           uuid_command->uuid[7],
           uuid_command->uuid[8],
           uuid_command->uuid[9],
           uuid_command->uuid[10],
           uuid_command->uuid[11],
           uuid_command->uuid[12],
           uuid_command->uuid[13],
           uuid_command->uuid[14],
           uuid_command->uuid[15]
           );
}

/// Process chained fixups load command
- (void) handleLoadCommandDyldChainedFixups: (struct linkedit_data_command *)linkedit withBase: (unsigned char *)base {
    
    void* lib = NULL;
    void* func = NULL;
    struct dyld_chained_fixups_header *fixupsHeader;
    struct dyld_chained_import *chainedImports;
    struct dyld_chained_starts_in_image *chainedStarts;
    NSPointerArray *imports;
    char *symbolNames = NULL;
    
    // Check if dyld load command has been processed yet, as this command is dependant on this
    if ([dylds count] == 0) {
        printf("\t[-] Requeing as no dylibs available\n");
        [commands enqueue:linkedit];
        return;
    }
    
    fixupsHeader = (struct dyld_chained_fixups_header *)((char *)base + linkedit->dataoff);
    
    printf("\t[*] Fixups Version: %d\n", fixupsHeader->fixups_version);
    printf("\t[*] Fixups Imports Count: %d\n", fixupsHeader->imports_count);
    printf("\t[*] Fixups Symbol strings offset: %d\n", fixupsHeader->symbols_offset);
    printf("\t[*] Fixups Chained Starts offset: %d\n", fixupsHeader->starts_offset);
    
    chainedImports = (struct dyld_chained_import *)((char *)fixupsHeader + fixupsHeader->imports_offset);
    chainedStarts = (struct dyld_chained_starts_in_image *)((char *)fixupsHeader + fixupsHeader->starts_offset);
    symbolNames = (char *)((char *)fixupsHeader + fixupsHeader->symbols_offset);
    
    switch (fixupsHeader->imports_format) {
        case DYLD_CHAINED_IMPORT:
            printf("\t[*] Fixups Format: DYLD_CHAINED_IMPORT\n");
            break;
        case DYLD_CHAINED_IMPORT_ADDEND64:
            printf("\t[*] Fixups Format: DYLD_CHAINED_IMPORT_ADDEND64\n");
            break;
        default:
            printf("\t[!] Unknown Fixups Format\n");
            break;
    }
    
    imports = [[NSPointerArray alloc] initWithOptions: NSPointerFunctionsOpaqueMemory];
    
    // First we need to gather a list of symbols that will be referenced later
    for(int i=0; i < fixupsHeader->imports_count; i++) {
        int ordinal = chainedImports[i].lib_ordinal;
        printf("\t[*] Symbol fixup string: %s\n", symbolNames + chainedImports[i].name_offset);
        
        if (ordinal == 253 || ordinal == 0) {
            // this-image
            printf("\t[*] Library name: this-image\n");
            func = [symbols[@(symbolNames + chainedImports[i].name_offset)] pointerValue];
            func = VMADDR((unsigned long long)func);
        } else {
            const char *dyldName = [dylds[ordinal-1] UTF8String];
            printf("\t[*] Library name: %s\n", dyldName);
            lib = dlopen(dyldName, RTLD_NOW);
            if (lib == NULL) {
                printf("[!] Could not load dylib: %s\n", dyldName);
            }
            
            // Symbol imports start with _ which we need to remove before searching
            char *name = symbolNames + chainedImports[i].name_offset;
            if (name[0] == '_') {
                name += 1;
            }
            func = dlsym(lib, name);
        }
        
        if (func == NULL) {
            printf("\t[!] Cannot load dynamic library function!\n");
        }
        
        // Build an ordered list for later reference
        [imports enqueue:func];
    }
    
    // Now we can process chained fixups
    
    for(int i=0; i < chainedStarts->seg_count; i++) {
        printf("\t[*] Chained Start Offset: %d\n", chainedStarts->seg_info_offset[i]);
        
        // Not sure why, but we get `0` in here quite often which doesn't make sense.
        // Looking at dyld src, this is just ignored
        if (chainedStarts->seg_info_offset[i] == 0) {
            continue;
        }
        
        struct dyld_chained_starts_in_segment *chainedStartsSegment = (struct dyld_chained_starts_in_segment *)((char *)chainedStarts + chainedStarts->seg_info_offset[i]);
        printf("\t[*] Chained Start Segment Offset: %llx\n", chainedStartsSegment->segment_offset);
        printf("\t[*] Chained Start Page Size: %hx\n", chainedStartsSegment->page_size);
        printf("\t[*] Chained Start Page Count: %hx\n", chainedStartsSegment->page_count);
        printf("\t[*] Chained Start Size: %x\n", chainedStartsSegment->size);
        
        for(int j=0; j < chainedStartsSegment->page_count; j++) {
            if (chainedStartsSegment->page_start[j] == DYLD_CHAINED_PTR_START_NONE) {
                continue;
            }
            printf("\t[*] Chained Start Page Start: %d\n", (j * chainedStartsSegment->page_size) + chainedStartsSegment->page_start[j]);
            
            struct dyld_chained_ptr_64_rebase curRebase;
            struct dyld_chained_ptr_64_bind *bind, *prevBind, curBind;
            
            bind = (struct dyld_chained_ptr_64_bind *)VMADDR(chainedStartsSegment->segment_offset + (j * chainedStartsSegment->page_size) + chainedStartsSegment->page_start[j]);
            prevBind = NULL;
            
            while(bind != prevBind) {
                prevBind = bind;
                
                if (bind->bind == 1) {
                    // This is a bind, so update from the imports we built and the ordinal
                    memcpy(&curBind, bind, sizeof(struct dyld_chained_ptr_64_bind));
                    *(void **)bind = [imports pointerAtIndex:curBind.ordinal];
                    bind = (struct dyld_chained_ptr_64_bind *)((char *)bind + (4 * curBind.next));
                } else {
                    // This is a rebase
                    memcpy(&curRebase, bind, sizeof(struct dyld_chained_ptr_64_rebase));
                    *(void **)bind = baseAlloc + curRebase.target;
                    bind = (struct dyld_chained_ptr_64_bind *)((char *)bind + (4 * curRebase.next));
                }
            }
        }
    }
}

/// Handles the loading of the provided load_command pointed at by memory
-(void) processLoadCommand: (unsigned char *)loadCommandMem withBase: (unsigned char *)base {
    struct load_command *loadCommand;
    
    loadCommand = (struct load_command *)loadCommandMem;
    
    switch(loadCommand->cmd) {
        case LC_UUID:
            printf("[*] LC_UUID Load Command\n");
            [self handleLoadCommandUUID: (struct uuid_command *)loadCommand withBase:base];
            break;
        case LC_SEGMENT_64:
            printf("[*] LC_SEGMENT_64 Load Command\n");
            [self handleLoadCommandSegment64: (struct segment_command_64 *)loadCommand withBase:base];
            break;
        case LC_SYMTAB:
            printf("[*] LC_SYMTAB Load Command\n");
            [self handleLoadCommandSymTab: (struct symtab_command *)loadCommand withBase:base];
            break;
        case LC_DYSYMTAB:
            printf("[*] LC_DYSYMTAB Load Command\n");
            [self handleLoadCommandDySymTab:(struct dysymtab_command *)loadCommand withBase:base];
            break;
        case LC_LOAD_DYLIB:
            printf("[*] LC_LOAD_DYLIB Load Command\n");
            [self handleLoadCommandLoadDylib: (struct dylib_command *)loadCommand withBase:base];
            break;
        case LC_DYLD_CHAINED_FIXUPS:
            printf("[*] LC_DYLD_CHAINED_FIXUPS Load Command\n");
            [self handleLoadCommandDyldChainedFixups:(struct linkedit_data_command *)loadCommand withBase:base];
            break;
        case LC_THREAD:
        case LC_UNIXTHREAD:
            printf("[*] LC_THREAD Load Command\n");
            break;
        case LC_ID_DYLIB:
            printf("[*] LC_ID_DYLIB Load Command\n");
            break;
        case LC_PREBOUND_DYLIB:
            printf("[*] LC_PREBOUND_DYLIB Load Command\n");
            break;
        case LC_LOAD_DYLINKER:
            printf("[*] LC_LOAD_DYLINKER Load Command\n");
            break;
        case LC_ID_DYLINKER:
            printf("[*] LC_ID_DYLINKER Load Command\n");
            break;
        case LC_ROUTINES_64:
            printf("[*] LC_ROUTINES_64 Load Command\n");
            break;
        case LC_TWOLEVEL_HINTS:
            printf("[*] LC_TWOLEVEL_HINTS Load Command\n");
            break;
        case LC_SUB_FRAMEWORK:
            printf("[*] LC_SUB_FRAMEWORK Load Command\n");
            break;
        case LC_SUB_UMBRELLA:
            printf("[*] LC_SUB_UMBRELLA Load Command\n");
            break;
        case LC_SUB_LIBRARY:
            printf("[*] LC_SUB_LIBRARY Load Command\n");
            break;
        case LC_SUB_CLIENT:
            printf("[*] LC_SUB_CLIENT Load Command\n");
            break;
        case LC_DYLD_EXPORTS_TRIE:
            printf("[*] LC_DYLD_EXPORTS_TRIE Load Command\n");
            break;
        case LC_BUILD_VERSION:
            printf("[*] LC_BUILD_VERSION Load Command\n");
            break;
        case LC_SOURCE_VERSION:
            printf("[*] LC_SOURCE_VERSION Load Command\n");
            break;
        case LC_FUNCTION_STARTS:
            printf("[*] LC_FUNCTION_STARTS Load Command\n");
            break;
        case LC_DATA_IN_CODE:
            printf("[*] LC_DATA_IN_CODE Load Command\n");
            break;
        case LC_CODE_SIGNATURE:
            printf("[*] LC_CODE_SIGNATURE Load Command\n");
            break;
        default:
            printf("[!] Unknown Load Command: %d\n", loadCommand->cmd);
            break;
    }
}

/// Calculate the amount of virtual memory we need to load the mach-o file
-(uint64_t) calculateVirtualMemorySize: (void*)contents {
    struct mach_header_64 *header;
    struct load_command *load_command;
    struct segment_command_64 *segment_command;
    uint64_t maxAddr = 0;
    uint64_t maxLength = 0;
    
    header = (struct mach_header_64 *)contents;
    
    load_command = (struct load_command *)(contents + sizeof(struct mach_header_64));
    
    for(int i=0; i < header->ncmds; i++) {
        if (load_command->cmd == LC_SEGMENT_64) {
            segment_command = (struct segment_command_64 *)(load_command);
            if (segment_command->vmaddr >= maxAddr + maxLength) {
                maxAddr = segment_command->vmaddr;
                maxLength = segment_command->vmsize;
            }
            load_command = (struct load_command *)((char *)load_command + load_command->cmdsize);
        }
    }
    
    return maxAddr + maxLength;
}

/// Load a macho bundle from disk into memory.
/// Mainly used for testing (as we would just use dynamic loading if we wanted this)
-(void) loadMachoBundle: (NSString *)filename {
    NSData *data = [NSData dataWithContentsOfFile:filename];
    if (data == NULL) {
        printf("[!] Error: Could not open: %s\n", [filename UTF8String]);
        return;
    }
    
    [self loadMachoBundleFromMemory:data withEntryPoint:@"__Z5runmev"];
}

/// Loads a macho bundle from memory into memory and calls the entry point symbol
-(void) loadMachoBundleFromMemory: (NSData *)memory withEntryPoint: (NSString *)export {
    
    unsigned char *bytes;
    uint64_t maxVirtMemSize;
    struct mach_header_64 *header;
    struct load_command *load_command;
    entryfunc* entry;
    NSValue *exportAddr;
    
    sections = [[NSMutableDictionary alloc] init];
    segments = [[NSPointerArray alloc] initWithOptions:NSPointerFunctionsOpaqueMemory];
    commands = [[NSPointerArray alloc] initWithOptions:NSPointerFunctionsOpaqueMemory];
    dylds = [[NSMutableArray alloc] init];
    symbols = [[NSMutableDictionary alloc] init];
    orderedSymbols = [[NSPointerArray alloc] initWithOptions:NSPointerFunctionsOpaqueMemory];
    
    if (memory == NULL || export == NULL) {
        return;
    }
    
    bytes = (unsigned char *)[memory bytes];
    if (bytes == NULL) {
        return;
    }
    
    header = (struct mach_header_64 *)bytes;
    
    if (header->magic != MH_MAGIC_64) {
        printf("[!] Invalid MAGIC Header value\n");
        return;
    }
    
    if (header->cputype != CPU_TYPE_ARM64) {
        printf("[!] Invalid CPU_TYPE\n");
        return;
    }
    
    if (header->filetype != MH_BUNDLE) {
        printf("[!] Not a bundle MACHO file\n");
        return;
    }
    
    // Need to work out how much memory we need here
    maxVirtMemSize = [self calculateVirtualMemorySize: bytes];
    assert(maxVirtMemSize != 0);
    
    vm_allocate(mach_task_self(), (vm_address_t*)&baseAlloc, maxVirtMemSize, VM_FLAGS_ANYWHERE);
    if (baseAlloc == NULL) {
        printf("[!] Error allocating %llx bytes of memory\n", maxVirtMemSize);
        return;
    }
    printf("[*] Loading into base address: %p\n", baseAlloc);
    
    printf("[*] %d Load Commands\n", header->ncmds);
    load_command = (struct load_command *)(bytes + sizeof(struct mach_header_64));
    
    for(int i=0; i < header->ncmds; i++) {
        [commands enqueue:load_command];
        load_command = (struct load_command *)((char *)load_command + load_command->cmdsize);
    }
    
    // Main processing loop until all commands are clear
    // This gives us the ability to re-queue commands if they need to wait on other commands
    for(struct load_command *command = [commands dequeue]; command != NULL; command = [commands dequeue]) {
        [self processLoadCommand:(unsigned char*)command withBase:bytes];
    }
    
    // Now do the objective-c initialization (Coming in Part 2...)

    
    // Loaded, now jump to the symbol
    exportAddr = symbols[export];;
    if (exportAddr == NULL) {
        printf("[!] Could not find symbol %s for entry\n", [export UTF8String]);
        return;
    }
    
    entry = (entryfunc*)[exportAddr pointerValue];
    entry = (entryfunc*)((char *)entry + (unsigned long long)baseAlloc);
    
    // Hold onto your butts...
    printf("==== HOLD ONTO YOUR BUTTS ====\n");

    int ret = vm_protect(mach_task_self(), (vm_address_t)baseAlloc, maxVirtMemSize, true, PROT_READ | PROT_EXEC);
    if (ret != 0) {
        printf("\t[!] Error during vm_protect: %d\n", ret);
    }
    
    entry();
}

@end

