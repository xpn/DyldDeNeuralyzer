#import <Foundation/Foundation.h>
#import "macholoader.h"
#include "dyldpatch.h"

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        printf("Dyld-DeNeuralyzer POC.. by @_xpn_\n\n");
        
        if (argc != 3) {
            printf("Usage: %s [METHOD] [BundlePath]\n", argv[0]);
            printf("Method 1 - Patch Dyld\n", argv[0]);
            printf("Method 2 - Custom Loader\n", argv[0]);
            return 2;
        }
        
        if (argv[1][0] == '1') {
            // POC 1 - Patch dyld
            patchDyld(argv[2]);
        } else {
            // POC 2 - Custom loader
            [[[MachoLoader alloc] init] loadMachoBundle:@(argv[2])];
        }
    }
}
