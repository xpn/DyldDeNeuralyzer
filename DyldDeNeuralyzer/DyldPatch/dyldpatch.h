//
//  dyldpatch.h
//  DyldDeNeuralyzer
//
//  Created by Adam Chester on 17/01/2023.
//

#ifndef dyldpatch_h
#define dyldpatch_h
#define FILENAME_SEARCH "/usr/lib/libffi-trampolines.dylib"

void patchDyld(char *path);

#endif /* dyldpatch_h */
