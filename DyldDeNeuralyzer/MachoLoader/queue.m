//
//  queue.m
//  DyldDeNeuralyzer
//
//  Created by Adam Chester on 17/01/2023.
//

#import <Foundation/Foundation.h>
#include "queue.h"

@implementation NSPointerArray (QueueAdditions)
// Queues are first-in-first-out, so we remove objects from the head
- (void*) dequeue {
    if ([self count] == 0) return (void*)0; // to avoid raising exception (Quinn)
    void* headObject = [self pointerAtIndex:0];
    if (headObject != nil) { // so it isn't dealloc'ed on remove
        [self removePointerAtIndex:0];
    }
    return headObject;
}

// Add to the tail of the queue (no one likes it when people cut in line!)
- (void) enqueue:(void*)anObject {
    [self addPointer:anObject];
}
@end
