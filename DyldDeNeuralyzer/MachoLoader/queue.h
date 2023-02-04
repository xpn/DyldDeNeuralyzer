//
//  queue.h
//  DyldDeNeuralyzer
//
//  Created by Adam Chester on 17/01/2023.
//

#ifndef queue_h
#define queue_h

@interface NSPointerArray (QueueAdditions)
- (void*) dequeue;
- (void) enqueue:(void*)obj;
@end

#endif /* queue_h */
