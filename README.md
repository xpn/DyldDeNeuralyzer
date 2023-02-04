## Dyld-DeNeuralyzer

A simple set of POCs to demonstrate in-memory loading of Mach-O's.

* Method 1 - Patch up dyld for in-memory loading of Mach-O bundles.
* Method 2 - Use a custom in-memory loader for loading Mach-O bundles.

## Usage

```
# For Method 1
./dylddeneuralyzer 1 macho_bundle_path

# For Method 2
./dylddeneuralyzer 2 macho_bundle_path
```

## Blog posts

Restoring Dyld Memory Loading - [https://blog.xpnsec.com/restoring-dyld-memory-loading/](https://blog.xpnsec.com/restoring-dyld-memory-loading/)
Building a Custom Mach-O Memory Loader for macOS - Part 1 - [https://blog.xpnsec.com/building-a-mach-o-memory-loader-part-1/](https://blog.xpnsec.com/building-a-mach-o-memory-loader-part-1/)