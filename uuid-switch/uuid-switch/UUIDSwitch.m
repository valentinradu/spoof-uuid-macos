//
//  main.m
//  uuid-switch
//
//  Created by Valentin Radu on 08/04/2017.
//  Copyright © 2017 Valentin Radu. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import "fishhook.h"
#import "UUIDSwitch.h"


static CFTypeRef (*original_IORegistryEntryCreateCFProperty)(io_registry_entry_t entry,
                                                             CFStringRef key,
                                                             CFAllocatorRef allocator,
                                                             IOOptionBits options);

static CFTypeRef replaced_IORegistryEntryCreateCFProperty(io_registry_entry_t entry,
                                                          CFStringRef key,
                                                          CFAllocatorRef allocator,
                                                          IOOptionBits options) {
    if (CFStringCompare(key, CFSTR(kIOPlatformUUIDKey), kCFCompareCaseInsensitive) == 0) {
        return CFSTR("0FAFE915-8176-461F-AA24-C747EDFF7F1E");
    }
    else {
        return original_IORegistryEntryCreateCFProperty(entry, key, allocator, options);
    }
}

#pragma mark Dylib Constructor

__attribute__((constructor)) static void init(int argc, const char **argv)
{
    NSLog(@"Fishhook hook enabled.");
    original_IORegistryEntryCreateCFProperty = dlsym(RTLD_DEFAULT, "IORegistryEntryCreateCFProperty");
    if ((rebind_symbols((struct rebinding[1]){{(char *)"IORegistryEntryCreateCFProperty", (void *)replaced_IORegistryEntryCreateCFProperty}}, 1) < 0))
    {
        NSLog(@"Hooking failed.");
    }
    else {
        NSLog(@"Hooking was successful.");
    }
}
