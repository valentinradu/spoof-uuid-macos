//
//  main.m
//  uuid-switch
//
//  Created by Valentin Radu on 08/04/2017.
//  Copyright © 2017 Valentin Radu. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <signal.h>
#import "fishhook.h"
#import "UUIDSwitch.h"


static volatile NSString* uuid = NULL;

static CFTypeRef (*original_IORegistryEntryCreateCFProperty)(io_registry_entry_t entry,
                                                             CFStringRef key,
                                                             CFAllocatorRef allocator,
                                                             IOOptionBits options);

static CFTypeRef replaced_IORegistryEntryCreateCFProperty(io_registry_entry_t entry,
                                                          CFStringRef key,
                                                          CFAllocatorRef allocator,
                                                          IOOptionBits options) {
    if (CFStringCompare(key, CFSTR(kIOPlatformUUIDKey), kCFCompareCaseInsensitive) == 0) {
        return CFBridgingRetain(uuid);
    }
    else {
        return original_IORegistryEntryCreateCFProperty(entry, key, allocator, options);
    }
}

static void switchUUID(int dummy) {
    uuid = [[NSUUID UUID] UUIDString];
}

#pragma mark Dylib Constructor

__attribute__((constructor)) static void init(int argc, const char **argv)
{
    NSLog(@"Fishhook hook enabled.");
    
    uuid = [[NSUUID UUID] UUIDString];
    signal(SIGUSR1, switchUUID);
    original_IORegistryEntryCreateCFProperty = dlsym(RTLD_DEFAULT, "IORegistryEntryCreateCFProperty");
    if ((rebind_symbols((struct rebinding[1]){{(char *)"IORegistryEntryCreateCFProperty", (void *)replaced_IORegistryEntryCreateCFProperty}}, 1) < 0))
    {
        NSLog(@"Hooking failed.");
    }
    else {
        NSLog(@"Hooking was successful.");
    }
}
