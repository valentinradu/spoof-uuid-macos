//
//  main.m
//  uuid-switch
//
//  Created by Valentin Radu on 08/04/2017.
//  Copyright © 2017 Valentin Radu. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <IOKit/network/IOEthernetInterface.h>
#import <SystemConfiguration/SystemConfiguration.h>
#import <dlfcn.h>
#import <signal.h>
#import <sys/sysctl.h>
#import "fishhook.h"
#import <string.h>
#import "UUIDSwitch.h"


static volatile NSString* uuid = NULL;
static volatile NSString* serialno = NULL;
static volatile NSString* machinename = NULL;
static volatile NSString* mac = NULL;

static NSData* dataFromHexString(__volatile NSString* string) {
    const char *chars = [string UTF8String];
    NSUInteger i = 0, len = string.length;
    
    NSMutableData *data = [NSMutableData dataWithCapacity:len / 2];
    char byteChars[3] = {'\0','\0','\0'};
    unsigned long wholeByte;
    
    while (i < len) {
        byteChars[0] = chars[i++];
        byteChars[1] = chars[i++];
        wholeByte = strtoul(byteChars, NULL, 16);
        [data appendBytes:&wholeByte length:1];
    }
    
    return data;
}

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
    else if (CFStringCompare(key, CFSTR(kIOPlatformSerialNumberKey), kCFCompareCaseInsensitive) == 0) {
        return CFBridgingRetain(serialno);
    }
    else if (CFStringCompare(key, CFSTR(kIOMACAddress), kCFCompareCaseInsensitive) == 0) {
        NSData* data = dataFromHexString(mac);
        return CFDataCreate(NULL, [data bytes], [data length]);
    }
    else {
        return original_IORegistryEntryCreateCFProperty(entry, key, allocator, options);
    }
}

static int (*original_sysctl)(const int *name, u_int namelen, void *oldp,	size_t *oldlenp, const void *newp, size_t newlen);

static int replaced_sysctl(const int *name, u_int namelen,
                           void *oldp,	size_t *oldlenp,
                           const void *newp, size_t newlen) {
    if (name != NULL && namelen >= 2 &&
        name[0] == CTL_KERN && name[1] == KERN_HOSTNAME &&
        newp == NULL && newlen == 0) {
        
        *oldlenp = machinename.length;
        
        if (oldp != NULL) {
            memcpy(oldp, [machinename cStringUsingEncoding:NSUTF8StringEncoding], *oldlenp);
        }
        return 0;
    }
    else {
        return original_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    }
}

static CFStringRef (*original_SCDynamicStoreCopyComputerName)(SCDynamicStoreRef store, CFStringEncoding* nameEncoding);

static CFStringRef replaced_SCDynamicStoreCopyComputerName(SCDynamicStoreRef store, CFStringEncoding* nameEncoding) {
    return CFBridgingRetain(machinename);
}


static void switchIdentity(int dummy) {
    uuid = [[NSUUID UUID] UUIDString];
    serialno = [[[[NSUUID UUID] UUIDString] componentsSeparatedByString:@"-"] lastObject];
    machinename = [[[[NSUUID UUID] UUIDString] componentsSeparatedByString:@"-"] lastObject];
    mac = [@"0x" stringByAppendingString:[[[[NSUUID UUID] UUIDString] componentsSeparatedByString:@"-"] lastObject]];
}

#pragma mark Dylib Constructor

__attribute__((constructor)) static void init(int argc, const char **argv)
{
    NSLog(@"Fishhook hook enabled.");
    
    uuid = [[NSUUID UUID] UUIDString];
    serialno = [[[[NSUUID UUID] UUIDString] componentsSeparatedByString:@"-"] lastObject];
    machinename = [[[[NSUUID UUID] UUIDString] componentsSeparatedByString:@"-"] lastObject];
    mac = [[[[NSUUID UUID] UUIDString] componentsSeparatedByString:@"-"] lastObject];
    
    signal(SIGUSR1, switchIdentity);
    
    original_IORegistryEntryCreateCFProperty = dlsym(RTLD_DEFAULT, "IORegistryEntryCreateCFProperty");
    if ((rebind_symbols((struct rebinding[1]){{(char *)"IORegistryEntryCreateCFProperty", (void *)replaced_IORegistryEntryCreateCFProperty}}, 1) < 0))
    {
        NSLog(@"Hooking IORegistryEntryCreateCFProperty failed.");
    }
    else {
        NSLog(@"Hooking IORegistryEntryCreateCFProperty was successful.");
    }
    
    original_sysctl = dlsym(RTLD_DEFAULT, "sysctl");
    if ((rebind_symbols((struct rebinding[1]){{(char *)"sysctl", (void *)replaced_sysctl}}, 1) < 0))
    {
        NSLog(@"Hooking sysctlbyname failed.");
    }
    else {
        NSLog(@"Hooking sysctlbyname was successful.");
    }
    
    original_SCDynamicStoreCopyComputerName = dlsym(RTLD_DEFAULT, "SCDynamicStoreCopyComputerName");
    if ((rebind_symbols((struct rebinding[1]){{(char *)"SCDynamicStoreCopyComputerName", (void *)replaced_SCDynamicStoreCopyComputerName}}, 1) < 0))
    {
        NSLog(@"Hooking SCDynamicStoreCopyComputerName failed.");
    }
    else {
        NSLog(@"Hooking SCDynamicStoreCopyComputerName was successful.");
    }
}
