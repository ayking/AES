//
//  AESCrypto.m
//
//  Created by Alan YU on 16/11/15.
//  Copyright © 2015 yDiva.com. All rights reserved.
//

#import "AESCrypto.h"

typedef struct {
    char ivData[kCCBlockSizeAES128];
    unsigned long dataLength;
} AES256Header;

@implementation AESCrypto

+ (NSData *)encrypt:(NSData *)data key:(NSString *)key {
    
    AES256Header header;
    
    char keyPointer[kCCKeySizeAES256 + 2];
    bzero(keyPointer, sizeof(keyPointer));
    
    NSData *ivData = [self generateRandomIV:kCCBlockSizeAES128];
    memcpy(header.ivData, [ivData bytes], [ivData length]);
    
    if ([key length] > kCCKeySizeAES256) {
        NSLog(@"Will limit the key size to %d", kCCKeySizeAES256);
        key = [key substringToIndex:kCCKeySizeAES256];
    }
    [key getCString:keyPointer maxLength:sizeof(keyPointer) encoding:NSUTF8StringEncoding];
    
    header.dataLength = [data length];
    
    //see https://developer.apple.com/library/ios/documentation/System/Conceptual/ManPages_iPhoneOS/man3/CCryptorCreateFromData.3cc.html
    // For block ciphers, the output size will always be less than or equal to the input size plus the size of one block.
    size_t buffSize = header.dataLength + kCCBlockSizeAES128;
    void *buff = malloc(buffSize);
    
    size_t numBytesEncrypted = 0;
    
    //refer to http://www.opensource.apple.com/source/CommonCrypto/CommonCrypto-36064/CommonCrypto/CommonCryptor.h
    //for details on this function
    //Stateless, one-shot encrypt or decrypt operation.
    CCCryptorStatus status = CCCrypt(kCCEncrypt,                    /* kCCEncrypt, etc. */
                                     kCCAlgorithmAES128,            /* kCCAlgorithmAES128, etc. */
                                     kCCOptionPKCS7Padding,         /* kCCOptionPKCS7Padding, etc. */
                                     keyPointer, kCCKeySizeAES256,  /* key and its length */
                                     header.ivData,                 /* initialization vector - use random IV everytime */
                                     [data bytes], [data length],   /* input  */
                                     buff, buffSize,                /* output */
                                     &numBytesEncrypted);
    
    if (status == kCCSuccess) {
        
        NSMutableData *result =  [NSMutableData dataWithBytes:&header length:sizeof(AES256Header)];
        [result appendData:[NSData dataWithBytesNoCopy:buff length:numBytesEncrypted]];
        
        return result;
    }
    
    free(buff);
    return nil;
}

+ (NSData *)decrypt:(NSData *)package key:(NSString *)key {
    
    AES256Header header;
    NSUInteger headerLength = sizeof(AES256Header);
    NSUInteger dataLength = [package length] - headerLength;
    
    [package getBytes:&header length:headerLength];
    
    NSData *data = [package subdataWithRange:NSMakeRange(headerLength, dataLength)];
    
    char keyPointer[kCCKeySizeAES256 + 2];
    bzero(keyPointer, sizeof(keyPointer));
    
    if ([key length] > kCCKeySizeAES256) {
        NSLog(@"Will limit the key size to %d", kCCKeySizeAES256);
        key = [key substringToIndex:kCCKeySizeAES256];
    }
    [key getCString:keyPointer maxLength:sizeof(keyPointer) encoding:NSUTF8StringEncoding];
    
    //see https://developer.apple.com/library/ios/documentation/System/Conceptual/ManPages_iPhoneOS/man3/CCryptorCreateFromData.3cc.html
    // For block ciphers, the output size will always be less than or equal to the input size plus the size of one block.
    size_t buffSize = dataLength + kCCBlockSizeAES128;
    
    void *buff = malloc(buffSize);
    
    size_t numBytesEncrypted = 0;
    
    //refer to http://www.opensource.apple.com/source/CommonCrypto/CommonCrypto-36064/CommonCrypto/CommonCryptor.h
    //for details on this function
    //Stateless, one-shot encrypt or decrypt operation.
    CCCryptorStatus status = CCCrypt(kCCDecrypt,                    /* kCCEncrypt, etc. */
                                     kCCAlgorithmAES128,            /* kCCAlgorithmAES128, etc. */
                                     kCCOptionPKCS7Padding,         /* kCCOptionPKCS7Padding, etc. */
                                     keyPointer, kCCKeySizeAES256,  /* key and its length */
                                     header.ivData,                 /* initialization vector - use same IV which was used for decryption */
                                     [data bytes], [data length],   /* input */
                                     buff, buffSize,                /* output */
                                     &numBytesEncrypted);
    if (status == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:buff length:header.dataLength];
    }
    
    free(buff);
    return nil;
}

+ (NSData *)generateRandomIV:(size_t)length {
    
    NSMutableData *data = [NSMutableData dataWithLength:length];
    
    int err = SecRandomCopyBytes(kSecRandomDefault,
                                   length,
                                   data.mutableBytes);
    
    NSAssert(err == 0, @"SecRandomCopyBytes errno : %d", errno);
    
    return data;
}

@end