//
//  AESCrypto.h
//
//  Created by Alan YU on 16/11/15.
//  Copyright © 2015 yDiva.com. All rights reserved.
//

#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
#import <Foundation/Foundation.h>

@interface AESCrypto : NSObject

+ (NSData *)encrypt:(NSData *)data key:(NSString *)key;
+ (NSData *)decrypt:(NSData *)package key:(NSString *)key;

@end