//
//  RSA.swift
//  RSA
//
//  Created by 王义川 on 15/7/13.
//  Copyright © 2015年 肇庆市创威发展有限公司. All rights reserved.
//

import Foundation


public enum RSAErrorType : ErrorType {
    case CertificateBase64DecodedFailure
    case SecTrustCreateFailure(OSStatus)
    case SecTrustEvaluateFailure(OSStatus)
    case SecKeyEncryptFailure(OSStatus)
}

public enum BlockMode {
    case ECB
}

private let DefaultBlockMode = BlockMode.ECB
private let DefaultPadding = SecPadding(kSecPaddingPKCS1)

/// 从X.509证书中提取公钥，使用公钥对数据进行加密。
public func encrypt(data: NSData, certificateBase64String: String, blockMode: BlockMode = DefaultBlockMode, padding: SecPadding = DefaultPadding) throws -> NSData {
    guard let certificate = NSData(base64EncodedString: certificateBase64String, options: NSDataBase64DecodingOptions()) else {
        throw RSAErrorType.CertificateBase64DecodedFailure
    }
    return try encrypt(data, certificate: certificate, blockMode: blockMode, padding: padding)
}

/// 从X.509证书中提取公钥，使用公钥对数据进行加密。
public func encrypt(data: NSData, certificate: NSData, blockMode: BlockMode = DefaultBlockMode, padding: SecPadding = DefaultPadding) throws -> NSData {
    let key = try publicKeyFromCertificate(certificate)
    return try encrypt(data, publicKey: key, blockMode: blockMode, padding: padding)
}

/// 从X.509证书中提取公钥。
public func publicKeyFromCertificate(certificate: NSData) throws -> SecKeyRef {
    let certificate = SecCertificateCreateWithData(kCFAllocatorDefault, certificate as CFData).takeUnretainedValue()
    let policy = SecPolicyCreateBasicX509().takeUnretainedValue()
    var unmanagedTrust : Unmanaged<SecTrust>? = nil
    let status = SecTrustCreateWithCertificates(certificate, policy, &unmanagedTrust)
    if (status != 0) {
        throw RSAErrorType.SecTrustCreateFailure(status)
    }
    let trust = unmanagedTrust!.takeUnretainedValue()
    let evaluateStatus = SecTrustEvaluate(trust, nil)
    if (evaluateStatus != 0) {
        throw RSAErrorType.SecTrustEvaluateFailure(evaluateStatus)
    }
    return SecTrustCopyPublicKey(trust).takeUnretainedValue()
}

/// 使用公钥对数据进行加密。
public func encrypt(data: NSData, publicKey key: SecKeyRef, blockMode: BlockMode = DefaultBlockMode, padding: SecPadding = DefaultPadding) throws -> NSData {
    let blockSize = SecKeyGetBlockSize(key) - 11
    let encryptedData = NSMutableData()
    let blockCount = Int(ceil(Double(data.length) / Double(blockSize)))
    
    for i in 0..<blockCount {
        var cipherLen = SecKeyGetBlockSize(key)
        var cipher = [UInt8](count: Int(cipherLen), repeatedValue: 0)
        let bufferSize = min(blockSize,(data.length - i * blockSize))
        let buffer = data.subdataWithRange(NSMakeRange(i*blockSize, bufferSize))
        let status = SecKeyEncrypt(key, padding, UnsafePointer<UInt8>(buffer.bytes), buffer.length, &cipher, &cipherLen)
        if (status == noErr){
            encryptedData.appendBytes(cipher, length: Int(cipherLen))
        } else {
            throw RSAErrorType.SecKeyEncryptFailure(status)
        }
    }
    return encryptedData
}