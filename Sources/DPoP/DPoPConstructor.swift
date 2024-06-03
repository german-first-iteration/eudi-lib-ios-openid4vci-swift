/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import Foundation
import JOSESwift

public class DPoPConstructor {
  
  public let algorithm: JWSAlgorithm
  public let jwk: JWK
  public let privateKey: SecKey
  
  public init(algorithm: JWSAlgorithm, jwk: JWK, privateKey: SecKey) {
    self.algorithm = algorithm
    self.jwk = jwk
    self.privateKey = privateKey
  }
  
  func jwt(tokenEndpoint: URL) throws -> String {
    
    let header = try JWSHeader(parameters: [
      "typ": "dpop+jwt",
      "alg": algorithm.name,
      "jwk": jwk.toDictionary()
    ])
    
    let dictionary: [String: Any] = [
      JWTClaimNames.issuedAt: Int(Date().timeIntervalSince1970.rounded()),
      "htm": "POST",
      "htu": tokenEndpoint.absoluteString,
      "jti": String.randomBase64URLString(length: 20)
    ]
    
    let payload = Payload(try dictionary.toThrowingJSONData())
    
    guard let signatureAlgorithm = SignatureAlgorithm(rawValue: algorithm.name) else {
      throw CredentialIssuanceError.cryptographicAlgorithmNotSupported
    }
    
    guard let signer = Signer(
      signingAlgorithm: signatureAlgorithm,
      key: privateKey
    ) else {
      throw ValidationError.error(reason: "Unable to create JWS signer")
    }
    
    let jws = try JWS(
      header: header,
      payload: payload,
      signer: signer
    )
    
    return jws.compactSerializedString
  }
}
