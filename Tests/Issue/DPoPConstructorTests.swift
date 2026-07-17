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
import XCTest
import JOSESwift

@testable import OpenID4VCI

final class DPoPConstructorTests: XCTestCase {

  func testDPoPProofUsesPublicJWKAndCanonicalHTU() async throws {
    let signingKey = try KeyController.generateECDHPrivateKey()
    let privateJWK = try ECPrivateKey(
      privateKey: signingKey,
      additionalParameters: [
        "alg": JWSAlgorithm(.ES256).name,
        "kid": "dpop-key"
      ]
    )
    let constructor = DPoPConstructor(
      algorithm: .init(.ES256),
      jwk: privateJWK,
      privateKey: .secKey(signingKey)
    )

    let jwt = try await constructor.jwt(
      endpoint: try XCTUnwrap(URL(string: "https://issuer.example.com/token?tenant=one#fragment")),
      accessToken: nil,
      nonce: nil
    )
    let components = jwt.split(separator: ".")
    XCTAssertEqual(components.count, 3)
    let header = try decodeJSONObject(String(components[0]))
    let payload = try decodeJSONObject(String(components[1]))

    let jwk = try XCTUnwrap(header[JWTClaimNames.JWK] as? [String: Any])
    XCTAssertEqual(jwk["kty"] as? String, "EC")
    XCTAssertEqual(jwk["kid"] as? String, "dpop-key")
    XCTAssertNotNil(jwk["x"])
    XCTAssertNotNil(jwk["y"])
    XCTAssertNil(jwk["d"])
    XCTAssertEqual(payload[JWTClaimNames.htm] as? String, "POST")
    XCTAssertEqual(payload[JWTClaimNames.htu] as? String, "https://issuer.example.com/token")
  }

  private func decodeJSONObject(_ encoded: String) throws -> [String: Any] {
    let data = try XCTUnwrap(Data(base64URLEncoded: encoded))
    return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
  }
}
