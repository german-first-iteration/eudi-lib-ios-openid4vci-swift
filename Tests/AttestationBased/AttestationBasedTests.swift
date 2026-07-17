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
import SwiftyJSON

@testable import OpenID4VCI

class AttestationBasedTests: XCTestCase {
  
  func testClientAttestation() async throws {
    
    let clientAttestation = try ClientAttestationJWT(
      jws: JWS(
        compactSerialization: TestsConstants.CNF_JWT
      )
    )
    
    let jwk = clientAttestation.pubKey
    XCTAssertNotNil(jwk)
  }
  
  func testClientAttestationPopJwt() async throws {
    
    let clientAttestation = try? ClientAttestationPoPJWT(
      jws: JWS(
        compactSerialization: TestsConstants.CNF_JWT
      )
    )
    
    XCTAssertNotNil(clientAttestation)
  }
  
  func testClient() async throws {
    
    let clientAttestationPop = try? ClientAttestationPoPJWT(
      jws: JWS(
        compactSerialization: TestsConstants.CNF_JWT
      )
    )

    XCTAssertNotNil(clientAttestationPop)
  }
  
  func testClientAttestationJWT() async throws {
    
    let client = try selfSignedClient(
      clientId: WALLET_DEV_CLIENT_ID,
      privateKey: try! KeyController.generateECDHPrivateKey()
    )
    
    XCTAssertNotNil(client)
  }

  func testClientAttestationPoPUsesProvidedClock() async throws {
    let signingKey = try KeyController.generateECDHPrivateKey()
    let client = try selfSignedClient(
      clientId: WALLET_DEV_CLIENT_ID,
      privateKey: signingKey
    )
    let now = Date(timeIntervalSince1970: 1_700_000_000)
    let proof = try await DefaultClientAttestationPoPBuilder().buildAttestationPoPJWT(
      for: client,
      algorithm: .ES256,
      clock: FixedClock(date: now),
      authServerId: try XCTUnwrap(URL(string: "https://issuer.example.com")),
      challenge: nil
    )
    let payload = try XCTUnwrap(
      JSONSerialization.jsonObject(with: proof.jws.payload.data()) as? [String: Any]
    )

    XCTAssertEqual(payload[JWTClaimNames.issuedAt] as? TimeInterval, now.timeIntervalSince1970)
    XCTAssertEqual(payload[JWTClaimNames.expirationTime] as? TimeInterval, now.addingTimeInterval(300).timeIntervalSince1970)
  }
}

private struct FixedClock: ClockType {
  let date: Date

  func now() -> Date { date }
}
