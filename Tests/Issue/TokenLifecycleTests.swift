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
@preconcurrency import Foundation
import XCTest

@testable import OpenID4VCI

final class TokenLifecycleTests: XCTestCase {

  private let config = OpenId4VCIConfig(
    client: .public(id: "token-lifecycle-client"),
    authFlowRedirectionURI: URL(string: "https://wallet.example.com/callback")!,
    requirePAR: false,
    requireDpop: false
  )

  func testAuthorizationCodeResponseKeepsAbsentRefreshAndExpiryNil() async throws {
    let networking = TokenLifecycleNetworking(
      json: """
      {
        "access_token": "access-token",
        "token_type": "dpop"
      }
      """
    )
    let (issuer, offer) = try await makeIssuer(networking: networking)

    let authorizedRequest = try await issuer.authorizeWithAuthorizationCode(
      serverState: TestsConstants.unAuthorizedRequest.state,
      request: TestsConstants.unAuthorizedRequest,
      authorizationCode: try AuthorizationCode(value: "authorization-code"),
      grant: try XCTUnwrap(offer.grants)
    )

    XCTAssertNil(authorizedRequest.refreshToken)
    XCTAssertNil(authorizedRequest.accessToken.expiresIn)
    XCTAssertEqual(authorizedRequest.accessToken.tokenType, .dpop)
    XCTAssertEqual(TokenType(value: "bearer"), .bearer)
  }

  func testDPoPAccessTokenFailsClosedWithoutProofConstructor() async throws {
    let accessToken = try IssuanceAccessToken(
      accessToken: "access-token",
      tokenType: .dpop
    )

    do {
      _ = try await accessToken.dPoPOrBearerAuthorizationHeader(
        dpopConstructor: nil,
        dPopNonce: nil,
        endpoint: URL(string: "https://issuer.example.com/credential")!
      )
      XCTFail("Expected a DPoP-bound token without a proof constructor to fail")
    } catch let ValidationError.error(reason) {
      XCTAssertTrue(reason.contains("DPoP proof constructor"))
    } catch {
      XCTFail("Unexpected error: \(error)")
    }
  }

  func testTokenResponseRequiresKnownTokenTypeButAllowsMissingExpiry() throws {
    let valid = try JSONDecoder().decode(
      AccessTokenRequestResponse.self,
      from: Data("{\"access_token\":\"access-token\",\"token_type\":\"DPOP\"}".utf8)
    )
    guard case let .success(tokenType, _, _, _, expiresIn, _, _) = valid else {
      return XCTFail("Expected token response success")
    }
    XCTAssertEqual(TokenType.parse(tokenType), .dpop)
    XCTAssertNil(expiresIn)

    for invalid in [
      "{\"access_token\":\"access-token\"}",
      "{\"access_token\":\"access-token\",\"token_type\":\"macaroon\"}"
    ] {
      XCTAssertThrowsError(
        try JSONDecoder().decode(AccessTokenRequestResponse.self, from: Data(invalid.utf8))
      )
    }
  }

  func testTokenErrorAllowsOmittedDescription() throws {
    let response = try JSONDecoder().decode(
      AccessTokenRequestResponse.self,
      from: Data("{\"error\":\"invalid_grant\"}".utf8)
    )
    guard case let .failure(error, errorDescription) = response else {
      return XCTFail("Expected token error response")
    }
    XCTAssertEqual(error, "invalid_grant")
    XCTAssertNil(errorDescription)
  }

  func testPreAuthorizedSuccessUsesResponseDPoPNonce() async throws {
    let networking = TokenLifecycleNetworking(
      json: """
      {
        "access_token": "access-token",
        "token_type": "Bearer"
      }
      """,
      headers: [Constants.DPOP_NONCE_HEADER: "response-nonce"]
    )
    let client = try await makeAuthorizationClient(networking: networking)

    let response = try await client.requestAccessTokenPreAuthFlow(
      preAuthorizedCode: "pre-authorized-code",
      txCode: nil,
      client: .public(id: "token-lifecycle-client"),
      transactionCode: nil,
      identifiers: [],
      dpopNonce: Nonce(value: "request-nonce"),
      challenge: nil,
      maxRetries: 0
    )

    XCTAssertNil(response.1)
    XCTAssertNil(response.0.expiresIn)
    XCTAssertEqual(response.4?.value, "response-nonce")
  }

  func testRefreshPreservesRefreshTokenAndStampsCurrentTimeAndNonce() async throws {
    let networking = TokenLifecycleNetworking(
      json: """
      {
        "access_token": "new-access-token",
        "token_type": "Bearer",
        "expires_in": 120
      }
      """,
      headers: [Constants.DPOP_NONCE_HEADER: "new-nonce"]
    )
    let (issuer, _) = try await makeIssuer(networking: networking)
    let original = try makeAuthorizedRequest()
    let beforeRefresh = Date().timeIntervalSinceReferenceDate

    let refreshed = try await issuer.refresh(
      clientId: "token-lifecycle-client",
      authorizedRequest: original
    )
    let afterRefresh = Date().timeIntervalSinceReferenceDate

    XCTAssertEqual(refreshed.accessToken.accessToken, "new-access-token")
    XCTAssertEqual(refreshed.accessToken.expiresIn, 120)
    XCTAssertEqual(refreshed.refreshToken?.refreshToken, "old-refresh-token")
    XCTAssertEqual(refreshed.refreshToken?.expiresIn, 600)
    XCTAssertEqual(refreshed.dPopNonce?.value, "new-nonce")
    XCTAssertGreaterThanOrEqual(refreshed.timeStamp, beforeRefresh)
    XCTAssertLessThanOrEqual(refreshed.timeStamp, afterRefresh)
  }

  func testRefreshReplacesRotatedRefreshToken() async throws {
    let networking = TokenLifecycleNetworking(
      json: """
      {
        "access_token": "new-access-token",
        "token_type": "bearer",
        "refresh_token": "rotated-refresh-token",
        "refresh_expires_in": 900
      }
      """
    )
    let (issuer, _) = try await makeIssuer(networking: networking)

    let refreshed = try await issuer.refresh(
      client: .public(id: "token-lifecycle-client"),
      authorizedRequest: try makeAuthorizedRequest(),
      dPopNonce: nil
    )

    XCTAssertEqual(refreshed.refreshToken?.refreshToken, "rotated-refresh-token")
    XCTAssertEqual(refreshed.refreshToken?.expiresIn, 900)
    XCTAssertEqual(refreshed.dPopNonce?.value, "old-nonce")
    XCTAssertNil(refreshed.accessToken.expiresIn)
  }

  func testAuthorizationCodeNetworkFailureIsNotRetried() async throws {
    let networking = TokenLifecycleNetworking(error: .networkFailure)
    let client = try await makeAuthorizationClient(networking: networking)

    do {
      _ = try await client.requestAccessTokenAuthFlow(
        authorizationCode: try AuthorizationCode(value: "authorization-code"),
        codeVerifier: "code-verifier",
        identifiers: [],
        dpopNonce: nil,
        challenge: nil,
        maxRetries: 3
      )
      XCTFail("Expected the network failure to be propagated")
    } catch {
      // The request is intentionally not retried because an authorization code is single-use.
    }

    let requestCount = await networking.requestCountValue()
    XCTAssertEqual(requestCount, 1)
  }

  private func makeIssuer(
    networking: TokenLifecycleNetworking
  ) async throws -> (Issuer, CredentialOffer) {
    let offer = try await credentialOffer()
    let issuer = try Issuer(
      authorizationServerMetadata: offer.authorizationServerMetadata,
      issuerMetadata: offer.credentialIssuerMetadata,
      config: config,
      tokenPoster: Poster(session: networking),
      challengePoster: Poster(session: networking)
    )
    return (issuer, offer)
  }

  private func makeAuthorizationClient(
    networking: TokenLifecycleNetworking
  ) async throws -> AuthorizationServerClient {
    let offer = try await credentialOffer()
    return try AuthorizationServerClient(
      challenger: nil,
      tokenPoster: Poster(session: networking),
      config: config,
      authorizationServerMetadata: offer.authorizationServerMetadata,
      credentialIssuerIdentifier: offer.credentialIssuerMetadata.credentialIssuerIdentifier
    )
  }

  private func credentialOffer() async throws -> CredentialOffer {
    guard let offer = await TestsConstants.createMockCredentialOffer() else {
      throw TokenLifecycleTestError.missingCredentialOffer
    }
    return offer
  }

  private func makeAuthorizedRequest() throws -> AuthorizedRequest {
    return AuthorizedRequest(
      accessToken: try IssuanceAccessToken(
        accessToken: "old-access-token",
        tokenType: .bearer,
        expiresIn: 10
      ),
      refreshToken: try IssuanceRefreshToken(
        refreshToken: "old-refresh-token",
        expiresIn: 600
      ),
      credentialIdentifiers: nil,
      timeStamp: 1,
      dPopNonce: Nonce(value: "old-nonce"),
      grantType: .authorizationCode
    )
  }
}

private enum TokenLifecycleTestError: Error, Sendable {
  case missingCredentialOffer
  case networkFailure
}

private actor TokenLifecycleNetworking: Networking {
  private let json: String?
  private let headers: [String: String]
  private let error: TokenLifecycleTestError?
  private var requestCount = 0

  init(
    json: String,
    headers: [String: String] = [:]
  ) {
    self.json = json
    self.headers = headers
    self.error = nil
  }

  init(error: TokenLifecycleTestError) {
    self.json = nil
    self.headers = [:]
    self.error = error
  }

  func data(from url: URL) async throws -> (Data, URLResponse) {
    requestCount += 1
    return try response(url: url)
  }

  func data(for request: URLRequest) async throws -> (Data, URLResponse) {
    requestCount += 1
    return try response(url: request.url ?? URL(string: "https://example.com")!)
  }

  func requestCountValue() -> Int {
    requestCount
  }

  private func response(url: URL) throws -> (Data, URLResponse) {
    if let error {
      throw error
    }
    let data = Data((json ?? "").utf8)
    let response = HTTPURLResponse(
      url: url,
      statusCode: 200,
      httpVersion: nil,
      headerFields: headers
    )!
    return (data, response)
  }
}
