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

@testable import OpenID4VCI

final class AuthorizationDetailsWireTests: XCTestCase {

  func testStandardAuthorizationUsesAuthorizationDetailsQueryParameter() async throws {
    let client = try makeClient(hasAuthorizationServers: false)
    let identifier = try CredentialConfigurationIdentifier(value: "UniversityDegreeCredential")

    let (_, authorizationURL) = try await client.authorizationRequestUrl(
      scopes: [],
      credentialConfigurationIdentifiers: [identifier],
      state: "state",
      issuerState: nil
    )

    let parameters = authorizationURL.url.queryParameters
    XCTAssertNil(parameters["credential_configuration_ids"])
    let details = try decodeDetails(parameters[Constants.AUTHORIZATION_DETAILS])
    XCTAssertEqual(details.count, 1)
    XCTAssertEqual(details[0].type.type, OPENID_CREDENTIAL)
    XCTAssertEqual(details[0].credentialConfigurationId, identifier.value)
    XCTAssertTrue(details[0].locations.isEmpty)
  }

  func testPARPostsAuthorizationDetailsAsOneFormEncodedJSONValue() async throws {
    let networking = RecordingNetworking(
      responseData: Data("{\"request_uri\":\"urn:example:request\",\"expires_in\":60}".utf8)
    )
    let client = try makeClient(
      hasAuthorizationServers: true,
      parPoster: Poster(session: networking)
    )
    let identifier = try CredentialConfigurationIdentifier(value: "UniversityDegreeCredential")

    _ = try await client.submitPushedAuthorizationRequest(
      scopes: [],
      credentialConfigurationIdentifiers: [identifier],
      state: "state",
      issuerState: nil,
      resource: nil,
      dpopNonce: nil,
      challenge: nil,
      maxRetries: 0
    )

    let recordedRequest = await networking.lastRequest()
    let request = try XCTUnwrap(recordedRequest)
    let body = try XCTUnwrap(request.httpBody)
    let parameters = formParameters(body)
    XCTAssertFalse(String(decoding: body, as: UTF8.self).contains("%25"))
    XCTAssertNil(parameters["credential_configuration_ids"])
    let details = try decodeDetails(parameters[Constants.AUTHORIZATION_DETAILS])
    XCTAssertEqual(details.first?.locations, ["https://issuer.example.com"])
  }

  func testTokenRequestPostsRawAuthorizationDetailsForSingleFormEncoding() async throws {
    let networking = RecordingNetworking(
      responseData: Data(
        "{\"access_token\":\"access-token\",\"token_type\":\"Bearer\",\"expires_in\":3600}".utf8
      )
    )
    let client = try makeClient(
      hasAuthorizationServers: true,
      tokenPoster: Poster(session: networking)
    )
    let identifier = try CredentialConfigurationIdentifier(value: "UniversityDegreeCredential")

    _ = try await client.requestAccessTokenPreAuthFlow(
      preAuthorizedCode: "pre-authorized-code",
      txCode: nil,
      client: .public(id: "wallet-client"),
      transactionCode: nil,
      identifiers: [identifier],
      dpopNonce: nil,
      challenge: nil,
      maxRetries: 0
    )

    let recordedRequest = await networking.lastRequest()
    let request = try XCTUnwrap(recordedRequest)
    let body = try XCTUnwrap(request.httpBody)
    let parameters = formParameters(body)
    XCTAssertFalse(String(decoding: body, as: UTF8.self).contains("%25"))
    let details = try decodeDetails(parameters[Constants.AUTHORIZATION_DETAILS])
    XCTAssertEqual(details.first?.credentialConfigurationId, identifier.value)
    XCTAssertEqual(details.first?.locations, ["https://issuer.example.com"])
  }

  private func makeClient(
    hasAuthorizationServers: Bool,
    parPoster: PostingType = Poster(session: NetworkingThrowingMock()),
    tokenPoster: PostingType = Poster(session: NetworkingThrowingMock())
  ) throws -> AuthorizationServerClient {
    let metadata = AuthorizationServerMetadata(
      issuer: "https://authorization.example.com",
      authorizationEndpoint: "https://authorization.example.com/authorize",
      tokenEndpoint: "https://authorization.example.com/token",
      pushedAuthorizationRequestEndpoint: "https://authorization.example.com/par"
    )
    return try AuthorizationServerClient(
      challenger: nil,
      parPoster: parPoster,
      tokenPoster: tokenPoster,
      config: .init(
        client: .public(id: "wallet-client"),
        authFlowRedirectionURI: URL(string: "https://wallet.example.com/callback")!,
        requirePAR: false,
        requireDpop: false
      ),
      authorizationServerMetadata: .oauth(metadata),
      credentialIssuerIdentifier: try CredentialIssuerId("https://issuer.example.com"),
      credentialIssuerHasAuthorizationServers: hasAuthorizationServers
    )
  }

  private func decodeDetails(_ value: String?) throws -> [AuthorizationDetail] {
    let value = try XCTUnwrap(value)
    return try JSONDecoder().decode([AuthorizationDetail].self, from: Data(value.utf8))
  }

  private func formParameters(_ data: Data) -> [String: String] {
    let body = String(decoding: data, as: UTF8.self)
    return URLComponents(string: "?\(body)")?.queryItems?.reduce(into: [:]) {
      $0[$1.name] = $1.value
    } ?? [:]
  }
}

private actor RecordingNetworking: Networking {
  private let responseData: Data
  private var request: URLRequest?

  init(responseData: Data) {
    self.responseData = responseData
  }

  func data(from url: URL) async throws -> (Data, URLResponse) {
    throw ValidationError.error(reason: "Unexpected URL fetch")
  }

  func data(for request: URLRequest) async throws -> (Data, URLResponse) {
    self.request = request
    return (
      responseData,
      HTTPURLResponse(
        url: request.url!,
        statusCode: 200,
        httpVersion: nil,
        headerFields: nil
      )!
    )
  }

  func lastRequest() -> URLRequest? {
    request
  }
}
