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

public enum TokenType: String, Codable, Sendable {
  case bearer = "Bearer"
  case dpop = "DPoP"
  
  public init(value: String?) {
    self = Self.parse(value) ?? .bearer
  }

  public static func parse(_ value: String?) -> TokenType? {
    guard let value else { return nil }
    if value.caseInsensitiveCompare(TokenType.bearer.rawValue) == .orderedSame {
      return .bearer
    }
    if value.caseInsensitiveCompare(TokenType.dpop.rawValue) == .orderedSame {
      return .dpop
    }
    return nil
  }
}

public struct IssuanceAccessToken: Codable, CanExpire, Sendable {
  public var expiresIn: TimeInterval?
    
  public let accessToken: String
  public let tokenType: TokenType?
  
  public init(
    accessToken: String,
    tokenType: TokenType?,
    expiresIn: TimeInterval? = nil
  ) throws {
    guard !accessToken.isEmpty else {
      throw ValidationError.error(reason: "Access token cannot be empty")
    }
    self.accessToken = accessToken
    self.tokenType = tokenType
    self.expiresIn = expiresIn
  }
}

public extension IssuanceAccessToken {
  var authorizationHeader: [String: String] {
    ["Authorization": "\(TokenType.bearer.rawValue) \(accessToken)"]
  }
  
  func dPoPOrBearerAuthorizationHeader(
    dpopConstructor: DPoPConstructorType?,
    dPopNonce: Nonce?,
    endpoint: URL?
  ) async throws -> [String: String] {
    if tokenType != TokenType.dpop {
      return ["Authorization": "\(TokenType.bearer.rawValue) \(accessToken)"]
    }

    guard let dpopConstructor else {
      throw ValidationError.error(
        reason: "A DPoP proof constructor is required for a DPoP-bound access token"
      )
    }
    guard let endpoint else {
      throw ValidationError.error(
        reason: "A target endpoint is required for a DPoP-bound access token"
      )
    }

    let jwt = try await dpopConstructor.jwt(
      endpoint: endpoint,
      accessToken: accessToken,
      nonce: dPopNonce
    )
    return [
      "Authorization": "\(TokenType.dpop.rawValue) \(accessToken)",
      TokenType.dpop.rawValue: jwt
    ]
  }
}
