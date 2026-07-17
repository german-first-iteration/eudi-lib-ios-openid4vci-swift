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
import SwiftyJSON

public typealias AuthorizationDetailsIdentifiers = [CredentialConfigurationIdentifier: [CredentialIdentifier]]

public enum AccessTokenRequestResponse: Codable, Sendable {
  case success(
    tokenType: String?,
    accessToken: String,
    refreshToken: String?,
    refreshTokenExpiresIn: Int?,
    expiresIn: Int?,
    scope: String?,
    authorizationDetails: AuthorizationDetailsIdentifiers?
  )
  case failure(
    error: String,
    errorDescription: String?
  )
  
  enum CodingKeys: String, CodingKey {
    case tokenType = "token_type"
    case accessToken = "access_token"
    case refreshToken = "refresh_token"
    case refreshTokenExpiresIn = "refresh_expires_in"
    case expiresIn = "expires_in"
    case scope
    case error
    case errorDescription = "error_description"
    case authorizationDetails = "authorization_details"
  }
  
  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    
    if let accessToken = try? container.decode(String.self, forKey: .accessToken),
       let tokenType = try? container.decode(String.self, forKey: .tokenType) {
      guard TokenType.parse(tokenType) != nil else {
        throw DecodingError.dataCorruptedError(
          forKey: .tokenType,
          in: container,
          debugDescription: "Unsupported token_type '\(tokenType)'"
        )
      }
      
      let refeshToken = try? container.decode(String.self, forKey: .refreshToken)
      let refreshTokenExpiresIn = try? container.decode(Int.self, forKey: .refreshTokenExpiresIn)
      let expiresIn = try? container.decode(Int.self, forKey: .expiresIn)
      var authorizationDetails: AuthorizationDetailsIdentifiers = [:]
      
      if container.contains(.authorizationDetails) {
        let json = try container.decode(JSON.self, forKey: .authorizationDetails)
        guard let array = json.array, !array.isEmpty else {
          throw DecodingError.dataCorruptedError(
            forKey: .authorizationDetails,
            in: container,
            debugDescription: "authorization_details must be a non-empty array"
          )
        }
        for item in array {
          guard let key = item["credential_configuration_id"].string,
                let values = item["credential_identifiers"].array,
                let credentialConfigurationIdentifier = try? CredentialConfigurationIdentifier(value: key) else {
            throw DecodingError.dataCorruptedError(
              forKey: .authorizationDetails,
              in: container,
              debugDescription: "authorization_details contains an invalid credential configuration"
            )
          }

          let credentialIdentifiers = try values.map { value in
            guard let string = value.string else {
              throw DecodingError.dataCorruptedError(
                forKey: .authorizationDetails,
                in: container,
                debugDescription: "credential_identifiers must contain strings"
              )
            }
            return try CredentialIdentifier(value: string)
          }
          guard !credentialIdentifiers.isEmpty else {
            throw DecodingError.dataCorruptedError(
              forKey: .authorizationDetails,
              in: container,
              debugDescription: "credential_identifiers must not be empty"
            )
          }
          authorizationDetails[credentialConfigurationIdentifier] = credentialIdentifiers
        }
      }
      
      self = .success(
        tokenType: tokenType,
        accessToken: accessToken,
        refreshToken: refeshToken,
        refreshTokenExpiresIn: refreshTokenExpiresIn,
        expiresIn: expiresIn,
        scope: try? container.decode(String.self, forKey: .scope),
        authorizationDetails: (authorizationDetails.isEmpty ? nil : authorizationDetails)
      )
    } else if let error = try? container.decode(String.self, forKey: .error) {
      self = .failure(
        error: error,
        errorDescription: try? container.decode(String.self, forKey: .errorDescription)
      )
    } else {
      throw DecodingError.dataCorrupted(
        DecodingError.Context(
          codingPath: decoder.codingPath,
          debugDescription: "Invalid response format"
        )
      )
    }
  }
  
  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    
    switch self {
    case let .success(
      tokenType,
      accessToken,
      refreshToken,
      refreshTokenExpiresIn,
      expiresIn,
      scope,
      _
    ):
      try container.encodeIfPresent(tokenType, forKey: .tokenType)
      try container.encode(accessToken, forKey: .accessToken)
      try container.encodeIfPresent(refreshToken, forKey: .refreshToken)
      try container.encodeIfPresent(refreshTokenExpiresIn, forKey: .refreshTokenExpiresIn)
      try container.encodeIfPresent(expiresIn, forKey: .expiresIn)
      try container.encodeIfPresent(scope, forKey: .scope)
    case let .failure(error, errorDescription):
      try container.encode(error, forKey: .error)
      try container.encode(errorDescription, forKey: .errorDescription)
    }
  }
}
