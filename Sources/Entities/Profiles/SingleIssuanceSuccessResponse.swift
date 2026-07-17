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
@preconcurrency import SwiftyJSON

public struct SingleIssuanceSuccessResponse: Codable, Sendable {
  public let credential: JSON?
  public let credentials: [JSON]?
  public let transactionId: String?
  public let interval: TimeInterval?
  public let notificationId: String?
  
  enum CodingKeys: String, CodingKey {
    case credential
    case credentials
    case transactionId = "transaction_id"
    case interval
    case notificationId = "notification_id"
  }
  
  public init(
    credential: JSON?,
    credentials: [JSON]?,
    transactionId: String?,
    interval: TimeInterval?,
    notificationId: String?
  ) {
    self.credential = credential
    self.credentials = credentials
    self.transactionId = transactionId
    self.interval = interval
    self.notificationId = notificationId
  }
  
  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    
    credential = try container.decodeIfPresent(JSON.self, forKey: .credential)
    credentials = try container.decodeIfPresent([JSON].self, forKey: .credentials)
    transactionId = try container.decodeIfPresent(String.self, forKey: .transactionId)
    interval = try container.decodeIfPresent(TimeInterval.self, forKey: .interval)
    notificationId = try container.decodeIfPresent(String.self, forKey: .notificationId)

    if let validationIssue {
      throw DecodingError.dataCorrupted(
        .init(
          codingPath: decoder.codingPath,
          debugDescription: validationIssue
        )
      )
    }
  }
}

public extension SingleIssuanceSuccessResponse {
  
  func toDomain() throws -> CredentialIssuanceResponse {
    if let validationIssue {
      throw ValidationError.error(reason: validationIssue)
    }

    if let transactionId, let interval {
      return .init(
        credentialResponses: [
          .deferred(
            transactionId: try .init(
              value: transactionId
            ),
            interval: interval
          )
        ]
      )
    } else if let credential {
      return .init(
        credentialResponses: [
          .issued(
            format: nil,
            credential: try Self.toCredential(credential),
            notificationId: notificationId,
            additionalInfo: nil
          )
        ]
      )
    } else if let credentials {
      return .init(
        credentialResponses: try credentials.map(toIssuedCredential)
      )
    } else {
      throw ValidationError.error(reason: "CredentialIssuanceResponse unparseable")
    }
  }
  
  static func fromJSONString(_ jsonString: String) -> SingleIssuanceSuccessResponse? {
    guard let jsonData = jsonString.data(using: .utf8) else {
      return nil
    }
    
    do {
      let yourObject = try JSONDecoder().decode(SingleIssuanceSuccessResponse.self, from: jsonData)
      return yourObject
    } catch {
      return nil
    }
  }
}

private extension SingleIssuanceSuccessResponse {

  /// The top-level `credential` member is retained for compatibility with
  /// earlier OpenID4VCI drafts and existing callers. Final 1.0 responses use
  /// the `credentials` array instead.
  var validationIssue: String? {
    let responseMembers = [
      credential != nil,
      credentials != nil,
      transactionId != nil
    ].filter { $0 }.count

    guard responseMembers == 1 else {
      return "Exactly one of 'credential', 'credentials', or 'transaction_id' must be present."
    }

    if let credential, !Self.isSupportedCredential(credential) {
      return "'credential' must be a string or an object."
    }

    if let credentials {
      guard !credentials.isEmpty else {
        return "'credentials' must contain at least one credential object."
      }

      for (index, response) in credentials.enumerated() {
        guard let dictionary = response.dictionary,
              let credential = dictionary["credential"],
              Self.isSupportedCredential(credential) else {
          return "'credentials[\(index)]' must be an object containing a string or object 'credential'."
        }
      }
    }

    if let transactionId {
      guard !transactionId.isEmpty else {
        return "'transaction_id' must not be empty."
      }
      guard let interval, interval > 0 else {
        return "'interval' must be a positive number when 'transaction_id' is present."
      }
      guard notificationId == nil else {
        return "'notification_id' must not be used with 'transaction_id'."
      }
    } else if interval != nil {
      return "'interval' must only be used with 'transaction_id'."
    }

    if let notificationId, notificationId.isEmpty {
      return "'notification_id' must not be empty."
    }

    return nil
  }

  static func isSupportedCredential(_ credential: JSON) -> Bool {
    credential.type == .string || credential.type == .dictionary
  }

  static func toCredential(_ credential: JSON) throws -> Credential {
    switch credential.type {
    case .string:
      guard let value = credential.string else {
        throw ValidationError.error(reason: "Credential string is unparseable")
      }
      return .string(value)
    case .dictionary:
      return .json(credential)
    default:
      throw ValidationError.error(reason: "Credential must be a string or an object")
    }
  }

  func toIssuedCredential(_ response: JSON) throws -> IssuedCredential {
    guard var parameters = response.dictionary,
          let credential = parameters.removeValue(forKey: "credential") else {
      throw ValidationError.error(reason: "Credential response object is unparseable")
    }

    let format = parameters.removeValue(forKey: "format")?.string
    let additionalInfo = parameters.isEmpty ? nil : JSON(parameters)

    return .issued(
      format: format,
      credential: try Self.toCredential(credential),
      notificationId: notificationId,
      additionalInfo: additionalInfo
    )
  }
}
