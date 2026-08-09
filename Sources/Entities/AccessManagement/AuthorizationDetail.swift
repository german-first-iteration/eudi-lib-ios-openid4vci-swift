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

public struct AuthorizationType: Codable, Sendable {
  public let type: String
  
  public init(type: String) {
    self.type = type
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    type = try container.decode(String.self)
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.singleValueContainer()
    try container.encode(type)
  }
}

public struct AuthorizationDetail: Codable, Sendable {
  public let type: AuthorizationType
  public let locations: [String]
  public let credentialConfigurationId: String

  enum CodingKeys: String, CodingKey {
    case type
    case locations
    case credentialConfigurationId = "credential_configuration_id"
  }
  
  public init(
    type: AuthorizationType,
    locations: [String],
    credentialConfigurationId: String
  ) {
    self.type = type
    self.locations = locations
    self.credentialConfigurationId = credentialConfigurationId
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    type = try container.decode(AuthorizationType.self, forKey: .type)
    locations = try container.decodeIfPresent([String].self, forKey: .locations) ?? []
    credentialConfigurationId = try container.decode(
      String.self,
      forKey: .credentialConfigurationId
    )
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(type, forKey: .type)
    if !locations.isEmpty {
      try container.encode(locations, forKey: .locations)
    }
    try container.encode(
      credentialConfigurationId,
      forKey: .credentialConfigurationId
    )
  }
}
