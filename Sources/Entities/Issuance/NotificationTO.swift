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

public struct NotificationTO: Codable, Sendable {
  public let notificationId: String
  public let event: String
  public let eventDescription: String?
  
  public enum CodingKeys: String, CodingKey {
    case notificationId = "notification_id"
    case event
    case eventDescription = "event_description"
  }
  
  public init(
    notificationId: String,
    event: NotifiedEvent,
    eventDescription: String? = nil
  ) {
    self.notificationId = notificationId
    self.event = event.rawValue
    self.eventDescription = eventDescription
  }

  @available(*, deprecated, message: "Use the NotifiedEvent initializer")
  public init(
    notificationId: String,
    event: String,
    eventDescription: String? = nil
  ) {
    self.notificationId = notificationId
    self.event = Self.canonicalEvent(event)?.rawValue ?? event
    self.eventDescription = eventDescription
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    notificationId = try container.decode(String.self, forKey: .notificationId)
    let event = try container.decode(String.self, forKey: .event)
    guard let event = NotifiedEvent(rawValue: event) else {
      throw DecodingError.dataCorruptedError(
        forKey: .event,
        in: container,
        debugDescription: "Unsupported notification event '\(event)'."
      )
    }
    self.event = event.rawValue
    eventDescription = try container.decodeIfPresent(String.self, forKey: .eventDescription)
  }

  public func encode(to encoder: Encoder) throws {
    guard let event = NotifiedEvent(rawValue: event) else {
      throw EncodingError.invalidValue(
        event,
        .init(
          codingPath: encoder.codingPath,
          debugDescription: "Unsupported notification event '\(event)'."
        )
      )
    }

    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(notificationId, forKey: .notificationId)
    try container.encode(event.rawValue, forKey: .event)
    try container.encodeIfPresent(eventDescription, forKey: .eventDescription)
  }

  private static func canonicalEvent(_ event: String) -> NotifiedEvent? {
    switch event {
    case NotifiedEvent.credentialAccepted.rawValue, "CREDENTIAL_ACCEPTED":
      .credentialAccepted
    case NotifiedEvent.credentialFailure.rawValue, "CREDENTIAL_FAILURE":
      .credentialFailure
    case NotifiedEvent.credentialDeleted.rawValue, "CREDENTIAL_DELETED":
      .credentialDeleted
    default:
      nil
    }
  }
}
