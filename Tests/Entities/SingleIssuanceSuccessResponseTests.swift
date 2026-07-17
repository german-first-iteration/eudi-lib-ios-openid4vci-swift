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

final class SingleIssuanceSuccessResponseTests: XCTestCase {

  func testFinalResponseMapsEveryCredentialObjectAndPropagatesNotificationId() throws {
    let response = try decode(
      """
      {
        "credentials": [
          {
            "credential": "compact-credential",
            "format": "dc+sd-jwt",
            "issuer_hint": "first"
          },
          {
            "credential": {
              "@context": ["https://www.w3.org/2018/credentials/v1"],
              "type": ["VerifiableCredential"]
            }
          }
        ],
        "notification_id": "notification-123"
      }
      """
    )

    let domain = try response.toDomain()
    XCTAssertEqual(domain.credentialResponses.count, 2)

    guard case let .issued(format, credential, notificationId, additionalInfo) = domain.credentialResponses[0] else {
      return XCTFail("Expected the first credential to be issued")
    }
    XCTAssertEqual(format, "dc+sd-jwt")
    XCTAssertEqual(notificationId, "notification-123")
    XCTAssertEqual(additionalInfo?["issuer_hint"].string, "first")
    guard case let .string(value) = credential else {
      return XCTFail("Expected a string credential")
    }
    XCTAssertEqual(value, "compact-credential")

    guard case let .issued(format, credential, notificationId, additionalInfo) = domain.credentialResponses[1] else {
      return XCTFail("Expected the second credential to be issued")
    }
    XCTAssertNil(format)
    XCTAssertEqual(notificationId, "notification-123")
    XCTAssertNil(additionalInfo)
    guard case let .json(value) = credential else {
      return XCTFail("Expected an object credential")
    }
    XCTAssertEqual(value["type"][0].string, "VerifiableCredential")
  }

  func testLegacySingularCredentialRemainsSupported() throws {
    let response = try decode(
      """
      {
        "credential": {
          "type": ["VerifiableCredential"]
        },
        "notification_id": "legacy-notification"
      }
      """
    )

    let domain = try response.toDomain()
    guard case let .issued(_, credential, notificationId, _) = domain.credentialResponses.first else {
      return XCTFail("Expected an issued credential")
    }
    XCTAssertEqual(notificationId, "legacy-notification")
    guard case let .json(value) = credential else {
      return XCTFail("Expected an object credential")
    }
    XCTAssertEqual(value["type"][0].string, "VerifiableCredential")
  }

  func testDeferredResponseRequiresPositiveInterval() throws {
    let response = try decode(
      """
      {
        "transaction_id": "transaction-123",
        "interval": 5
      }
      """
    )

    let domain = try response.toDomain()
    guard case let .deferred(transactionId, interval) = domain.credentialResponses.first else {
      return XCTFail("Expected a deferred credential")
    }
    XCTAssertEqual(transactionId.value, "transaction-123")
    XCTAssertEqual(interval, 5)

    for invalidInterval in ["0", "-1"] {
      XCTAssertThrowsError(
        try decode(
          """
          {
            "transaction_id": "transaction-123",
            "interval": \(invalidInterval)
          }
          """
        )
      )
    }
  }

  func testDecoderRejectsMutuallyExclusiveAndMalformedResponses() {
    let invalidResponses = [
      """
      {
        "credentials": [{"credential": "issued"}],
        "transaction_id": "transaction-123",
        "interval": 5
      }
      """,
      """
      {
        "credential": "legacy",
        "credentials": [{"credential": "issued"}]
      }
      """,
      """
      {
        "credentials": []
      }
      """,
      """
      {
        "credentials": ["not-an-object"]
      }
      """,
      """
      {
        "credentials": [{"format": "dc+sd-jwt"}]
      }
      """,
      """
      {
        "transaction_id": "transaction-123"
      }
      """,
      """
      {
        "transaction_id": "",
        "interval": 5
      }
      """,
      """
      {
        "credentials": [{"credential": "issued"}],
        "interval": 5
      }
      """,
      """
      {
        "transaction_id": "transaction-123",
        "interval": 5,
        "notification_id": "not-allowed-for-deferred"
      }
      """
    ]

    for response in invalidResponses {
      XCTAssertThrowsError(try decode(response), response)
    }
  }

  private func decode(_ response: String) throws -> SingleIssuanceSuccessResponse {
    try JSONDecoder().decode(
      SingleIssuanceSuccessResponse.self,
      from: Data(response.utf8)
    )
  }
}

final class NotificationWireFormatTests: XCTestCase {

  func testNotificationObjectUsesExactFinalWireFormat() throws {
    let notification = NotificationObject(
      id: try .init(value: "notification-123"),
      event: .credentialAccepted,
      eventDescription: "Stored successfully"
    )

    let data = try JSONSerialization.data(
      withJSONObject: notification.toDictionary(),
      options: [.sortedKeys]
    )

    XCTAssertEqual(
      try XCTUnwrap(String(data: data, encoding: .utf8)),
      #"{"event":"credential_accepted","event_description":"Stored successfully","notification_id":"notification-123"}"#
    )
  }

  func testNotificationDTOUsesExactFinalWireFormat() throws {
    let notification = NotificationTO(
      notificationId: "notification-123",
      event: .credentialFailure,
      eventDescription: "Could not store credential"
    )
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]

    XCTAssertEqual(
      try XCTUnwrap(String(data: encoder.encode(notification), encoding: .utf8)),
      #"{"event":"credential_failure","event_description":"Could not store credential","notification_id":"notification-123"}"#
    )
  }

  func testNotificationEventValuesMatchFinalSpecification() {
    XCTAssertEqual(NotifiedEvent.credentialAccepted.rawValue, "credential_accepted")
    XCTAssertEqual(NotifiedEvent.credentialFailure.rawValue, "credential_failure")
    XCTAssertEqual(NotifiedEvent.credentialDeleted.rawValue, "credential_deleted")
  }
}
