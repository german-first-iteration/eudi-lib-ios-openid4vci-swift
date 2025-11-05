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
import os

// Result type for responses with headers
public struct ResponseWithHeaders<Response: Sendable>: Sendable {
  nonisolated(unsafe) public let headers: [AnyHashable: Any]
  public let body: Response
  
  public init(headers: [AnyHashable: Any], body: Response) {
    self.headers = headers
    self.body = body
  }
}

public extension ResponseWithHeaders {
  func headerValue(forKey key: AnyHashable) -> Any? {
    return headers[key]
  }
}

public enum PostError: LocalizedError {
  case invalidUrl
  case networkError(Error)
  case response(GenericErrorResponse)
  case cannotParse(String)
  case serverError
  case useDpopNonce(Nonce)
  
  /**
   Provides a localized description of the post error.
   
   - Returns: A string describing the post error.
   */
  public var errorDescription: String? {
    switch self {
    case .invalidUrl:
      return "Invalid URL"
    case .networkError(let error):
      return "Network Error: \(error.localizedDescription)"
    case .response:
      return "Generic error response"
    case .cannotParse(let string):
      return "Could not parse: \(string)"
    case .serverError:
      return "Server error"
    case .useDpopNonce(let nonce):
      return "Use dPopp Nonce error: \(nonce)"
    }
  }
}

public protocol PostingType: Sendable {
  
  var session: Networking { get set }
  
  /**
   Performs a POST request with the provided URLRequest.
   
   - Parameters:
   - request: The URLRequest to be used for the POST request.
   
   - Returns: A Result type with the response data or an error.
   */
  func post<Response: Codable>(request: URLRequest) async -> Result<ResponseWithHeaders<Response>, PostError>
  
  /**
   Performs a POST request with the provided URLRequest.
   
   - Parameters:
   - request: The URLRequest to be used for the POST request.
   
   - Returns: A Result type with a success boolean (based on status code) or an error.
   */
  func check(request: URLRequest) async -> Result<Bool, PostError>
}

public struct Poster: PostingType {
  
  public var session: Networking
  private let networkLogger = Logger(subsystem: Bundle.main.bundleIdentifier ?? "com.myapp",
                                     category: "Network")
  /**
   Initializes a Poster instance.
   */
  public init(
    session: Networking = URLSession.shared
  ) {
    self.session = session
  }
  
  /**
   Performs a POST request with the provided URLRequest.
   
   - Parameters:
   - request: The URLRequest to be used for the POST request.
   
   - Returns: A Result type with the response data or an error.
   */
  public func post<Response: Codable>(request: URLRequest) async -> Result<ResponseWithHeaders<Response>, PostError> {
    do {
      let startTime = Date()
      let (data, response) = try await self.session.data(for: request)
      let httpResponse = (response as? HTTPURLResponse)
      let statusCode = httpResponse?.statusCode ?? 0
      let headers = httpResponse?.allHeaderFields ?? [:]
      log(request: request, responseData: data, startTime: startTime)

      if statusCode >= HTTPStatusCode.badRequest && statusCode < HTTPStatusCode.internalServerError {
        if let httpResponse,
           httpResponse.containsDpopError(),
           let dPopNonce = headers.value(forCaseInsensitiveKey: Constants.DPOP_NONCE_HEADER) as? String {
          return .failure(
            .useDpopNonce(
              .init(
                value: dPopNonce
              )
            )
          )
        } else {
          let object = try JSONDecoder().decode(GenericErrorResponse.self, from: data)
          if object.error == Constants.USE_DPOP_NONCE,
             let dPopNonce = headers.value(forCaseInsensitiveKey: Constants.DPOP_NONCE_HEADER) as? String {
            return .failure(
              .useDpopNonce(
                .init(
                  value: dPopNonce
                )
              )
            )
          }
          return .failure(
            .response(object)
          )
        }
        
      } else if statusCode >= HTTPStatusCode.internalServerError {
        return .failure(.serverError)
      }
      
      do {
        let object = try JSONDecoder().decode(Response.self, from: data)
        return .success(
          .init(
            headers: headers,
            body: object
          )
        )
      } catch {
        if statusCode == HTTPStatusCode.ok || statusCode == HTTPStatusCode.accepted, let string = String(data: data, encoding: .utf8) {
          return .failure(.cannotParse(string))
        } else {
          return .failure(.networkError(error))
        }
      }
      
    } catch let error as NSError {
      return .failure(.networkError(error))
    } catch {
      return .failure(.networkError(error))
    }
  }

  nonisolated public func log(request: URLRequest, responseData: Data? = nil, startTime: Date) {
      let duration = Date().timeIntervalSince(startTime)

      networkLogger.info("0️⃣ ===================== Library Network Request Begin =====================")
      networkLogger.info("1️⃣ URL: \(request.url?.absoluteString ?? "nil", privacy: .public)")
      networkLogger.info("2️⃣ Method: \(request.httpMethod ?? "nil", privacy: .public)")
    if let data = request.httpBody {
      networkLogger.info("3️⃣ Body: \(String(data: data, encoding: .utf8) ?? "nil", privacy: .public))")
    }


      if let headers = request.allHTTPHeaderFields, !headers.isEmpty {
          networkLogger.info("4️⃣ Headers:")
          headers.forEach { key, value in
              networkLogger.info("   \(key): \(value, privacy: .public)")
          }
      } else {
          networkLogger.info("4️⃣ Headers: none")
      }

      if let responseData {
          networkLogger.info("✅ Response: \(responseData.prettyJson ?? "nil", privacy: .public)")
      }
      networkLogger.info("⏱ Duration: \(duration, format: .fixed(precision: 3)) seconds")
      networkLogger.info("5️⃣ ===================== Network Request End =====================")
  }

  /**
   Performs a POST request with the provided URLRequest.
   
   - Parameters:
   - request: The URLRequest to be used for the POST request.
   
   - Returns: A Result type with a success boolean (based on status code) or an error.
   */
  public func check(request: URLRequest) async -> Result<Bool, PostError> {
    do {
      let (_, response) = try await self.session.data(for: request)
      let httpResponse = (response as? HTTPURLResponse)
      
      return .success(httpResponse?.statusCode.isWithinRange(
        HTTPStatusCode.ok...HTTPStatusCode.imUsed
      ) ?? false)
    } catch let error as NSError {
      return .failure(.networkError(error))
    } catch {
      return .failure(.networkError(error))
    }
  }
}
public extension Data {
  var prettyJson: String? {
    guard let object = try? JSONSerialization.jsonObject(with: self, options: []),
          let data = try? JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys]),
          let prettyPrintedString = String(data: data, encoding: .utf8) else { return nil }

    return prettyPrintedString
  }
}
