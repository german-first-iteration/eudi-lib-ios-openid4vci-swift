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

final class RemoteDataAccessTests: XCTestCase {

  func testPosterAcceptsEmptyNoContentResponse() async throws {
    let url = URL(string: "https://example.com/notification")!
    let poster = Poster(session: StaticNetworking(data: Data(), statusCode: 204))
    let result: Result<ResponseWithHeaders<EmptyResponse>, Error> = await poster.post(
      request: URLRequest(url: url)
    )

    _ = try result.get()
  }

  func testPosterRejectsRedirectResponse() async throws {
    let url = URL(string: "https://example.com/token")!
    let poster = Poster(session: StaticNetworking(data: Data("{}".utf8), statusCode: 302))
    let result: Result<ResponseWithHeaders<EmptyResponse>, Error> = await poster.post(
      request: URLRequest(url: url)
    )

    do {
      _ = try result.get()
      XCTFail("Expected a redirect response to fail")
    } catch let PostError.requestError(statusCode, _) {
      XCTAssertEqual(statusCode, 302)
    } catch {
      XCTFail("Unexpected error: \(error)")
    }
  }

  func testFetcherPreservesInvalidStatusCode() async {
    let url = URL(string: "https://example.com/metadata")!
    let fetcher = Fetcher<EmptyResponse>(
      session: StaticNetworking(data: Data("{}".utf8), statusCode: 404)
    )

    switch await fetcher.fetch(url: url) {
    case .failure(.invalidStatusCode(let responseURL, let statusCode)):
      XCTAssertEqual(responseURL, url)
      XCTAssertEqual(statusCode, 404)
    default:
      XCTFail("Expected invalidStatusCode")
    }
  }

  func testRawFetcherPreservesInvalidStatusCode() async {
    let url = URL(string: "https://example.com/offer")!
    let fetcher = RawDataFetcher(
      session: StaticNetworking(data: Data(), statusCode: 401)
    )

    switch await fetcher.fetchRawWithHeaders(url: url) {
    case .failure(.invalidStatusCode(let responseURL, let statusCode)):
      XCTAssertEqual(responseURL, url)
      XCTAssertEqual(statusCode, 401)
    default:
      XCTFail("Expected invalidStatusCode")
    }
  }
}

private struct StaticNetworking: Networking {
  let data: Data
  let statusCode: Int

  func data(from url: URL) async throws -> (Data, URLResponse) {
    (data, response(for: url))
  }

  func data(for request: URLRequest) async throws -> (Data, URLResponse) {
    (data, response(for: request.url!))
  }

  private func response(for url: URL) -> URLResponse {
    HTTPURLResponse(
      url: url,
      statusCode: statusCode,
      httpVersion: nil,
      headerFields: nil
    )!
  }
}
