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
@preconcurrency import JOSESwift

extension JWK {
  func publicHeaderParameters() throws -> [String: Any] {
    guard keyType == .EC || keyType == .RSA else {
      throw ValidationError.error(reason: "DPoP requires an asymmetric public JWK")
    }

    var parameters = try toDictionary()
    ["d", "p", "q", "dp", "dq", "qi", "oth", "k"].forEach {
      parameters.removeValue(forKey: $0)
    }

    let requiredParameters: [String] = switch keyType {
    case .EC: ["kty", "crv", "x", "y"]
    case .RSA: ["kty", "n", "e"]
    default: []
    }
    guard requiredParameters.allSatisfy({ parameters[$0] is String }) else {
      throw ValidationError.error(reason: "DPoP JWK is missing public key parameters")
    }
    return parameters
  }
}
