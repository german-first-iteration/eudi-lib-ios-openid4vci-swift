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

public enum CredentialMetadata {
  case scope(Scope)
  case msoMdoc(MsoMdocProfile)
  case w3CSignedJwt(W3CSignedJwtProfile)
  case w3CJsonLdSignedJwt(W3CJsonLdSignedJwtProfile)
  case w3CJsonLdDataIntegrity(W3CJsonLdDataIntegrityProfile)
  case sdJwtVc(SdJwtVcProfile)
}

/// State denoting that the pushed authorization request has been placed successfully and response processed
public struct ParRequested {
  public let credentials: [CredentialMetadata]
  public let getAuthorizationCodeURL: GetAuthorizationCodeURL
  public let pkceVerifier: PKCEVerifier
  public let state: String
  
  public init(
    credentials: [CredentialMetadata],
    getAuthorizationCodeURL: GetAuthorizationCodeURL,
    pkceVerifier: PKCEVerifier,
    state: String
  ) {
    self.credentials = credentials
    self.getAuthorizationCodeURL = getAuthorizationCodeURL
    self.pkceVerifier = pkceVerifier
    self.state = state
  }
}

/// State denoting that caller has followed the GetAuthorizationCodeURL URL and response received
/// from the authorization server and processed successfully.
public struct AuthorizationCodeRetrieved {
  public let credentials: [CredentialMetadata]
  public let authorizationCode: IssuanceAuthorization
  public let pkceVerifier: PKCEVerifier
  
  public init(
    credentials: [CredentialMetadata],
    authorizationCode: IssuanceAuthorization,
    pkceVerifier: PKCEVerifier
  ) throws {
    
    guard case .authorizationCode = authorizationCode else {
      throw ValidationError.error(reason: "IssuanceAuthorization must be authorization code")
    }

    self.credentials = credentials
    self.authorizationCode = authorizationCode
    self.pkceVerifier = pkceVerifier
  }
}

public enum UnauthorizedRequest {
  case par(ParRequested)
  case authorizationCode(AuthorizationCodeRetrieved)
}
