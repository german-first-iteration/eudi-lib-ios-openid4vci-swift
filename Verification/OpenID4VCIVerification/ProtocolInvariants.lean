import Std

/-!
  Executable reference model for selected OpenID4VCI client invariants.

  This file deliberately models the decision logic only.  It does not claim a
  source-level refinement proof for the Swift implementation; the mapping to
  production code is recorded in `Verification/README.md`.
-/

namespace OpenID4VCIVerification

/-! ## HTTP response classification -/

def isSuccessStatus (status : Nat) : Bool :=
  200 ≤ status && status < 300

theorem successStatus_iff (status : Nat) :
    isSuccessStatus status = true ↔ 200 ≤ status ∧ status < 300 := by
  simp [isSuccessStatus]

example : isSuccessStatus 200 = true := by decide
example : isSuccessStatus 204 = true := by decide
example : isSuccessStatus 299 = true := by decide
example : isSuccessStatus 300 = false := by decide
example : isSuccessStatus 400 = false := by decide

/-! ## DPoP target and public JWK headers -/

structure TargetURI where
  scheme : String
  authority : String
  path : String
  query : Option String
  fragment : Option String
  deriving Repr, DecidableEq

def canonicalHTU (uri : TargetURI) : TargetURI :=
  { uri with query := none, fragment := none }

theorem canonicalHTU_noQuery (uri : TargetURI) : (canonicalHTU uri).query = none := rfl
theorem canonicalHTU_noFragment (uri : TargetURI) : (canonicalHTU uri).fragment = none := rfl
theorem canonicalHTU_preservesOriginAndPath (uri : TargetURI) :
    (canonicalHTU uri).scheme = uri.scheme ∧
    (canonicalHTU uri).authority = uri.authority ∧
    (canonicalHTU uri).path = uri.path := by
  simp [canonicalHTU]

def privateJWKParameters : List String :=
  ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]

def publicJWKParameters (parameters : List String) : List String :=
  parameters.filter (fun parameter => !(parameter ∈ privateJWKParameters))

theorem publicJWKParameters_excludesPrivate
    (parameters : List String) (parameter : String)
    (isPrivate : parameter ∈ privateJWKParameters) :
    parameter ∉ publicJWKParameters parameters := by
  simp [publicJWKParameters, isPrivate]

/-! ## Credential response shape -/

structure CredentialResponse where
  credential : Option String
  transactionId : Option String
  errorCode : Option String
  deriving Repr, DecidableEq

def validCredentialResponse (response : CredentialResponse) : Prop :=
  match response.errorCode, response.credential, response.transactionId with
  | some _, none, none => True
  | none, some _, none => True
  | none, none, some _ => True
  | _, _, _ => False

theorem validCredentialResponse_notBothCredentialAndDeferred
    (response : CredentialResponse)
    (valid : validCredentialResponse response) :
    ¬ (response.credential.isSome ∧ response.transactionId.isSome) := by
  cases response with
  | mk credential transactionId errorCode =>
    cases credential <;> cases transactionId <;> cases errorCode <;>
      simp [validCredentialResponse] at valid ⊢

theorem validCredentialResponse_errorIsExclusive
    (response : CredentialResponse)
    (valid : validCredentialResponse response) :
    response.errorCode.isSome → ¬ response.credential.isSome ∧ ¬ response.transactionId.isSome := by
  cases response with
  | mk credential transactionId errorCode =>
    cases credential <;> cases transactionId <;> cases errorCode <;>
      simp [validCredentialResponse] at valid ⊢

/-! ## Access-token refresh lifecycle -/

inductive TokenType where
  | bearer
  | dpop
  deriving Repr, DecidableEq

structure TokenState where
  accessToken : String
  refreshToken : Option String
  expiresAt : Option Nat
  tokenType : TokenType
  nonce : Option String
  deriving Repr, DecidableEq

structure RefreshResponse where
  accessToken : String
  refreshToken : Option String
  expiresAt : Option Nat
  nonce : Option String
  deriving Repr, DecidableEq

def applyRefresh (previous : TokenState) (response : RefreshResponse) : TokenState :=
  { accessToken := response.accessToken
    refreshToken := response.refreshToken.or previous.refreshToken
    expiresAt := response.expiresAt
    tokenType := previous.tokenType
    nonce := response.nonce }

theorem refresh_preservesTokenType
    (previous : TokenState) (response : RefreshResponse) :
    (applyRefresh previous response).tokenType = previous.tokenType := rfl

theorem refresh_preservesRefreshTokenWhenOmitted
    (previous : TokenState) (response : RefreshResponse)
    (omitted : response.refreshToken = none) :
    (applyRefresh previous response).refreshToken = previous.refreshToken := by
  simp [applyRefresh, omitted]

theorem refresh_rotatesRefreshTokenWhenProvided
    (previous : TokenState) (response : RefreshResponse) (token : String)
    (provided : response.refreshToken = some token) :
    (applyRefresh previous response).refreshToken = some token := by
  simp [applyRefresh, provided]

theorem refresh_usesResponseExpiry
    (previous : TokenState) (response : RefreshResponse) :
    (applyRefresh previous response).expiresAt = response.expiresAt := rfl

theorem refresh_usesResponseNonce
    (previous : TokenState) (response : RefreshResponse) :
    (applyRefresh previous response).nonce = response.nonce := rfl

end OpenID4VCIVerification
