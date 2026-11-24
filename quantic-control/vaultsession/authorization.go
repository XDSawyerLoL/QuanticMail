package vaultsession

import(
 "crypto/sha256"
 "crypto/ed25519"
 "encoding/hex"
 "errors"
 "time"

 control "github.com/XDSawyerLoL/QuanticMail/quantic-control"
)

// AuthorizationClaims returns a short-lived, session-specific request for an
// existing Quantic Control read-only action. The enrolled controller must
// separately approve and sign control.SigningBytes(claims). A device proof
// alone is insufficient. This is NOT a general OS execution authorization.
func(s *Session) AuthorizationClaims(action string, now time.Time)(control.Claims,error){
 s.mu.Lock();defer s.mu.Unlock()
 if err:=s.checkAuthorization(now);err!=nil{return control.Claims{},err}
 if !readAction(action){return control.Claims{},errors.New("unsupported read-only action")}
 pin:=sha256.Sum256(s.brokerController)
 return control.Claims{Version:1,MachineID:s.machineID,Action:action,
  KeyID:hex.EncodeToString(pin[:]),Nonce:s.Request().PQChallenge,
  IssuedAt:now.Unix(),ExpiresAt:s.born.Add(maxLifetime).Unix()},nil
}
func readAction(action string)bool{
 switch action{case "alerts.read","status.read","integrity.scan":return true}
 return false
}
func(s *Session) checkAuthorization(now time.Time)error{
 if s.revoked||s.authorizationUsed||!s.consumed||len(s.brokerController)!=32||
    now.Before(s.born)||!now.Before(s.born.Add(maxLifetime))||
    now.Unix()>=s.born.Add(maxLifetime).Unix(){
  return errors.New("broker-authenticated session unavailable, expired, revoked or consumed")
 }
 return nil
}

// AuthorizeRead consumes one separately signed authorization for exactly the
// expected read-only action, on this machine and this authenticated session.
// expectedAction is selected by the local trusted handler, never the request.
// The existing Quantic Control Guard is reused for signature and time checks.
func(s *Session) AuthorizeRead(r control.SignedRequest,expectedAction string,now time.Time)error{
 s.mu.Lock();defer s.mu.Unlock()
 if err:=s.checkAuthorization(now);err!=nil{return err}
 c:=r.Claims
 pin:=sha256.Sum256(s.brokerController)
 keyID:=hex.EncodeToString(pin[:])
 if !readAction(expectedAction)||c.Action!=expectedAction||c.MachineID!=s.machineID||
  c.KeyID!=keyID||c.Nonce!=s.Request().PQChallenge||
  c.IssuedAt<s.born.Unix()||c.ExpiresAt>s.born.Add(maxLifetime).Unix(){
  return errors.New("authorization not bound to this action, controller, machine and session")
 }
 g,err:=control.NewGuard(s.machineID,map[string]ed25519.PublicKey{keyID:s.brokerController})
 if err!=nil{return err}
 if err:=g.Authorize(r,now);err!=nil{return err}
 s.authorizationUsed=true
 return nil
}

// Revoke invalidates this in-memory session; it cannot undo an already
// completed read. Persistent identity revocation remains the responsibility
// of the independently trusted enrollment/authority system.
func(s *Session) Revoke(){
 s.mu.Lock();defer s.mu.Unlock()
 s.revoked=true
}
