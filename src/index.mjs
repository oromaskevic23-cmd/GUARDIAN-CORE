const deny=reason=>({decision:'DENY',reason});
export function evaluate(req,policy,veto,now) {
  if (!Number.isSafeInteger(now) || !req || !policy || !veto || req.identityVerified!==true || typeof req.org!=='string' || typeof req.action!=='string' || !req.action || req.org!==policy.org || req.org!==veto.org) return deny('CONTEXT');
  if (!Number.isSafeInteger(veto.observedAt) || veto.observedAt>now || now-veto.observedAt>30 || !Number.isSafeInteger(veto.epoch) || veto.epoch<0 || !Array.isArray(veto.actions) || veto.actions.some(x=>typeof x!=='string') || typeof veto.global!=='boolean') return deny('VETO_STATE_UNKNOWN');
  if (veto.global || veto.actions.includes(req.action)) return deny('ARCHITECT_VETO');
  if (!Array.isArray(policy.rules)) return deny('NO_POLICY');
  const rules=policy.rules.filter(r=>r && r.action===req.action);
  if (rules.length!==1 || !['ALLOW','DENY','REQUIRE_APPROVAL'].includes(rules[0].decision)) return deny('NO_UNAMBIGUOUS_RULE');
  const decision=rules[0].decision;
  return {decision,reason:'POLICY',epoch:veto.epoch};
}
