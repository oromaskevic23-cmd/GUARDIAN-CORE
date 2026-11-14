import {verify} from 'node:crypto';
import {evaluate} from './index.mjs';
import {verifyVetoState} from './veto.mjs';
export function policyBytes(p) {
  if (!p||Object.keys(p).length!==6||!['v','org','epoch','iat','exp','rules'].every(k=>Object.hasOwn(p,k))||p.v!==1||typeof p.org!=='string'||!p.org||p.org.length>128||![p.epoch,p.iat,p.exp].every(Number.isSafeInteger)||p.epoch<0||p.exp<=p.iat||p.exp-p.iat>300||!Array.isArray(p.rules)||p.rules.length>1000) throw Error('policy');
  const seen=new Set(); const rules=p.rules.map(r=>{
    if (!r||Object.keys(r).length!==2||!Object.hasOwn(r,'action')||!Object.hasOwn(r,'decision')||typeof r.action!=='string'||!r.action||r.action.length>128||seen.has(r.action)||!['ALLOW','DENY','REQUIRE_APPROVAL'].includes(r.decision)) throw Error('rule');
    seen.add(r.action);return [r.action,r.decision];
  });
  return Buffer.from('IMPERIAL:policy:v1\n'+JSON.stringify([p.v,p.org,p.epoch,p.iat,p.exp,rules]));
}
export function evaluateSigned(req,envelope,vetoEnvelope,trust,now) {
  const deny=reason=>({decision:'DENY',reason});
  try {
    const {payload:p,signature:s}=envelope, bytes=policyBytes(p);
    if (!Number.isSafeInteger(now)||now<p.iat||now>=p.exp||!Number.isSafeInteger(trust.minimumPolicyEpoch)||trust.minimumPolicyEpoch<0||p.epoch<trust.minimumPolicyEpoch||p.org!==trust.org||req.org!==trust.org) return deny('POLICY_CONTEXT');
    if (trust.policyKey.asymmetricKeyType!=='ed25519'||typeof s!=='string'||!/^[a-f0-9]{128}$/.test(s)||!verify(null,bytes,trust.policyKey,Buffer.from(s,'hex'))) return deny('POLICY_SIGNATURE');
    const veto=verifyVetoState(vetoEnvelope,trust.vetoKey,trust.org,trust.minimumVetoEpoch,now);
    if (!veto) return deny('VETO_STATE_UNKNOWN');
    return {...evaluate(req,p,veto,now),policyEpoch:p.epoch};
  } catch {return deny('INVALID_INPUT');}
}
