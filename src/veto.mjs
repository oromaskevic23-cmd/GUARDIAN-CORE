import {verify} from 'node:crypto';
export function vetoBytes(p) {
  if (!p||Object.keys(p).length!==7||!['v','org','epoch','iat','exp','global','actions'].every(k=>Object.hasOwn(p,k))||p.v!==1||typeof p.org!=='string'||!p.org||![p.epoch,p.iat,p.exp].every(Number.isSafeInteger)||p.epoch<0||p.exp<=p.iat||p.exp-p.iat>30||typeof p.global!=='boolean'||!Array.isArray(p.actions)||p.actions.length>10000||p.actions.some(x=>typeof x!=='string'||!x||x.length>128)||new Set(p.actions).size!==p.actions.length) throw Error('snapshot');
  return Buffer.from('IMPERIAL:veto-state:v1\n'+JSON.stringify([p.v,p.org,p.epoch,p.iat,p.exp,p.global,[...p.actions].sort()]));
}
// A signed state snapshot is not a signed Owner command. The authority must be pinned externally.
export function verifyVetoState(env,key,org,minimumEpoch,now) {
  try {
    const {payload:p,signature:s}=env, bytes=vetoBytes(p);
    if (key.asymmetricKeyType!=='ed25519'||typeof s!=='string'||!/^[a-f0-9]{128}$/.test(s)||!verify(null,bytes,key,Buffer.from(s,'hex'))) return null;
    if (p.org!==org||!Number.isSafeInteger(minimumEpoch)||minimumEpoch<0||p.epoch<minimumEpoch||!Number.isSafeInteger(now)||now<p.iat||now>=p.exp) return null;
    return Object.freeze({org:p.org,epoch:p.epoch,observedAt:p.iat,global:p.global,actions:Object.freeze([...p.actions])});
  } catch {return null;}
}
